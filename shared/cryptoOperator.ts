import _ from "lodash";
import { isBrowser, isNode, isWebWorker } from "./node_modules/browser-or-node";
import { Packr } from "msgpackr";
import { EncryptedData, SignedEncryptedData, EncryptInfo, PasswordDeriveInfo, SignedKeyPair, ExposedSignedPublicKey, ExportedSigningKeyPair, ExportedSignedKeyPair } from "./commonTypes";
import { randomFunctions } from "./commonFunctions";

const packr = new Packr();

export const serialize = (obj: any) => {
    const serialized = packr.pack(obj);
    return Buffer.from(serialized.buffer, serialized.byteOffset, serialized.byteLength);
}

export const deserialize = (bytes: Uint8Array) => {
    try {
        return packr.unpack(bytes) as any;
    } catch(err) {
        return null;
    }
}

export const { getRandomVector } = randomFunctions();
const subtle = assignSubtle();

const ecdsaSignParams = { name: "ECDSA", hash: { name: "SHA-512" } };
const iterFromSeed = (seed: number) => 1e5 + (10 * (Math.abs(Math.round(seed)) % 100));
const pbkdf2Params = (salt: Buffer, seed: number) => ({ name: "PBKDF2", salt, iterations: iterFromSeed(seed), hash: "SHA-512" });
const aesKeyGenParams = { name: "AES-GCM", length: 256 };
const hmacKeyGenParams = (length: 256 | 512) => ({ name: "HMAC", hash: { name: `SHA-${length}` }, length });
const aesGCM = (iv: Buffer) => ({ name: "AES-GCM", iv });
const hkdfParams = (salt: Buffer, length: 256 | 512, info: string) => ({ name: "HKDF", hash: `SHA-${length}`, salt, info: Buffer.from(`${info}${salt.toString("base64").slice(0, 20)}`) });

export async function digestToHex(algorithm: AlgorithmIdentifier, data: BufferSource) {
    return Buffer.from(await subtle.digest(algorithm, data)).toString("hex");
}

export async function digestToBuffer(algorithm: AlgorithmIdentifier, data: BufferSource) {
    return Buffer.from(await subtle.digest(algorithm, data));
}

export async function digestToBase64(algorithm: AlgorithmIdentifier, data: BufferSource) {
    return Buffer.from(await subtle.digest(algorithm, data)).toString("base64");
}

export async function importRaw(source: BufferSource | string): Promise<CryptoKey> {
    const usePbkdf = typeof source === "string";
    const bits = usePbkdf ? Buffer.from(source) : source;
    return await subtle.importKey("raw", bits, usePbkdf ? "PBKDF2" : "HKDF", false, ["deriveBits", "deriveKey"]);
}

export async function generateKeyPair(name: "ECDH" | "ECDSA"): Promise<CryptoKeyPair> {
    const isEcdh = name === "ECDH";
    return subtle.generateKey({ name, namedCurve: "P-521" }, true, isEcdh ? ["deriveBits", "deriveKey"] : ["sign", "verify"]);
}

export async function deriveSymmetricBits(privateKey: CryptoKey, publicKey: CryptoKey, length: 256 | 512): Promise<Buffer> {
    return Buffer.from(await subtle.deriveBits({ name: "ECDH", public: publicKey }, privateKey, length));
}

export async function deriveSymmetricBitsKey(privateKey: CryptoKey, publicKey: CryptoKey, length: 256 | 512): Promise<CryptoKey> {
    return await importRaw(await deriveSymmetricBits(privateKey, publicKey, length));
}

export async function importKey(keyData: BufferSource, name: "ECDH" | "ECDSA", type: "public" | "private", extractable: boolean): Promise<CryptoKey> {
    const isPrivate = type === "private";
    const isSigning = name === "ECDSA"
    const usages: Array<"deriveBits" | "deriveKey" | "sign" | "verify"> =
        !isSigning
            ? (isPrivate
                ? ["deriveBits", "deriveKey"]
                : [])
            : (isPrivate
                ? ["sign"]
                : ["verify"]);
    return await subtle.importKey(isPrivate ? "pkcs8" : "spki", keyData, { name, namedCurve: "P-521" }, extractable, usages);
}

export async function exportKey(key: CryptoKey): Promise<Buffer> {
    const isPrivate = key.type === "private";
    return Buffer.from(await subtle.exportKey(isPrivate ? "pkcs8" : "spki", key));
}

export async function encrypt(encryptInfo: EncryptInfo, plaintext: BufferSource): Promise<Buffer> {
    const { encryptKey, iv } = encryptInfo;
    return Buffer.from(await subtle.encrypt(aesGCM(iv), encryptKey, plaintext));
}

export async function decrypt(encryptInfo: EncryptInfo, ciphertext: BufferSource): Promise<Buffer> {
    const { encryptKey, iv } = encryptInfo;
    return Buffer.from(await subtle.decrypt(aesGCM(iv), encryptKey, ciphertext));
}

export async function deriveEncrypt(data: any, keyBits: CryptoKey | BufferSource, purpose: string, hSalt?: Buffer): Promise<EncryptedData> {
    return await deriveSignEncrypt(data, keyBits, hSalt ? [purpose, hSalt] : purpose);
}

export async function deriveDecrypt(data: EncryptedData, keyBits: CryptoKey | BufferSource, purpose: string): Promise<any> {
    const { ciphertext, hSalt } = data;
    return await deriveDecryptVerify(data, keyBits, purpose);
}

export async function sign(data: BufferSource, signingKey: CryptoKey): Promise<Buffer> {
    let algo: any = signingKey.algorithm.name;
    if (algo === "ECDSA") {
        algo = ecdsaSignParams;
    }
    return Buffer.from(await subtle.sign(algo, signingKey, data));
}

export async function verify(originalData: BufferSource, signature: Buffer, verifyingKey: CryptoKey): Promise<boolean> {
    let algo: any = verifyingKey.algorithm.name;
    if (algo === "ECDSA") {
        algo = ecdsaSignParams;
    }
    return await subtle.verify(algo, verifyingKey, signature, originalData);
}

export async function deriveSignMac(data: Buffer, keyBits: CryptoKey | BufferSource, salt: Buffer, purpose: string, length: 256 | 512 = 256) {
    return await sign(data, await deriveMACKey(keyBits, salt, purpose, length));
}

export async function deriveVerifyMac(originalData: Buffer, signature: Buffer, keyBits: CryptoKey | BufferSource, salt: Buffer, purpose: string, length: 256 | 512 = 256) {
    return await verify(originalData, signature, await deriveMACKey(keyBits, salt, purpose, length));

}

export async function deriveMasterKeyBits(str: string, pInfo: PasswordDeriveInfo): Promise<Buffer>;
export async function deriveMasterKeyBits(str: string): Promise<[Buffer, PasswordDeriveInfo]>;
export async function deriveMasterKeyBits(str: string, pInfo?: PasswordDeriveInfo) {
  const returnInfo = !pInfo;
  let { pSalt, iterSeed } = pInfo ?? {};
  pSalt ??= getRandomVector(64);
  iterSeed ??= _.random(1, 999);
  const masterKeyBits = Buffer.from(await subtle.deriveBits(pbkdf2Params(pSalt, iterSeed), await importRaw(str), 512));
  return returnInfo ? [masterKeyBits, { pSalt, iterSeed }] : masterKeyBits;
}

export async function deriveHKDF(keyBits: CryptoKey | BufferSource, salt: Buffer, purpose: string, length: 256 | 512 = 256): Promise<Buffer> {
    const importedBits = "algorithm" in keyBits ? keyBits : await importRaw(keyBits);
    return Buffer.from(await subtle.deriveBits(hkdfParams(salt, length, purpose), importedBits, length));
}

export async function deriveAESKey(keyBits: CryptoKey | BufferSource, salt: Buffer, purpose: string): Promise<EncryptInfo> {
    let importedBits = "algorithm" in keyBits ? keyBits : await importRaw(keyBits);
    const kdfOutput = Buffer.from(await subtle.deriveBits(hkdfParams(salt, 512, `${purpose} Derive`), importedBits, 384));
    importedBits = await importRaw(subarray(kdfOutput, 0, 32));
    const iv = subarray(kdfOutput, 32, 48);
    const encryptKey = await subtle.deriveKey(hkdfParams(salt, 256, `${purpose} Encrypt|Decrypt`), importedBits, aesKeyGenParams, false, ["unwrapKey", "wrapKey", "encrypt", "decrypt"]);
    return { encryptKey, iv };
}

export async function deriveMACKey(keyBits: CryptoKey | BufferSource, salt: Buffer, purpose: string, length: 256 | 512 = 256): Promise<CryptoKey> {
    const importedBits = "algorithm" in keyBits ? keyBits : await importRaw(keyBits);
    return await subtle.deriveKey(hkdfParams(salt, length, purpose), importedBits, hmacKeyGenParams(length), false, ["sign", "verify"]);
}

type EncryptionParameters = string | [string, Buffer];

export async function deriveSignEncrypt(plaintext: any | BufferSource, keyBits: CryptoKey | BufferSource, parameters: EncryptionParameters):
    Promise<EncryptedData>
export async function deriveSignEncrypt(plaintext: any | BufferSource, keyBits: CryptoKey | BufferSource, parameters: EncryptionParameters, signingKey: CryptoKey):
        Promise<SignedEncryptedData>
export async function deriveSignEncrypt(plaintext: any | BufferSource, keyBits: CryptoKey | BufferSource, parameters: EncryptionParameters, signingKey?: CryptoKey):
    Promise<EncryptedData | SignedEncryptedData> {
    const plaintextBuffer = Buffer.isBuffer(plaintext) || ArrayBuffer.isView(plaintext) ? plaintext : serialize(plaintext);
    const purpose = parameters instanceof Array ? parameters[0] : parameters;
    const hSalt = parameters instanceof Array ? parameters[1] : getRandomVector(64);
    const ciphertext = await encrypt(await deriveAESKey(keyBits, hSalt, purpose), plaintextBuffer);
    if (signingKey) {
        const signature = await sign(plaintextBuffer, signingKey);
        return { hSalt, ciphertext, signature };
    }
    return { hSalt, ciphertext };
}

export async function deriveDecryptVerify(encrypted: EncryptedData, keyBits: CryptoKey | BufferSource, purpose: string): Promise<any>
export async function deriveDecryptVerify(encrypted: SignedEncryptedData, keyBits: CryptoKey | BufferSource, purpose: string, verifyingKey: CryptoKey): Promise<any>
export async function deriveDecryptVerify(encrypted: EncryptedData | SignedEncryptedData, keyBits: CryptoKey | BufferSource, purpose: string, verifyingKey?: CryptoKey): Promise<any> {
    try {
        const { hSalt, ciphertext } = encrypted;
        const plaintext = await decrypt(await deriveAESKey(keyBits, hSalt, purpose), ciphertext);
        if ("signature" in encrypted) {
            if (!verifyingKey) {
                throw new Error("No verifying key provided");
            }
            const verified = await verify(plaintext, encrypted.signature, verifyingKey);
            if (!verified) {
                return null;
            }
        }
        return deserialize(plaintext);
    }
    catch (err) {
        console.log(`${err}`);
        return null;
    }
}

export async function deriveWrap(privateKey: CryptoKey, keyBits: CryptoKey | BufferSource, purpose: string, hSalt?: Buffer): Promise<EncryptedData> {
    hSalt ||= getRandomVector(48);
    const { encryptKey, iv } = await deriveAESKey(keyBits, hSalt, `${purpose} Wrap|Unwrap`);
    const ciphertext = Buffer.from(await subtle.wrapKey("pkcs8", privateKey, encryptKey, aesGCM(iv)));
    return { ciphertext, hSalt}
}

export async function deriveUnwrap(wrappedKey: EncryptedData, keyBits: CryptoKey | BufferSource, name: "ECDH" | "ECDSA", purpose: string, extractable: boolean): Promise<CryptoKey> {
    const { ciphertext, hSalt } = wrappedKey;
    const decryptedKey = await decrypt(await deriveAESKey(keyBits, hSalt, `${purpose} Wrap|Unwrap`), ciphertext);
    return await importKey(decryptedKey, name, "private", extractable);
}

export async function generateSignedKeyPair(signingKey: CryptoKey): Promise<SignedKeyPair> {
    const keyPair = await generateKeyPair("ECDH");
    const exportedPublicKey = await exportKey(keyPair.publicKey);
    const signature = await sign(exportedPublicKey, signingKey);
    return { keyPair, signature, exportedPublicKey };
}

export function exposeSignedKey(signedKeyPair: SignedKeyPair): ExposedSignedPublicKey {
    const { signature, exportedPublicKey } = signedKeyPair;
    return { exportedPublicKey, signature }
}

export async function exportSigningKeyPair(keyPair: CryptoKeyPair, keyBits: CryptoKey | BufferSource, purpose: string, hSalt?: Buffer): Promise<ExportedSigningKeyPair> {
    const { privateKey, publicKey } = keyPair;
    const exportedPublicKey = await exportKey(publicKey);
    const wrappedPrivateKey = await deriveWrap(privateKey, keyBits, purpose, hSalt);
    return { exportedPublicKey, wrappedPrivateKey };
}

export async function exportSignedKeyPair(signedKeyPair: SignedKeyPair, keyBits: CryptoKey | BufferSource, purpose: string, hSalt?: Buffer): Promise<ExportedSignedKeyPair> {
    const { keyPair: { privateKey }, exportedPublicKey, signature } = signedKeyPair;
    const wrappedPrivateKey = await deriveWrap(privateKey, keyBits, purpose, hSalt);
    return { exportedPublicKey, wrappedPrivateKey, signature };
}

export async function verifyKey(signedKey: ExposedSignedPublicKey, verifyingKey: CryptoKey | BufferSource): Promise<CryptoKey | null> {
    const { exportedPublicKey, signature } = signedKey;
    if (!("algorithm" in verifyingKey)) {
        verifyingKey = await importKey(verifyingKey, "ECDSA", "public", false);
    }
    if (!(await verify(exportedPublicKey, signature, verifyingKey)))
        return null;
    return await importKey(exportedPublicKey, "ECDH", "public", true);
}

export async function importSignedKeyPair(exportedKeyPair: ExportedSignedKeyPair, keyBits: CryptoKey | BufferSource, description: string): Promise<SignedKeyPair> {
    const { exportedPublicKey, wrappedPrivateKey, signature } = exportedKeyPair; const publicKey = await importKey(exportedPublicKey, "ECDH", "public", true);
    const privateKey = await deriveUnwrap(wrappedPrivateKey, keyBits, "ECDH", description, true);
    return { keyPair: { publicKey, privateKey }, exportedPublicKey, signature };
}

export async function importSigningKeyPair(exportedKeyPair: ExportedSigningKeyPair, keyBits: CryptoKey | BufferSource, description: string): Promise<CryptoKeyPair> {
    const { exportedPublicKey, wrappedPrivateKey } = exportedKeyPair;
    const publicKey = await importKey(exportedPublicKey, "ECDSA", "public", true);
    const privateKey = await deriveUnwrap(wrappedPrivateKey, keyBits, "ECDSA", description, true);
    return { publicKey, privateKey };
}

export function subarray(source: Buffer, start: number, end: number) {
    return Buffer.from(source.subarray(start, end));
}

function assignSubtle(): SubtleCrypto {
    if (isBrowser) {
        return window.crypto.subtle;
    }
    if (isWebWorker) {
        return self.crypto.subtle;
    }
    if (isNode) {
        return eval("require('node:crypto').webcrypto.subtle");
    }
    throw new Error("Couldn't identify environment");
}