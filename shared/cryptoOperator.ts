import _ from "./node_modules/lodash";
import { isBrowser, isNode, isWebWorker } from "./node_modules/browser-or-node";
import { Buffer } from "./node_modules/buffer";
import BufferSerializer from "./custom_modules/buffer-serializer";
import { EncryptedData, SignedEncryptedData, EncryptInfo, PasswordDeriveInfo, randomFunctions, SignedKeyPair, ExposedSignedPublicKey, ExportedSigningKeyPair, ExportedSignedKeyPair, UserEncryptedData } from "./commonTypes";
import BufferWriter from "./custom_modules/buffer-serializer/types/buffer-writer";
import BufferReader from "./custom_modules/buffer-serializer/types/buffer-reader";

export const serializer = new BufferSerializer();
const serializeToB64 = (arg: any) => serialize(arg).toString("base64");
const deserializeFromB64 = (str: string) => deserialize(Buffer.from(str, "base64"));
const serializeMap = (map: Map<any, any>, bufferWriter: BufferWriter) => {
    const entries = Array.from(map.entries())
        .map(([k, v]) => ({ key: serializeToB64(k), value: serializeToB64(v) }))
    serializer.toBufferInternal(serialize(entries), bufferWriter);
}
const deserializeMap = (bufferReader: BufferReader) => {
    const entries: Array<[any, any]> = deserialize(serializer.fromBufferInternal(bufferReader)).map(({ key, value }: { key: any, value: any }) => ([deserializeFromB64(key), deserializeFromB64(value)]));
    return new Map(entries);
}
serializer.register("Map", (value: any) => value instanceof Map, serializeMap, deserializeMap);
serializer.register("undefined", 
    (value: any) => typeof value === "undefined", 
    (v: undefined, bufferWriter: BufferWriter) => serializer.toBufferInternal("$undefined$", bufferWriter), 
    (bufferReader: BufferReader) => {
        serializer.fromBufferInternal(bufferReader);
        return undefined as any;
    });
export const serialize = (thing: any) => serializer.toBuffer(thing);
export const deserialize = (buff: Buffer) => serializer.fromBuffer(buff);
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

export async function digest(algorithm: AlgorithmIdentifier, data: BufferSource) {
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

export async function importKey(keyData: Buffer, name: "ECDH" | "ECDSA", type: "public" | "private", extractable: boolean): Promise<CryptoKey> {
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

export async function encrypt(encryptInfo: EncryptInfo, plaintext: Buffer): Promise<Buffer> {
    const { encryptKey, iv } = encryptInfo;
    return Buffer.from(await subtle.encrypt(aesGCM(iv), encryptKey, plaintext));
}

export async function decrypt(encryptInfo: EncryptInfo, ciphertext: Buffer): Promise<Buffer> {
    const { encryptKey, iv } = encryptInfo;
    return Buffer.from(await subtle.decrypt(aesGCM(iv), encryptKey, ciphertext));
}

export async function deriveEncrypt(data: any, keyBits: CryptoKey | Buffer, purpose: string, hSalt?: Buffer): Promise<UserEncryptedData> {
    hSalt ||= getRandomVector(48);
    const ciphertext = await encrypt(await deriveAESKey(keyBits, hSalt, purpose), serialize(data));
    return { ciphertext, hSalt };
}

export async function deriveDecrypt(data: UserEncryptedData, keyBits: CryptoKey | Buffer, purpose: string): Promise<any> {
    const { ciphertext, hSalt } = data;
    return deserialize(await decrypt(await deriveAESKey(keyBits, hSalt, purpose), ciphertext));
}

export async function sign(data: Buffer, signingKey: CryptoKey): Promise<Buffer> {
    let algo: any = signingKey.algorithm.name;
    if (algo === "ECDSA") {
        algo = ecdsaSignParams;
    }
    return Buffer.from(await subtle.sign(algo, signingKey, data));
}

export async function verify(signature: Buffer, originalData: Buffer,  verifyingKey: CryptoKey): Promise<boolean> {
    let algo: any = verifyingKey.algorithm.name;
    if (algo === "ECDSA") {
        algo = ecdsaSignParams;
    }
    return await subtle.verify(algo, verifyingKey, signature, originalData);
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

export async function deriveHKDF(keyBits: CryptoKey | Buffer, salt: Buffer, purpose: string, length: 256 | 512 = 256): Promise<Buffer> {
    const importedBits = "algorithm" in keyBits ? keyBits : await importRaw(keyBits);
    return Buffer.from(await subtle.deriveBits(hkdfParams(salt, length, purpose), importedBits, length));
}

export async function deriveAESKey(keyBits: CryptoKey | Buffer, salt: Buffer, purpose: string): Promise<EncryptInfo> {
    let importedBits = "algorithm" in keyBits ? keyBits : await importRaw(keyBits);
    const kdfOutput = Buffer.from(await subtle.deriveBits(hkdfParams(salt, 512, `${purpose} Derive`), importedBits, 384));
    importedBits = await importRaw(subarray(kdfOutput, 0, 32));
    const iv = subarray(kdfOutput, 32, 48);
    const encryptKey = await subtle.deriveKey(hkdfParams(salt, 256, `${purpose} Encrypt|Decrypt`), importedBits, aesKeyGenParams, false, ["unwrapKey", "wrapKey", "encrypt", "decrypt"]);
    return { encryptKey, iv };
}

export async function deriveMACKey(keyBits: CryptoKey | Buffer, salt: Buffer, purpose: string, length: 256 | 512 = 256): Promise<CryptoKey> {
    const importedBits = "algorithm" in keyBits ? keyBits : await importRaw(keyBits);
    return await subtle.deriveKey(hkdfParams(salt, length, purpose), importedBits, hmacKeyGenParams(length), false, ["sign", "verify"]);
}

export async function deriveSignEncrypt(keyBits: CryptoKey | Buffer, plaintext: any, salt: Buffer, purpose: string):
    Promise<EncryptedData>
export async function deriveSignEncrypt(keyBits: CryptoKey | Buffer, plaintext: any, salt: Buffer, purpose: string, signingKey: CryptoKey):
        Promise<SignedEncryptedData>
export async function deriveSignEncrypt(keyBits: CryptoKey | Buffer, plaintext: any, salt: Buffer, purpose: string, signingKey?: CryptoKey):
    Promise<EncryptedData | SignedEncryptedData> {
    const plaintextBuffer = serialize(plaintext);
    const ciphertext = await encrypt(await deriveAESKey(keyBits, salt, purpose), plaintextBuffer);
    if (signingKey) {
        const signature = await sign(plaintextBuffer, signingKey);
        return { ciphertext, signature };
    }
    return { ciphertext };
}

export async function deriveDecryptVerify(keyBits: CryptoKey | Buffer, ciphertext: Buffer, salt: Buffer, purpose: string): Promise<any>
export async function deriveDecryptVerify(keyBits: CryptoKey | Buffer, ciphertext: Buffer, salt: Buffer, purpose: string, signature: Buffer, verifyingKey: CryptoKey): Promise<any>
export async function deriveDecryptVerify(keyBits: CryptoKey | Buffer, ciphertext: Buffer, salt: Buffer, purpose: string, signature?: Buffer, verifyingKey?: CryptoKey): Promise<any> {
    try {
        const plaintext = await decrypt(await deriveAESKey(keyBits, salt, purpose), ciphertext);
        if (signature) {
            const verified = await verify(signature, plaintext, verifyingKey);
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

export async function deriveWrap(keyBits: CryptoKey | Buffer, privateKey: CryptoKey, salt: Buffer, description: string): Promise<Buffer> {
    const { encryptKey, iv } = await deriveAESKey(keyBits, salt, `${description} Wrap|Unwrap`);
    return Buffer.from(await subtle.wrapKey("pkcs8", privateKey, encryptKey, aesGCM(iv)));
}

export async function deriveUnwrap(keyBits: CryptoKey | Buffer, wrappedKey: Buffer, salt: Buffer, name: "ECDH" | "ECDSA", description: string, extractable: boolean): Promise<CryptoKey> {
    const decryptedKey = await decrypt(await deriveAESKey(keyBits, salt, `${description} Wrap|Unwrap`), wrappedKey);
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

export async function exportSigningKeyPair(keyPair: CryptoKeyPair, keyBits: CryptoKey | Buffer, salt: Buffer, description: string): Promise<ExportedSigningKeyPair> {
    const { privateKey, publicKey } = keyPair;
    const exportedPublicKey = await exportKey(publicKey);
    const wrappedPrivateKey = await deriveWrap(keyBits, privateKey, salt, `Signing ${description} Key`);
    return { exportedPublicKey, wrappedPrivateKey };
}

export async function exportSignedKeyPair(signedKeyPair: SignedKeyPair, keyBits: CryptoKey | Buffer, salt: Buffer, description: string): Promise<ExportedSignedKeyPair> {
    const { keyPair: { privateKey }, exportedPublicKey, signature } = signedKeyPair;
    const wrappedPrivateKey = await deriveWrap(keyBits, privateKey, salt, `Signed ${description} Key`);
    return { exportedPublicKey, wrappedPrivateKey, signature };
}

export async function verifyKey(signedKey: ExposedSignedPublicKey, verifyingKey: CryptoKey): Promise<CryptoKey> {
    const { exportedPublicKey, signature } = signedKey;
    if (!(await verify(signature, exportedPublicKey, verifyingKey)))
        return null;
    return await importKey(exportedPublicKey, "ECDH", "public", true);
}

export async function importSignedKeyPair(exportedKeyPair: ExportedSignedKeyPair, keyBits: CryptoKey | Buffer, salt: Buffer, description: string): Promise<SignedKeyPair> {
    const { exportedPublicKey, wrappedPrivateKey, signature } = exportedKeyPair; const publicKey = await importKey(exportedPublicKey, "ECDH", "public", true);
    const privateKey = await deriveUnwrap(keyBits, wrappedPrivateKey, salt, "ECDH", `Signed ${description} Key`, true);
    return { keyPair: { publicKey, privateKey }, exportedPublicKey, signature };
}

export async function importSigningKeyPair(exportedKeyPair: ExportedSigningKeyPair, keyBits: CryptoKey | Buffer, salt: Buffer, description: string): Promise<CryptoKeyPair> {
    const { exportedPublicKey, wrappedPrivateKey } = exportedKeyPair;
    const publicKey = await importKey(exportedPublicKey, "ECDSA", "public", true);
    const privateKey = await deriveUnwrap(keyBits, wrappedPrivateKey, salt, "ECDSA", `Signing ${description} Key`, true);
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
}