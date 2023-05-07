import _ from "./node_modules/lodash";
import { Buffer } from "./node_modules/buffer";
import { RistrettoPoint } from "@noble/curves/ed25519";
import { sha3_224, sha3_512 } from "@noble/hashes/sha3";
import { Input, randomBytes } from "@noble/hashes/utils";

function toBigInt(uint8: Uint8Array) {
    return BigInt(`0x${Buffer.from(uint8).toString("hex")}`);
}

function getPublicPoint(privateKey: Uint8Array) {
    if (privateKey.length !== 28) throw "Private key must be 224-bit";
    return RistrettoPoint.BASE.multiply(toBigInt(privateKey));
}

function sha3_512_base64(message: Input) {
    return Buffer.from(sha3_512(message)).toString("base64");
}

async function getVerifierPrivateHex(saltBase64: string, username: string, password: string) {
    return sha3_224(`${saltBase64}#${sha3_512_base64(`${username}#${password}`)}`);
}

export function generateEphemeral(): [Uint8Array, RistrettoPoint] {
    const emphemeralPrivate = randomBytes(28);
    const ephemeralPublic = getPublicPoint(emphemeralPrivate);
    return [emphemeralPrivate, ephemeralPublic];
}

export async function generateClientRegistration(saltBase64: string, username: string, password: string) {
    const verifierPointHex = getPublicPoint(await getVerifierPrivateHex(saltBase64, username, password)).toHex();
    return { username, verifierPointHex };
}

export async function clientCalculation(verifierPrivate: Uint8Array, clientEphemeralPrivate: Uint8Array, passwordEntangledHex: string) {
    const verifierPoint = getPublicPoint(verifierPrivate);
    const verifierExpanded = getPublicPoint(sha3_224(verifierPoint.toRawBytes()));
    const passwordEntangledPoint = RistrettoPoint.fromHex(passwordEntangledHex);
    const serverEphemeralPoint = passwordEntangledPoint.subtract(verifierExpanded);
    const clientEphemeralPoint = getPublicPoint(clientEphemeralPrivate);
    const commonHash = sha3_224(serverEphemeralPoint.add(clientEphemeralPoint).toRawBytes());
    const commonHashBigInt = toBigInt(commonHash);
    const scalarCommonSum = toBigInt(clientEphemeralPrivate) + (commonHashBigInt * toBigInt(verifierPrivate));
    const sharedSecret = Buffer.from(serverEphemeralPoint.multiply(scalarCommonSum).toRawBytes()).reverse();
    const sharedSecretBase64 = sharedSecret.toString("base64");
    const confirmationCodeBase64 = sha3_512_base64((toBigInt(sharedSecret) + commonHashBigInt).toString(36));
    return { sharedSecretBase64, confirmationCodeBase64 };
}

export async function serverCalculation(verifierPointHex: string, serverEphemeralPrivate: Uint8Array, clientEphemeralPointHex: string) {
    const verifierPoint = RistrettoPoint.fromHex(verifierPointHex);
    const serverEphemeralPoint = getPublicPoint(serverEphemeralPrivate);
    const clientEphemeralPoint = RistrettoPoint.fromHex(clientEphemeralPointHex);
    const commonHash = sha3_224(serverEphemeralPoint.add(clientEphemeralPoint).toRawBytes());
    const commonHashBigInt = toBigInt(commonHash);
    const vectorCommonSum = clientEphemeralPoint.add(verifierPoint.multiply(commonHashBigInt));
    const sharedSecret = Buffer.from(vectorCommonSum.multiply(toBigInt(serverEphemeralPrivate)).toRawBytes()).reverse();
    const sharedSecretBase64 = sharedSecret.toString("base64");
    const confirmationCodeBase64 = sha3_512_base64((toBigInt(sharedSecret) + commonHashBigInt).toString(36));
    return { sharedSecretBase64, confirmationCodeBase64 };
}

export async function serverGetEntangledPassword(verifierPointHex: string) {
    const [serverEphemeralPrivate, serverEphemeralPoint] = generateEphemeral();
    const verifierPoint = RistrettoPoint.fromHex(verifierPointHex);
    const verifierExpanded = getPublicPoint(sha3_224(verifierPoint.toRawBytes()));
    const passwordEntangledHex = serverEphemeralPoint.add(verifierExpanded).toHex();
    return { serverEphemeralPrivate, passwordEntangledHex };
}