import _ from "./node_modules/lodash";
import { Buffer } from "./node_modules/buffer";
import { RistrettoPoint } from "@noble/curves/ed25519";
import { sha3_224, sha3_512 } from "@noble/hashes/sha3";
import { Input, randomBytes } from "@noble/hashes/utils";
import { getRandomVector, importRaw } from "./cryptoOperator";

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

function calculateConfirmationCode(seed: string, commonHash: bigint, sharedSecret: bigint) {
    return sha3_512_base64((toBigInt(Buffer.from(seed, "utf8")) * (sharedSecret + commonHash)).toString(36));
}

function getConfirmationCodes(commonHash: bigint, sharedSecret: bigint) {
    const [clientConfirmationCode, serverConfirmationCode] = 
        ["client", "server"].map((seed) => calculateConfirmationCode(seed, commonHash, sharedSecret));
    return { clientConfirmationCode, serverConfirmationCode }; 
}

async function calculateShared(vectorCommonSum: RistrettoPoint, commonHash: bigint) {
    const sharedSecret = Buffer.from(vectorCommonSum.toRawBytes()).reverse();
    const sharedKeyBits = await importRaw(sha3_512(sharedSecret));
    const confirmationCodes = getConfirmationCodes(commonHash, toBigInt(sharedSecret));
    return { sharedKeyBits, ...confirmationCodes };
}

export function getVerifierPrivate(saltBase64: string, username: string, password: string) {
    return sha3_224(`${saltBase64}|${sha3_512_base64(`${username}#${password}`)}`);
}

export function generateEphemeral(): [Uint8Array, RistrettoPoint] {
    const emphemeralPrivate = randomBytes(28);
    const ephemeralPublic = getPublicPoint(emphemeralPrivate);
    return [emphemeralPrivate, ephemeralPublic];
}

export function generateClientRegistration(username: string, password: string) {
    const saltBase64 = getRandomVector(64).toString("base64");
    const verifierPointHex = getPublicPoint(getVerifierPrivate(saltBase64, username, password)).toHex();
    return { username, saltBase64, verifierPointHex };
}

export async function clientCalculation(verifierPrivate: Uint8Array, clientEphemeralPrivate: Uint8Array, passwordEntangledHex: string) {
    const verifierPoint = getPublicPoint(verifierPrivate);
    const verifierExpanded = getPublicPoint(sha3_224(verifierPoint.toRawBytes()));
    const passwordEntangledPoint = RistrettoPoint.fromHex(passwordEntangledHex);
    const serverEphemeralPoint = passwordEntangledPoint.subtract(verifierExpanded);
    const clientEphemeralPoint = getPublicPoint(clientEphemeralPrivate);
    const commonHash = toBigInt(sha3_224(serverEphemeralPoint.add(clientEphemeralPoint).toRawBytes()));
    const vector1 = serverEphemeralPoint.multiply(toBigInt(clientEphemeralPrivate));
    const vector2 = serverEphemeralPoint.multiply(toBigInt(verifierPrivate)).multiply(commonHash);
    return await calculateShared(vector1.add(vector2), commonHash);
}

export async function serverCalculation(verifierPointHex: string, serverEphemeralPrivate: Uint8Array, clientEphemeralPointHex: string) {
    const verifierPoint = RistrettoPoint.fromHex(verifierPointHex);
    const serverEphemeralPoint = getPublicPoint(serverEphemeralPrivate);
    const clientEphemeralPoint = RistrettoPoint.fromHex(clientEphemeralPointHex);
    const commonHash = toBigInt(sha3_224(serverEphemeralPoint.add(clientEphemeralPoint).toRawBytes()));
    const vector1 = clientEphemeralPoint.multiply(toBigInt(serverEphemeralPrivate));
    const vector2 = verifierPoint.multiply(toBigInt(serverEphemeralPrivate)).multiply(commonHash);
    return await calculateShared(vector1.add(vector2), commonHash);
}

export function serverGetEntangledPassword(verifierPointHex: string) {
    const [serverEphemeralPrivate, serverEphemeralPoint] = generateEphemeral();
    const verifierPoint = RistrettoPoint.fromHex(verifierPointHex);
    const verifierExpanded = getPublicPoint(sha3_224(verifierPoint.toRawBytes()));
    const passwordEntangledHex = serverEphemeralPoint.add(verifierExpanded).toHex();
    return { serverEphemeralPrivate, passwordEntangledHex };
}