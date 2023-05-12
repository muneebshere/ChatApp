import _ from "lodash";
import { Buffer } from "./node_modules/buffer";
import { RistrettoPoint } from "@noble/curves/ed25519";
import { sha3_224, sha3_512 } from "@noble/hashes/sha3";
import { Input, randomBytes } from "@noble/hashes/utils";
import * as crypto from "./cryptoOperator";
import { getRandomVector, importRaw } from "./cryptoOperator";

function toBigInt(uint8: Uint8Array) {
    return BigInt(`0x${Buffer.from(uint8).toString("hex")}`);
}

function getSharedSecret(privateKey: Uint8Array, publicKey: RistrettoPoint) {
    if (privateKey.length !== 28) throw "Private key must be 224-bit";
    return publicKey.multiply(toBigInt(privateKey));
}

function getPublicPoint(privateKey: Uint8Array) {
    return getSharedSecret(privateKey, RistrettoPoint.BASE);
}

function sha3_512_base64(message: Input) {
    return Buffer.from(sha3_512(message)).toString("base64");
}

async function calculateSharedKeyBits(vector1: RistrettoPoint, vector2: RistrettoPoint, commonHash: Uint8Array) {
    const sharedSecret = Buffer.from(vector1.add(vector2).toRawBytes()).reverse();
    const sharedKeyBits = await importRaw(sha3_512(sharedSecret));
    return { sharedKeyBits, commonHash: Buffer.from(commonHash) };
}

export async function calculateConfirmationCode(publicPointHex: string, commonHash: Buffer, sharedKeyBits: CryptoKey, purpose: string) {
    return await crypto.deriveSign(Buffer.from(publicPointHex, "hex"), sharedKeyBits, commonHash, purpose);
}

export async function verifyConfirmationCode(signature: Buffer, publicPointHex: string, commonHash: Buffer, sharedKeyBits: CryptoKey, purpose: string) {
    return await crypto.deriveVerify(Buffer.from(publicPointHex, "hex"), signature, sharedKeyBits, commonHash, purpose);
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
    const commonHash = sha3_224(serverEphemeralPoint.add(clientEphemeralPoint).toRawBytes());
    const vector1 = getSharedSecret(clientEphemeralPrivate, serverEphemeralPoint);
    const vector2 = getSharedSecret(verifierPrivate, serverEphemeralPoint).multiply(toBigInt(commonHash));
    return { ...(await calculateSharedKeyBits(vector1, vector2, commonHash)), serverEphemeralPoint };
}

export async function serverCalculation(verifierPointHex: string, serverEphemeralPrivate: Uint8Array, clientEphemeralPointHex: string) {
    const verifierPoint = RistrettoPoint.fromHex(verifierPointHex);
    const serverEphemeralPoint = getPublicPoint(serverEphemeralPrivate);
    const clientEphemeralPoint = RistrettoPoint.fromHex(clientEphemeralPointHex);
    const commonHash = sha3_224(serverEphemeralPoint.add(clientEphemeralPoint).toRawBytes());
    const vector1 = getSharedSecret(serverEphemeralPrivate, clientEphemeralPoint);
    const vector2 = getSharedSecret(serverEphemeralPrivate, verifierPoint).multiply(toBigInt(commonHash));
    return await calculateSharedKeyBits(vector1, vector2, commonHash);
}

export function serverGetEntangledPassword(verifierPointHex: string) {
    const [serverEphemeralPrivate, serverEphemeralPoint] = generateEphemeral();
    const verifierPoint = RistrettoPoint.fromHex(verifierPointHex);
    const verifierExpanded = getPublicPoint(sha3_224(verifierPoint.toRawBytes()));
    const passwordEntangledHex = serverEphemeralPoint.add(verifierExpanded).toHex();
    return { serverEphemeralPrivate, serverEphemeralPoint, passwordEntangledHex };
}