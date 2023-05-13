import _ from "lodash";
import { Buffer } from "./node_modules/buffer";
import { RistrettoPoint } from "@noble/curves/ed25519";
import { sha3_224, sha3_512 } from "@noble/hashes/sha3";
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

function generateEphemeral(): [Uint8Array, RistrettoPoint] {
    const emphemeralPrivate = getRandomVector(28);
    const ephemeralPublic = getPublicPoint(emphemeralPrivate);
    return [emphemeralPrivate, ephemeralPublic];
}

function getVerifierPrivate(saltBase64: string, username: string, password: string) {
    return sha3_224(`${saltBase64}|${Buffer.from(sha3_512(`${username}#${password}`)).toString("base64")}`);
}

function getPurposes(side: "Client" | "Server") {
    const clientConfirm = "ClientConfirmationCode";
    const serverConfirm = "ServerConfirmationCode";
    const [generatePurpose, confirmPurpose] = side === "Client" ? [clientConfirm, serverConfirm] : [serverConfirm, clientConfirm];
    return { generatePurpose, confirmPurpose };
}

async function setupConfirmation(sharedSecret: Uint8Array, pointToSign: RistrettoPoint, pointToConfirm: RistrettoPoint, side: "Client" | "Server") {
    const sharedKeyBits = await importRaw(sharedSecret);
    const commonHash = Buffer.from(sha3_224(pointToSign.add(pointToConfirm).toRawBytes()));
    const toSign = Buffer.from(pointToSign.toRawBytes());
    const toConfirm = Buffer.from(pointToConfirm.toRawBytes());
    const { generatePurpose, confirmPurpose } = getPurposes(side);
    const confirmationCode = await crypto.deriveSign(toSign, sharedKeyBits, commonHash, generatePurpose);
    const confirmCode = async (confirmationCode: Buffer) => await crypto.deriveVerify(toConfirm, confirmationCode, sharedKeyBits, commonHash, confirmPurpose);
    return { confirmationCode, confirmCode };
}

export function generateClientRegistration(username: string, password: string) {
    const saltBase64 = getRandomVector(64).toString("base64");
    const verifierPointHex = getPublicPoint(getVerifierPrivate(saltBase64, username, password)).toHex();
    return { username, saltBase64, verifierPointHex };
}

export async function clientSetupAuthProcess(username: string, password: string) {
    const [clientEphemeralPrivate, clientEphemeralPoint] = generateEphemeral();
    const clientEphemeralPointHex = clientEphemeralPoint.toHex();
    const processAuthChallenge = async (saltBase64: string, passwordEntangledHex: string, serverConfirmationCode: Buffer) => {
        const verifierPrivate = getVerifierPrivate(saltBase64, username, password)
        const verifierExpandedPoint = getPublicPoint(sha3_224(getPublicPoint(verifierPrivate).toRawBytes()));
        const passwordEntangledPoint = RistrettoPoint.fromHex(passwordEntangledHex);
        const serverEphemeralPoint = passwordEntangledPoint.subtract(verifierExpandedPoint);
        const commonHash = sha3_224(serverEphemeralPoint.add(clientEphemeralPoint).toRawBytes());
        const vector1 = getSharedSecret(clientEphemeralPrivate, serverEphemeralPoint);
        const vector2 = getSharedSecret(verifierPrivate, serverEphemeralPoint).multiply(toBigInt(commonHash));
        const sharedSecret = vector1.add(vector2).toRawBytes();
        const sharedKeyBits = await importRaw(sha3_512(sharedSecret));
        const { confirmationCode, confirmCode } = await setupConfirmation(sharedSecret, serverEphemeralPoint, clientEphemeralPoint, "Client");
        const confirmed = await confirmCode(serverConfirmationCode);
        return confirmed ? { sharedKeyBits, confirmationCode } : null;
    }
    return { clientEphemeralPointHex, processAuthChallenge }
}

export async function serverSetupAuthChallenge(verifierPointHex: string, clientEphemeralPointHex: string) {
    const [serverEphemeralPrivate, serverEphemeralPoint] = generateEphemeral();
    const verifierPoint = RistrettoPoint.fromHex(verifierPointHex);
    const verifierExpandedPoint = getPublicPoint(sha3_224(verifierPoint.toRawBytes()));
    const clientEphemeralPoint = RistrettoPoint.fromHex(clientEphemeralPointHex);
    const commonHash = sha3_224(serverEphemeralPoint.add(clientEphemeralPoint).toRawBytes());
    const vector1 = getSharedSecret(serverEphemeralPrivate, clientEphemeralPoint);
    const vector2 = getSharedSecret(serverEphemeralPrivate, verifierPoint).multiply(toBigInt(commonHash));
    const sharedSecret = vector1.add(vector2).toRawBytes();
    const sharedKeyBits = await importRaw(sha3_512(sharedSecret));
    const { confirmationCode, confirmCode } = await setupConfirmation(sharedSecret, clientEphemeralPoint, serverEphemeralPoint, "Server");
    const passwordEntangledHex = serverEphemeralPoint.add(verifierExpandedPoint).toHex();
    return { sharedKeyBits, confirmationCode, confirmCode, passwordEntangledHex };
}