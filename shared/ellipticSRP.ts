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

function condenseIntoPair(seed: Uint8Array): [Uint8Array, RistrettoPoint] {
    const privateValue = sha3_224(seed);
    const publicPoint = getPublicPoint(privateValue);
    return [privateValue, publicPoint];
}

function generateEphemeral(): [Uint8Array, RistrettoPoint] {
    return condenseIntoPair(getRandomVector(64));
}

function getVerifierPrivate(verifierSalt: Buffer, passwordString: string) {
    return sha3_224(`${verifierSalt.toString("base64")}|${Buffer.from(sha3_512(`${passwordString}`)).toString("base64")}`);
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

export function generateClientRegistration(passwordString: string) {
    const verifierSalt = getRandomVector(64);
    const verifierPointHex = getPublicPoint(getVerifierPrivate(verifierSalt, passwordString)).toHex();
    return { verifierSalt, verifierPointHex };
}

export async function clientSetupAuthProcess(passwordString: string) {
    const [clientEphemeralPrivate, clientEphemeralPublic] = generateEphemeral();
    const clientEphemeralPublicHex = clientEphemeralPublic.toHex();
    const processAuthChallenge = async (verifierSalt: Buffer, verifierEntangledHex: string, serverConfirmationCode: Buffer) => {
        const verifierPrivate = getVerifierPrivate(verifierSalt, passwordString)
        const verifierExpandedPoint = getPublicPoint(sha3_224(getPublicPoint(verifierPrivate).toRawBytes()));
        const verifierEntangledPoint = RistrettoPoint.fromHex(verifierEntangledHex);
        const serverEphemeralPublic = verifierEntangledPoint.subtract(verifierExpandedPoint);
        const commonHash = sha3_224(serverEphemeralPublic.add(clientEphemeralPublic).toRawBytes());
        const vector1 = getSharedSecret(clientEphemeralPrivate, serverEphemeralPublic);
        const vector2 = getSharedSecret(verifierPrivate, serverEphemeralPublic).multiply(toBigInt(commonHash));
        const sharedSecret = vector1.add(vector2).toRawBytes();
        const sharedKeyBits = await importRaw(sha3_512(sharedSecret));
        const { confirmationCode: clientConfirmationCode, confirmCode } = await setupConfirmation(sharedSecret, serverEphemeralPublic, clientEphemeralPublic, "Client");
        const confirmServer = async () => await confirmCode(serverConfirmationCode);
        return { sharedKeyBits, clientConfirmationCode, confirmServer };
    }
    return { clientEphemeralPublicHex, processAuthChallenge };
}

export async function serverSetupAuthChallenge(verifierPointHex: string, clientEphemeralPublicHex: string) {
    const [serverEphemeralPrivate, serverEphemeralPublic] = generateEphemeral();
    const verifierPoint = RistrettoPoint.fromHex(verifierPointHex);
    const verifierExpandedPoint = getPublicPoint(sha3_224(verifierPoint.toRawBytes()));
    const clientEphemeralPublic = RistrettoPoint.fromHex(clientEphemeralPublicHex);
    const commonHash = sha3_224(serverEphemeralPublic.add(clientEphemeralPublic).toRawBytes());
    const vector1 = getSharedSecret(serverEphemeralPrivate, clientEphemeralPublic);
    const vector2 = getSharedSecret(serverEphemeralPrivate, verifierPoint).multiply(toBigInt(commonHash));
    const sharedSecret = vector1.add(vector2).toRawBytes();
    const sharedKeyBits = await importRaw(sha3_512(sharedSecret));
    const { confirmationCode: serverConfirmationCode, confirmCode } = await setupConfirmation(sharedSecret, clientEphemeralPublic, serverEphemeralPublic, "Server");
    const verifierEntangledHex = serverEphemeralPublic.add(verifierExpandedPoint).toHex();
    return { sharedKeyBits, serverConfirmationCode, confirmCode, verifierEntangledHex };
}