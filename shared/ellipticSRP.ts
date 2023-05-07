import _ from "./node_modules/lodash";
import { Buffer } from "./node_modules/buffer";
import * as crypto from "./cryptoOperator";
import { RistrettoPoint } from "@noble/curves/ed25519";

function hexToBigInt(hex: string) {
    return BigInt(`0x${hex}`);
}

async function getVerifierPrivateHex(saltBase64: string, passwordString: string) {
    const passwordHash = await crypto.digestToBase64("SHA-512", Buffer.from(passwordString));
    return await crypto.digestToHex("SHA-512", Buffer.from(`${saltBase64}#${passwordHash}`));
}

export function generateEphemeral(): [string, RistrettoPoint] {
    const emphemeralPrivateHex = crypto.getRandomVector(64).toString("hex");
    const ephemeralPublicHex = RistrettoPoint.hashToCurve(emphemeralPrivateHex);
    return [emphemeralPrivateHex, ephemeralPublicHex];
}

export async function generateClientRegistration(saltBase64: string, username: string, password: string) {
    const verifierPointHex = RistrettoPoint.hashToCurve(await getVerifierPrivateHex(saltBase64, `${username}#${password}`)).toHex();
    return { username, verifierPointHex };
}

export async function clientCalculation(verifierPrivateHex: string, clientEphemeralPrivateHex: string, passwordEntangledHex: string) {
    const verifierPoint = RistrettoPoint.hashToCurve(verifierPrivateHex);
    const verifierExpanded = RistrettoPoint.hashToCurve(await crypto.digestToHex("SHA-512", verifierPoint.toRawBytes()));
    const passwordEntangledPoint = RistrettoPoint.fromHex(passwordEntangledHex);
    const serverEphemeralPoint = passwordEntangledPoint.subtract(verifierExpanded);
    const clientEphemeralPoint = RistrettoPoint.hashToCurve(clientEphemeralPrivateHex);
    const commonHash = await crypto.digestToHex("SHA-512", serverEphemeralPoint.add(clientEphemeralPoint).toRawBytes());
    const commonHashBigInt = hexToBigInt(commonHash);
    const scalarCommonSum = hexToBigInt(clientEphemeralPrivateHex) + (commonHashBigInt * hexToBigInt(verifierPrivateHex));
    const sharedSecret = Buffer.from(serverEphemeralPoint.multiply(scalarCommonSum).toRawBytes()).reverse();
    const sharedSecretBase64 = sharedSecret.toString("base64");
    const confirmationCodeBase64 = await crypto.digestToBase64("SHA-512", Buffer.from((hexToBigInt(sharedSecret.toString("hex")) + commonHashBigInt).toString(16), "hex"));
    return { sharedSecretBase64, confirmationCodeBase64 };
}

export async function serverCalculation(verifierPointHex: string, serverEphemeralPrivateHex: string, clientEphemeralPointHex: string) {
    const verifierPoint = RistrettoPoint.fromHex(verifierPointHex);
    const serverEphemeralPoint = RistrettoPoint.hashToCurve(serverEphemeralPrivateHex);
    const clientEphemeralPoint = RistrettoPoint.fromHex(clientEphemeralPointHex);
    const commonHash = await crypto.digestToHex("SHA-512", serverEphemeralPoint.add(clientEphemeralPoint).toRawBytes());
    const commonHashBigInt = hexToBigInt(commonHash);
    const vectorCommonSum = clientEphemeralPoint.add(verifierPoint.multiply(commonHashBigInt));
    const sharedSecret = vectorCommonSum.multiply(hexToBigInt(serverEphemeralPrivateHex));
    const sharedSecretBigInt = hexToBigInt(Buffer.from(sharedSecret.toRawBytes()).reverse().toString("hex"));
    const confirmationCodeBase64 = await crypto.digestToBase64("SHA-512", Buffer.from((sharedSecretBigInt + commonHashBigInt).toString(16), "hex"));
    return confirmationCodeBase64;
}

export async function serverGetEntangledPassword(verifierPointHex: string, serverEphemeralPrivateHex: string) {
    const verifierPoint = RistrettoPoint.fromHex(verifierPointHex);
    const verifierExpanded = RistrettoPoint.hashToCurve(await crypto.digestToHex("SHA-512", verifierPoint.toRawBytes()));
    const serverEphemeralPoint = RistrettoPoint.hashToCurve(serverEphemeralPrivateHex);
    return serverEphemeralPoint.add(verifierExpanded).toHex();
}