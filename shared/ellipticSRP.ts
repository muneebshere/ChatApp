import _ from "lodash";
import { RistrettoPoint, ed25519 } from "@noble/curves/ed25519";
import { sha3_224 as sha224_raw, sha3_512 as sha512_raw } from "@noble/hashes/sha3";
import * as crypto from "./cryptoOperator";
import { getRandomVector, importRaw } from "./cryptoOperator";
import { PasswordDeriveInfo, PasswordEntangleInfo } from "./commonTypes";

export type ConfirmationData = Readonly<{
    commonHash: Buffer,
    toConfirm: Buffer,
    confirmPurpose: string
}>

type ServerAuthChallengeNow = Readonly<{ 
    sharedKeyBits: CryptoKey, 
    serverConfirmationCode: Buffer,
    verifierEntangled: Buffer,
    confirmClient: (confirmationCode: Buffer) => Promise<boolean>, 
}>;

export type ServerAuthChallengeLater = Readonly<{ 
    sharedSecret: Buffer, 
    serverConfirmationCode: Buffer,
    verifierEntangled: Buffer,
    clientConfirmationData: ConfirmationData;
}>;

type ClientAuthChallengeNowResult = Readonly<{ 
    sharedKeyBits: CryptoKey, 
    clientConfirmationCode: Buffer,
    confirmServer: (confirmationCode: Buffer) => Promise<boolean>, 
}>;

export type ClientAuthChallengeLaterResult = Readonly<{ 
    sharedSecret: Buffer, 
    clientConfirmationCode: Buffer,
    serverConfirmationData: ConfirmationData;
}>;

function powerMod(a: bigint, e: bigint, m: bigint): bigint {
    if (m === 1n) return 0n;
    let result = 1n;
    a = a % m;
    while (e > 0) {
        if (e % 2n === 1n)  //odd number
            result = (result * a) % m;
        e = e >> 1n; //divide by 2
        a = (a * a) % m;
    }
    return result;
}

function invMod(a: bigint, m: bigint): bigint {
    return powerMod(a, m - 2n, m);
}

function toBigInt(uint8: Buffer) {
    return BigInt(`0x${uint8.toString("hex")}`);
}

function toBuffer(point: RistrettoPoint) {
    return Buffer.from(point.toRawBytes());
}

function sha224(input: Buffer) {
    return Buffer.from(sha224_raw(input));
}

function sha512(input: Buffer) {
    return Buffer.from(sha512_raw(input));
}

function getSharedSecret(privateKey: Buffer, publicKey: RistrettoPoint) {
    if (privateKey.length !== 28) throw "Private key must be 224-bit";
    return publicKey.multiply(toBigInt(privateKey));
}

function getPublicPoint(privateKey: Buffer) {
    return getSharedSecret(privateKey, RistrettoPoint.BASE);
}

function condenseIntoPair(seed: Buffer): [Buffer, RistrettoPoint] {
    const privateValue = Buffer.from(sha224(seed));
    const publicPoint = getPublicPoint(privateValue);
    return [privateValue, publicPoint];
}

function generateEphemeral(): [Buffer, RistrettoPoint] {
    return condenseIntoPair(getRandomVector(64));
}

function getPurposes(side: "Client" | "Server") {
    const clientConfirm = "ClientConfirmationCode";
    const serverConfirm = "ServerConfirmationCode";
    const [generatePurpose, confirmPurpose] = side === "Client" ? [clientConfirm, serverConfirm] : [serverConfirm, clientConfirm];
    return { generatePurpose, confirmPurpose };
}

async function setupConfirmation(sharedSecret: Buffer, pointToSign: RistrettoPoint, pointToConfirm: RistrettoPoint, side: "Client" | "Server") {
    const sharedKeyBits = await importRaw(sharedSecret);
    const commonHash = sha224(toBuffer(pointToSign.add(pointToConfirm)));
    const toSign = toBuffer(pointToSign);
    const toConfirm = toBuffer(pointToConfirm);
    const { generatePurpose, confirmPurpose } = getPurposes(side);
    const confirmationCode = await crypto.deriveSign(toSign, sharedKeyBits, commonHash, generatePurpose);
    const confirmCode = async (confirmationCode: Buffer) => await crypto.deriveVerify(toConfirm, confirmationCode, sharedKeyBits, commonHash, confirmPurpose);
    return { confirmationCode, confirmCode };
}

async function setupConfirmationData(sharedSecret: Buffer, toSign: RistrettoPoint, pointToConfirm: RistrettoPoint, side: "Client" | "Server") {
    const sharedKeyBits = await importRaw(sharedSecret);
    const commonHash = sha224(toBuffer(toSign.add(pointToConfirm)));
    const { generatePurpose, confirmPurpose } = getPurposes(side);
    const toConfirm = toBuffer(pointToConfirm);
    const confirmationCode = await crypto.deriveSign(Buffer.from(toSign.toRawBytes()), sharedKeyBits, commonHash, generatePurpose);
    return { confirmationCode, commonHash, toConfirm, confirmPurpose };
}

export async function getSharedKeyBits(sharedSecret: Buffer) {
    return await importRaw(sha512(sharedSecret));
}

export async function processConfirmationData(sharedSecret: Buffer, confirmationCode: Buffer, confirmationData: ConfirmationData) {
    const { commonHash, confirmPurpose, toConfirm } = confirmationData;
    const sharedKeyBits = await importRaw(sharedSecret);
    return await crypto.deriveVerify(toConfirm, confirmationCode, sharedKeyBits, commonHash, confirmPurpose);
}

export async function entanglePassword(passwordString: string, outputPoint?: RistrettoPoint) {
    const [passwordBits, pInfo] = await crypto.deriveMasterKeyBits(passwordString);
    const [p, ] = condenseIntoPair(passwordBits);
    outputPoint ||= generateEphemeral()[1];
    const passwordEntangledPoint = toBuffer(getSharedSecret(p, outputPoint));
    const outputBits = sha512(toBuffer(outputPoint));
    return [{ passwordEntangledPoint, ...pInfo }, outputBits] as const;
}

export async function disentanglePasswordToPoint(passwordString: string, passwordEntangleInfo: PasswordEntangleInfo) {
    const { passwordEntangledPoint, ...pInfo } = passwordEntangleInfo;
    const passwordBits = await crypto.deriveMasterKeyBits(passwordString, pInfo);
    const passwordEntangledPublic = RistrettoPoint.fromHex(passwordEntangledPoint);
    const passwordInv = invMod(toBigInt(sha224(passwordBits)), ed25519.CURVE.n);
    return passwordEntangledPublic.multiply(passwordInv);
}

export async function disentanglePasswordToBits(passwordString: string, passwordEntangleInfo: PasswordEntangleInfo) {
    return sha512(toBuffer(await disentanglePasswordToPoint(passwordString, passwordEntangleInfo)));
}

export async function generateClientRegistration(passwordString: string) {
    const [passwordBits, verifierDerive] = await crypto.deriveMasterKeyBits(passwordString);
    const verifierPoint = toBuffer(condenseIntoPair(passwordBits)[1])
    return { verifierPoint, verifierDerive };
}

export async function clientSetupAuthProcess(passwordString: string) {
    const [clientEphemeralPrivate, clientEphemeralPoint] = generateEphemeral();
    const clientEphemeralPublic = toBuffer(clientEphemeralPoint);

    async function processAuthChallenge(verifierEntangled: Buffer, verifierDerive: PasswordDeriveInfo, confirm: "now"): Promise<ClientAuthChallengeNowResult>;
    async function processAuthChallenge(verifierEntangled: Buffer, verifierDerive: PasswordDeriveInfo, confirm: "later"): Promise<ClientAuthChallengeLaterResult>;
    async function processAuthChallenge(verifierEntangled: Buffer, verifierDerive: PasswordDeriveInfo, confirm: "now" | "later"): Promise<ClientAuthChallengeNowResult | ClientAuthChallengeLaterResult> {
        const passwordBits = await crypto.deriveMasterKeyBits(passwordString, verifierDerive);
        const [verifierPrivate, verifierPoint] = condenseIntoPair(passwordBits);
        const [, verifierExpandedPoint] = condenseIntoPair(toBuffer(verifierPoint));
        const verifierEntangledPoint = RistrettoPoint.fromHex(verifierEntangled);
        const serverEphemeralPublic = verifierEntangledPoint.subtract(verifierExpandedPoint);
        const commonHash = sha224(toBuffer(serverEphemeralPublic.add(clientEphemeralPoint)));
        const vector1 = getSharedSecret(clientEphemeralPrivate, serverEphemeralPublic);
        const vector2 = getSharedSecret(verifierPrivate, serverEphemeralPublic).multiply(toBigInt(commonHash));
        const sharedSecret = toBuffer(vector1.add(vector2));
        const sharedKeyBits = await importRaw(sha512(sharedSecret));
        if (confirm === "later") {
            const { confirmationCode: clientConfirmationCode, ...serverConfirmationData } = await setupConfirmationData(sharedSecret, serverEphemeralPublic, clientEphemeralPoint, "Client");
            return { sharedSecret, clientConfirmationCode, serverConfirmationData };
        }
        else {
            const { confirmationCode: clientConfirmationCode, confirmCode: confirmServer } = await setupConfirmation(sharedSecret, serverEphemeralPublic, clientEphemeralPoint, "Client");
            return { sharedKeyBits, clientConfirmationCode, confirmServer };
        }
    }
    return { clientEphemeralPublic, processAuthChallenge };
}

export async function serverSetupAuthChallenge(verifierPublic: Buffer, clientEphemeralPublic: Buffer, confirm: "now"): Promise<ServerAuthChallengeNow>;
export async function serverSetupAuthChallenge(verifierPublic: Buffer, clientEphemeralPublic: Buffer, confirm: "later"): Promise<ServerAuthChallengeLater>;
export async function serverSetupAuthChallenge(verifierPublic: Buffer, clientEphemeralPublic: Buffer, confirm: "now" | "later"): Promise<ServerAuthChallengeLater | ServerAuthChallengeNow> {
    const [serverEphemeralPrivate, serverEphemeralPublic] = generateEphemeral();
    const verifierPoint = RistrettoPoint.fromHex(verifierPublic);
    const verifierExpandedPoint = getPublicPoint(sha224(verifierPublic));
    const clientEphemeralPoint = RistrettoPoint.fromHex(clientEphemeralPublic);
    const commonHash = sha224(toBuffer(serverEphemeralPublic.add(clientEphemeralPoint)));
    const vector1 = getSharedSecret(serverEphemeralPrivate, clientEphemeralPoint);
    const vector2 = getSharedSecret(serverEphemeralPrivate, verifierPoint).multiply(toBigInt(commonHash));
    const sharedSecret = toBuffer(vector1.add(vector2));
    const sharedKeyBits = await importRaw(sha512(sharedSecret));
    const verifierEntangled = toBuffer(serverEphemeralPublic.add(verifierExpandedPoint));
    if (confirm === "later") {
        const { confirmationCode: serverConfirmationCode, ...clientConfirmationData } = await setupConfirmationData(sharedSecret, clientEphemeralPoint, serverEphemeralPublic, "Server");
        return { sharedSecret, serverConfirmationCode, verifierEntangled, clientConfirmationData };
    }
    else {
        const { confirmationCode: serverConfirmationCode, confirmCode: confirmClient } = await setupConfirmation(sharedSecret, clientEphemeralPoint, serverEphemeralPublic, "Server");
        return { sharedKeyBits, serverConfirmationCode, confirmClient, verifierEntangled };
    }
}