import _ from "lodash";
import axios, { AxiosError } from "axios";
import isOnline from "is-online";
import { Queue } from "async-await-queue";
import { X3DHManager } from "./e2e-encryption";
import * as crypto from "../shared/cryptoOperator";
import { serialize, deserialize } from "../shared/cryptoOperator";
import * as esrp from "../shared/ellipticSRP";
import { failure, fromBase64, logError, randomFunctions } from "../shared/commonFunctions";
import { ErrorStrings, Failure, Username, SignUpRequest, NewUserData, Profile, SignUpChallengeResponse, LogInRequest, LogInChallengeResponse, SavePasswordRequest, SavePasswordResponse, SignUpChallenge, LogInResponse, LogInChallenge, LogInSavedRequest, LogInSavedResponse, LogInPermitted, SignUpResponse, EncryptedData, UserData  } from "../shared/commonTypes";
import Client, { ConnectionStatus } from "./Client";

const { getRandomVector, getRandomString } = randomFunctions();
axios.defaults.withCredentials = true;

type SavedAuthData = Readonly<{
    username: string,
    laterConfirmation: esrp.ClientAuthChallengeLaterResult;
    databaseAuthKeyBuffer: Buffer;
}>;

type SavedSessionData = Readonly<{
    username: string,
    clientReference: string,
    sharedKeyBitsBuffer: Buffer,
    encryptionBase: Buffer,
    sessionRecordKey: Buffer,
    userData: Omit<UserData, "encryptionBaseDerive">}>;

const { hostname, protocol } = window.location;
const baseURL = `${protocol}//${hostname}`;
const axInstance = axios.create({ baseURL, maxRedirects: 0, timeout: 2000 });

export type AuthConnectionStatus = Extract<ConnectionStatus, "Online" | "ClientOffline" | "ServerUnreachable">

export default class AuthClient {

    private static verified: Promise<boolean> | null = null;
    private static issuedNonce: { nonceId: string, authNonce: string } | null = null;
    private static nonceQueue = new Queue(1, 10);

    private static notifyConnectionStatus: ((status: AuthConnectionStatus) => void) | null = null;

    private constructor() {}

    static subscribeConnectionStatus(notifyCallback: ((status: AuthConnectionStatus) => void) | null) {
        this.notifyConnectionStatus = notifyCallback;
        this.isServerReachable();
    }

    static async latestJsHash(): Promise<string | null> {
        const response = await this.get("/latestJsHash");
        if (response?.status !== 200) return null;
        else return response.data.latestJsHash;
    }

    static async isServerReachable() {
        const response = await this.get("/isServerActive");
        return response?.status === 200;
    }

    static async userExists(username: string): Promise<boolean | null> {
        const response = await this.get(`/userExists/${username}`);
        if (response?.status === 200) return response.data.exists;
        else return null;
    }

    static async userLogInPermitted(username: string): Promise<LogInPermitted | null> {
        const response = await this.get(`/userLogInPermitted/${username}`);
        if (response?.status === 200) return response.data;
        else return null;
    }

    static async isAuthenticated(): Promise<boolean> {
        const response = await this.get("/isAuthenticated");
        return response?.status === 200 ? response.data.authenticated : null;
    }

    static async getAuthNonce(): Promise<{ nonceId?: string, authNonce?: string }> {
        if (this.verified) await this.verified;
        const token = Symbol();
        await this.nonceQueue.wait(token);
        if (this.issuedNonce) {
            console.log(`Previously obtained nonce id ${this.issuedNonce.nonceId}`);
            this.nonceQueue.end(token);
            return this.issuedNonce;
        }
        const response = await this.get("/authNonce");
        this.issuedNonce ||= response?.status === 200 ? response.data : {};
        this.nonceQueue.end(token);
        setTimeout(() => this.issuedNonce = null, 4500);
        console.log(`Newly obtained nonce id ${this.issuedNonce?.nonceId}`);
        return this.issuedNonce!;
    }

    static async clearNonce() {
        try {
            console.log(`Clearing nonce id ${this.issuedNonce?.nonceId}`);
            await axInstance.delete("/clearNonce");
            this.issuedNonce = null;
        }
        catch(err) {
            logError(err);
        }
    }

    static async verifyAuthentication(authToken: string, sessionRecordKey: string): Promise<boolean | null> {
        const nonceId = this.issuedNonce?.nonceId;
        if (!nonceId) return null;
        if (this.verified) {
            console.log(`Already waiting for nonce id ${nonceId}`)
            return await this.verified;
        }
        this.issuedNonce = null;
        return await (this.verified = new Promise(async (resolve) => {
            const response = await this.get(`/verifyAuthentication/${nonceId}/${authToken}/${sessionRecordKey}`);
            console.log(`Authentication verified: ${response?.data?.verified} for nonce id ${nonceId}`);
            resolve(response?.status === 200 ? response.data.confirmed : null);
            this.verified = null;
        }));
    }

    static async signUp(profile: Profile, password: string, savePassword: boolean): Promise<Client | Failure> {
        if (!(await this.isServerReachable())) return failure(ErrorStrings.NoConnectivity);
        try {
            const { username } = profile;
            const passwordString = `${username}#${password}`
            const { verifierPoint, verifierDerive } = await esrp.generateClientRegistration(passwordString);
            const { clientEphemeralPublic, processAuthChallenge } = await esrp.clientSetupAuthProcess(passwordString);
            const [encryptionBaseDerive, encryptionBase] = await esrp.entanglePassword(passwordString);
            const encryptionBaseVector = await crypto.importRaw(encryptionBase);
            const [x3dhManager, { firstKeys, x3dhIdentity, x3dhData }] = await X3DHManager.new(username, encryptionBaseVector);
            if (!x3dhManager) {
                throw new Error("Failed to create user");
            }
            const { publicIdentity } = x3dhManager;
            const [databaseAuthKeyDerive, databaseAuthKeyBuffer] = await esrp.entanglePassword(passwordString);
            const clientReference = getRandomString(16, "base64");
            const signUpRequest: SignUpRequest = {
                clientReference,
                username,
                verifierPoint,
                clientEphemeralPublic,
                publicIdentity
            };
            const resultInit: SignUpChallenge | Failure = await this.post("initiateSignUp", signUpRequest);
            if ("reason" in resultInit) {
                logError(resultInit);
                return resultInit;
            }
            const { serverIdentityVerifyingKey, verifierEntangled } = resultInit;
            const { clientConfirmationCode, sharedKeyBitsBuffer, confirmServer } = await processAuthChallenge(verifierEntangled, verifierDerive, "now");
            const sharedKeyBits = await crypto.importRaw(sharedKeyBitsBuffer);
            const serverIdentityVerifying = await crypto.deriveEncrypt({ serverIdentityVerifyingKey }, encryptionBaseVector, `${username} Server Identity Verifying Key`);
            const profileData = await x3dhManager.deriveSignEncrypt(profile, encryptionBaseVector, `${username} User Profile`);
            const newUserData: NewUserData =  { userData: { encryptionBaseDerive, profileData, x3dhIdentity, x3dhData, serverIdentityVerifying }, verifierDerive, databaseAuthKeyDerive, firstKeys };
            const newUserDataSigned = await x3dhManager.deriveSignEncrypt(newUserData, sharedKeyBits, `${username} New User Data`);
            const concludeSignUp: SignUpChallengeResponse = { clientConfirmationCode, newUserDataSigned, databaseAuthKeyBuffer };
            const resultConc: SignUpResponse | Failure = await this.post("concludeSignUp", concludeSignUp);
            if ("reason" in resultConc) {
                logError(resultConc);
                return resultConc;
            }
            const { serverConfirmationCode, sessionRecordKeyDeriveSalt, saveSessionKey } = resultConc;
            if (!(await confirmServer(serverConfirmationCode))) {
                logError(new Error("Server confirmation code incorrect."))
                return failure(ErrorStrings.ProcessFailed);
            }
            const sessionCrypto = await x3dhManager.createSessionCrypto(clientReference, sharedKeyBits, serverIdentityVerifyingKey);
            const sessionRecordKey = await crypto.deriveHKDF(sharedKeyBits, sessionRecordKeyDeriveSalt, "Session Record", 512);
            const savedSessionData: SavedSessionData = { username, clientReference, sharedKeyBitsBuffer, encryptionBase, sessionRecordKey, userData: { profileData, x3dhIdentity, x3dhData, serverIdentityVerifying }};
            const savingSession = serialize(await crypto.deriveEncrypt(savedSessionData, saveSessionKey, "SavedSession")).toString("base64");
            window.sessionStorage.setItem("SavedSession", savingSession);
            if (savePassword) {
                const savePasswordSuccess = await this.savePassword(username, passwordString, encryptionBase, databaseAuthKeyBuffer);
                console.log(savePasswordSuccess ? "Password saved successfully." : "Failed to save password.");
            }
            const serverVerifyingKey = await crypto.importKey(serverIdentityVerifyingKey, "ECDSA", "public", false);
            const client = await Client.initiate(baseURL, encryptionBaseVector, sessionRecordKey, username, profile, x3dhManager, sessionCrypto, serverVerifyingKey);
            if (!client) throw new Error("Failed to initiate client.");
            return client;
        }
        catch (err) {
            logError(err);
            return failure(ErrorStrings.ProcessFailed);
        }
    }

    static async logIn(username: string, password: string, savePassword: boolean): Promise<Client | Failure> {
        if (!(await this.isServerReachable())) return failure(ErrorStrings.NoConnectivity);
        try {
            const passwordString = `${username}#${password}`;
            const { clientEphemeralPublic, processAuthChallenge } = await esrp.clientSetupAuthProcess(passwordString);
            const clientReference = getRandomString(16, "base64");
            const logInRequest: LogInRequest = { clientReference, username, clientEphemeralPublic };
            const resultInit: LogInChallenge | Failure = await this.post("initiateLogIn", logInRequest);
            if ("reason" in resultInit) {
                logError(resultInit);
                return resultInit;
            }
            const { verifierEntangled, verifierDerive, databaseAuthKeyDerive } = resultInit;
            const { clientConfirmationCode, sharedKeyBitsBuffer, confirmServer } = await processAuthChallenge(verifierEntangled, verifierDerive, "now");
            const sharedKeyBits = await crypto.importRaw(sharedKeyBitsBuffer);
            const databaseAuthKeyBuffer = await esrp.disentanglePasswordToBits(passwordString, databaseAuthKeyDerive);
            const logInChallengeResponse: LogInChallengeResponse = { clientConfirmationCode, databaseAuthKeyBuffer };
            const resultConc: LogInResponse | Failure = await this.post("concludeLogIn", logInChallengeResponse);
            if ("reason" in resultConc) {
                logError(resultConc);
                return resultConc;
            }
            const { serverConfirmationCode, sessionRecordKeyDeriveSalt, saveSessionKey, encryptionBaseDerive, serverIdentityVerifying, profileData, x3dhIdentity, x3dhData } = resultConc;
            if (!(await confirmServer(serverConfirmationCode))) {
                logError(new Error("Server confirmation code incorrect."))
                return failure(ErrorStrings.ProcessFailed);
            }
            const encryptionBase = await esrp.disentanglePasswordToBits(passwordString, encryptionBaseDerive);
            const encryptionBaseVector = await crypto.importRaw(encryptionBase);
            const { serverIdentityVerifyingKey } = (await crypto.deriveDecrypt(serverIdentityVerifying, encryptionBaseVector, `${username} Server Identity Verifying Key`)) ?? {};
            if (!encryptionBaseVector || !serverIdentityVerifyingKey) {
                return failure(ErrorStrings.ProcessFailed);
            }
            const x3dhManager = await X3DHManager.import(username, x3dhIdentity, x3dhData, encryptionBaseVector);
            const profile: Profile = await x3dhManager?.deriveDecryptVerify(profileData, encryptionBaseVector, `${username} User Profile`);
            if (!profile) {
                return failure(ErrorStrings.ProcessFailed);
            }
            const sessionCrypto = await x3dhManager.createSessionCrypto(clientReference, sharedKeyBits, serverIdentityVerifyingKey);
            const sessionRecordKey = await crypto.deriveHKDF(sharedKeyBits, sessionRecordKeyDeriveSalt, "Session Record", 512);
            const savedSessionData: SavedSessionData = { username, clientReference, sharedKeyBitsBuffer, encryptionBase, sessionRecordKey, userData: { profileData, x3dhIdentity, x3dhData, serverIdentityVerifying }};
            const savingSession = serialize(await crypto.deriveEncrypt(savedSessionData, saveSessionKey, "SavedSession")).toString("base64");
            window.sessionStorage.setItem("SavedSession", savingSession);
            if (savePassword) {
                const savePasswordSuccess = await this.savePassword(username, passwordString, encryptionBase, databaseAuthKeyBuffer);
                console.log(savePasswordSuccess ? "Password saved successfully." : "Failed to save password.");
            }
            const serverVerifyingKey = await crypto.importKey(serverIdentityVerifyingKey, "ECDSA", "public", false);
            const client = await Client.initiate(baseURL, encryptionBaseVector, sessionRecordKey, username, profile, x3dhManager, sessionCrypto, serverVerifyingKey);
            if (!client) throw new Error("Failed to initiate client.");
            return client;
        }
        catch (err) {
            logError(err);
            return failure(ErrorStrings.ProcessFailed);
        }
    }

    static async logInSaved(): Promise<Client | Failure> {
        if (!(await this.isServerReachable())) return failure(ErrorStrings.NoConnectivity);
        try {
            const { serverKeyBits, authData, coreData } = deserialize(fromBase64(window.localStorage.getItem("SavedAuth") || "")) || {};
            if (!serverKeyBits) {
                await this.clearSavedPassword();
                logError("Saved details not found");
                return failure(ErrorStrings.ProcessFailed);
            };
            const passwordSaved = await this.isPasswordSaved();
            if (passwordSaved !== "same-ip") {
                if (passwordSaved === "other-ip") logError("Accessing server from a different ip than the one used to save password");
                else {
                    window.localStorage.removeItem("SavedAuth");
                    logError("Password not saved.");
                }
                return failure(ErrorStrings.ProcessFailed);
            };
            const clientReference = getRandomString(16, "base64");
            const logInSavedRequest: LogInSavedRequest = { clientReference, serverKeyBits };
            const resultInit: Username & { authKeyBits: Buffer } | Failure = await this.post("initiateLogInSaved", logInSavedRequest);
            if ("reason" in resultInit) {
                logError(resultInit);
                return resultInit;
            }
            const { authKeyBits } = resultInit;
            const { username, laterConfirmation, databaseAuthKeyBuffer }: SavedAuthData = await crypto.deriveDecrypt(authData, authKeyBits, "Auth Data");
            const { sharedSecret, clientConfirmationCode, serverConfirmationData } = laterConfirmation;
            const sharedKeyBitsBuffer = esrp.getSharedKeyBitsBuffer(sharedSecret);
            const sharedKeyBits = await crypto.importRaw(sharedKeyBitsBuffer);
            const concludeLogInSaved: Username & LogInChallengeResponse = { username, clientConfirmationCode, databaseAuthKeyBuffer };
            const resultConc: LogInSavedResponse | Failure = await this.post("concludeLogInSaved", concludeLogInSaved);
            if ("reason" in resultConc) {
                logError(resultConc);
                return resultConc;
            }
            const { coreKeyBits, serverConfirmationCode, sessionRecordKeyDeriveSalt, saveSessionKey, x3dhIdentity, x3dhData, profileData, serverIdentityVerifying } = resultConc;
            if (!(await esrp.processConfirmationData(sharedSecret, serverConfirmationCode, serverConfirmationData))) {
                logError(new Error("Server confirmation code incorrect."));
                return failure(ErrorStrings.ProcessFailed);
            }
            const { encryptionBaseVector: encryptionBase } = await crypto.deriveDecrypt(coreData, coreKeyBits, "Core Data");
            if (!encryptionBase) {
                return failure(ErrorStrings.ProcessFailed);
            }
            const encryptionBaseVector = await crypto.importRaw(encryptionBase);
            const { serverIdentityVerifyingKey } = (await crypto.deriveDecrypt(serverIdentityVerifying, encryptionBaseVector, `${username} Server Identity Verifying Key`)) ?? {};
            const x3dhManager = await X3DHManager.import(username, x3dhIdentity, x3dhData, encryptionBaseVector);
            const profile: Profile = await x3dhManager?.deriveDecryptVerify(profileData, encryptionBaseVector, `${username} User Profile`);
            if (!profile) {
                return failure(ErrorStrings.ProcessFailed);
            }
            const sessionCrypto = await x3dhManager.createSessionCrypto(clientReference, sharedKeyBits, serverIdentityVerifyingKey);
            const sessionRecordKey = await crypto.deriveHKDF(sharedKeyBits, sessionRecordKeyDeriveSalt, "Session Record", 512);
            const savedSessionData: SavedSessionData = { username, clientReference, sharedKeyBitsBuffer, encryptionBase, sessionRecordKey, userData: { profileData, x3dhIdentity, x3dhData, serverIdentityVerifying }};
            const savingSession = serialize(await crypto.deriveEncrypt(savedSessionData, saveSessionKey, "SavedSession")).toString("base64");
            window.sessionStorage.setItem("SavedSession", savingSession);
            const serverVerifyingKey = await crypto.importKey(serverIdentityVerifyingKey, "ECDSA", "public", false);
            const client = await Client.initiate(baseURL, encryptionBaseVector, sessionRecordKey, username, profile, x3dhManager, sessionCrypto, serverVerifyingKey);
            if (!client) throw new Error("Failed to initiate client.");
            return client;
        }
        catch (err) {
            logError(err);
            return failure(ErrorStrings.ProcessFailed);
        }
    }

    static async userLogOut() {
        window.sessionStorage.removeItem("SavedSession");
        window.localStorage.removeItem("SavedAuth");
        await axInstance.post("/userLogOut", {});
        Client.dispose("logging-out");
    }

    static async terminateCurrentSession(loggingOut?: "logging-out") {
        if (loggingOut) window.sessionStorage.removeItem("SavedSession");
        await Promise.all([navigator.sendBeacon(`${baseURL}/terminateCurrentSession`), Client.dispose(loggingOut)]);
    }

    static async resumeAuthenticatedSession(): Promise<Client | Failure> {
        if (!(await this.isServerReachable())) return failure(ErrorStrings.NoConnectivity);
        try {
            const encryptedSession: EncryptedData = deserialize(fromBase64(window.sessionStorage.getItem("SavedSession") || ""));
            if (!encryptedSession) {
                return failure(ErrorStrings.ProcessFailed);
            }
            const { resumed, saveSessionKeyBase64 } = (await this.get("/resumeAuthenticatedSession"))?.data || {};
            if (!resumed) {
                logError("Couldn't resume");
                return failure(ErrorStrings.ProcessFailed);
            }
            const saveSessionKey = Buffer.from(saveSessionKeyBase64, "base64");
            const { username, clientReference, sharedKeyBitsBuffer, encryptionBase, sessionRecordKey, userData: { profileData, x3dhIdentity, x3dhData, serverIdentityVerifying } }: SavedSessionData = await crypto.deriveDecrypt(encryptedSession, saveSessionKey, "SavedSession");
            if (!username) {
                logError("Couldn't resume");
                return failure(ErrorStrings.ProcessFailed);
            }
            const sharedKeyBits = await crypto.importRaw(sharedKeyBitsBuffer);
            const encryptionBaseVector = await crypto.importRaw(encryptionBase);
            const { serverIdentityVerifyingKey } = (await crypto.deriveDecrypt(serverIdentityVerifying, encryptionBaseVector, `${username} Server Identity Verifying Key`)) ?? {};
            const x3dhManager = await X3DHManager.import(username, x3dhIdentity, x3dhData, encryptionBaseVector);
            const profile: Profile = await x3dhManager?.deriveDecryptVerify(profileData, encryptionBaseVector, `${username} User Profile`);
            if (!profile) {
                return failure(ErrorStrings.ProcessFailed);
            }
            const savedSessionData: SavedSessionData = { username, clientReference, sharedKeyBitsBuffer, encryptionBase, sessionRecordKey, userData: { profileData, x3dhIdentity, x3dhData, serverIdentityVerifying }};
            const savingSession = serialize(await crypto.deriveEncrypt(savedSessionData, saveSessionKey, "SavedSession")).toString("base64");
            window.sessionStorage.setItem("SavedSession", savingSession);
            const sessionCrypto = await x3dhManager.createSessionCrypto(clientReference, sharedKeyBits, serverIdentityVerifyingKey);
            const serverVerifyingKey = await crypto.importKey(serverIdentityVerifyingKey, "ECDSA", "public", false);
            const client = await Client.initiate(baseURL, encryptionBaseVector, sessionRecordKey, username, profile, x3dhManager, sessionCrypto, serverVerifyingKey);
            if (!client) throw new Error("Failed to initiate client.");
            return client;
        }
        catch (err) {
            logError(err);
            return failure(ErrorStrings.ProcessFailed);
        }
    }

    private static async savePassword(username: string, passwordString: string, encryptionBaseVector: Buffer, databaseAuthKeyBuffer: Buffer) {
        const coreKeyBits = getRandomVector(32);
        const authKeyBits = getRandomVector(32);
        const serverKeyBits = getRandomVector(32);
        const coreData = await crypto.deriveEncrypt({ encryptionBaseVector }, coreKeyBits, "Core Data");
        const { clientEphemeralPublic, processAuthChallenge } = await esrp.clientSetupAuthProcess(passwordString);
        const request: SavePasswordRequest = { serverKeyBits, authKeyBits, coreKeyBits, clientEphemeralPublic };
        const result: SavePasswordResponse | Failure = await this.post("savePassword", request);
        if ("reason" in result) {
            logError(result);
            return false;
        }
        const { verifierDerive, verifierEntangled } = result;
        const laterConfirmation = await processAuthChallenge(verifierEntangled, verifierDerive, "later");
        const authData = await crypto.deriveEncrypt({ username, laterConfirmation, databaseAuthKeyBuffer }, authKeyBits, "Auth Data");
        const savedAuth = serialize({ serverKeyBits, authData, coreData }).toString("base64");
        window.localStorage.setItem("SavedAuth", savedAuth);
        return true;
    }

    private static async isPasswordSaved(): Promise<false | "same-ip" | "other-ip" | null> {
        const response = await this.get("/isPasswordSaved");
        if (response?.status !== 200) return null;
        else return response.data.passwordSaved;
    }

    private static async clearSavedPassword() {
        try {
            await axInstance.delete("/clearSavedPassword");
        }
        catch(err) {
            logError(err);
        }
    }

    private static async post(resource: string, data: any) {
        if (!window.navigator.onLine) {
            this.notifyResponseStatus(404);
            return {};
        }
        const payload = serialize(data).toString("base64");
        try {
            const response = await axInstance.post(`/${resource}`, { payload });
            this.notifyResponseStatus(response?.status);
            if (response?.status === 200) return deserialize(fromBase64(response.data.payload));
            else return {};
        }
        catch(err) {
            logError(err);
            this.notifyResponseStatus((err as AxiosError)?.status);
            return {};
        }
    }

    private static async get(resource: string) {
        if (!window.navigator.onLine) {
            this.notifyResponseStatus(404);
            return null;
        }
        try {
            const response = await axInstance.get(resource);
            this.notifyResponseStatus(response?.status);
            return response;
        }
        catch(err) {
            logError(err);
            this.notifyResponseStatus(404);
            return null;
        }
    }

    private static async notifyResponseStatus(status: number | undefined) {
        if (!this.notifyConnectionStatus) return;
        if (status === 200) this.notifyConnectionStatus("Online");
        else if (status === 404) {
            if (await isClientOnline()) this.notifyConnectionStatus("ClientOffline");
            else if (await this.isServerReachable()) this.notifyConnectionStatus("ServerUnreachable");
            else this.notifyConnectionStatus("Online");
        }
    }
}

export async function isClientOnline() {
    if (!window.navigator.onLine) return false;
    try {
        return await isOnline({ timeout: 1000 });
    } catch (err) {
        return false;
    }

}