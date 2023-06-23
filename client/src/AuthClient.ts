import _ from "lodash";
import axios from "axios";
import { SessionCrypto } from "../../shared/sessionCrypto";
import {  X3DHUser } from "./e2e-encryption";
import * as crypto from "../../shared/cryptoOperator";
import { serialize, deserialize } from "../../shared/cryptoOperator";
import * as esrp from "../../shared/ellipticSRP";
import { failure, fromBase64, logError, randomFunctions } from "../../shared/commonFunctions";
import { ErrorStrings, Failure, Username, SignUpRequest, NewUserData, Profile, SignUpChallengeResponse, LogInRequest, LogInChallengeResponse, SavePasswordRequest, SavePasswordResponse, SignUpChallenge, LogInResponse, LogInChallenge, LogInSavedRequest, LogInSavedResponse, LogInPermitted  } from "../../shared/commonTypes";
import Client from "./client";

const { getRandomVector, getRandomString } = randomFunctions();
axios.defaults.withCredentials = true;

type SavedAuthData = Readonly<{
    username: string,
    laterConfirmation: esrp.ClientAuthChallengeLaterResult;
    databaseAuthKeyBuffer: Buffer;
}>;

const PORT = 8080;
const { hostname, protocol } = window.location;
const baseURL = `${protocol}//${hostname}:${PORT}`;
const axInstance = axios.create({ baseURL, maxRedirects: 0 })

export default class AuthClient {

    private constructor() {}

    static async userExists(username: string): Promise<boolean> {
        try {
            const response = await axInstance.get(`/userExists/${username}`);
            if (response?.status === 200) return response.data.exists;
            else return null;
        }
        catch(err) {
            logError(err);
            return null;
        }
    }

    static async userLogInPermitted(username: string): Promise<LogInPermitted> {
        try {
            const response = await axInstance.get(`/userLogInPermitted/${username}`);
            if (response?.status === 200) return response.data;
            else return null;
        }
        catch(err) {
            logError(err);
            return null;
        }
    }

    static async isLoggedIn(): Promise<boolean> {
        try {
            const response = await axInstance.get(`/isLoggedIn`);
            if (response?.status === 200) return response.data.loggedIn;
            else return null;
        }
        catch(err) {
            logError(err);
            return null;
        }
    }

    static async signUp(profile: Profile, password: string, savePassword: boolean): Promise<Client | Failure> {
        try {
            const { username } = profile;
            const passwordString = `${username}#${password}`
            const { verifierPoint, verifierDerive } = await esrp.generateClientRegistration(passwordString);
            const { clientEphemeralPublic, processAuthChallenge } = await esrp.clientSetupAuthProcess(passwordString);
            const [encryptionBaseDerive, encryptionBase] = await esrp.entanglePassword(passwordString);
            const encryptionBaseVector = await crypto.importRaw(encryptionBase);
            const [databaseAuthKeyDerive, databaseAuthKeyBuffer] = await esrp.entanglePassword(passwordString);
            const identitySigningKeypair = await crypto.generateKeyPair("ECDSA");
            const { exportedPublicKey: clientIdentityVerifyingKey, wrappedPrivateKey: clientIdentitySigning } = await crypto.exportSigningKeyPair(identitySigningKeypair, encryptionBaseVector, "Client Identity Signing Key");
            const clientReference = getRandomString(16, "base64");
            const signUpRequest: SignUpRequest = {
                clientReference,
                username,
                verifierPoint,
                clientEphemeralPublic,
                clientIdentityVerifyingKey               
            };
            const resultInit: SignUpChallenge | Failure = await this.post("initiateSignUp", signUpRequest);
            if ("reason" in resultInit) {
                logError(resultInit);
                return resultInit;
            }
            const { serverIdentityVerifyingKey, verifierEntangled } = resultInit;
            const { clientConfirmationCode, sharedKeyBits, confirmServer } = await processAuthChallenge(verifierEntangled, verifierDerive, "now");
            const serverIdentityVerifying = await crypto.deriveEncrypt({ serverIdentityVerifyingKey }, encryptionBaseVector, "Server Identity Verifying Key");
            const x3dhUser = await X3DHUser.new(username, encryptionBaseVector);
            if (!x3dhUser) {
                throw new Error("Failed to create user");
            }
            const keyBundles = await x3dhUser.publishKeyBundles();
            const x3dhInfo = await x3dhUser.exportUser();
            const profileData = await crypto.deriveEncrypt(profile, encryptionBaseVector, "User Profile");
            const newUserData: NewUserData =  { userData: { encryptionBaseDerive, profileData, x3dhInfo, clientIdentitySigning, serverIdentityVerifying }, verifierDerive, databaseAuthKeyDerive, keyBundles };
            const newUserDataSigned = await crypto.deriveSignEncrypt(sharedKeyBits, newUserData, Buffer.alloc(32), "New User Data", identitySigningKeypair.privateKey);
            const concludeSignUp: SignUpChallengeResponse = { clientConfirmationCode, newUserDataSigned, databaseAuthKeyBuffer };
            const resultConc: Pick<LogInResponse, "serverConfirmationCode"> | Failure = await this.post("concludeSignUp", concludeSignUp);
            if ("reason" in resultConc) {
                logError(resultConc);
                return resultConc;
            }
            if (!(await confirmServer(resultConc.serverConfirmationCode))) {
                logError(new Error("Server confirmation code incorrect."))
                return failure(ErrorStrings.ProcessFailed);
            }
            const sessionCrypto = new SessionCrypto(clientReference, sharedKeyBits, identitySigningKeypair.privateKey, await crypto.importKey(serverIdentityVerifyingKey, "ECDSA", "public", false));
            if (savePassword) {
                const savePasswordSuccess = await this.savePassword(username, passwordString, encryptionBase, databaseAuthKeyBuffer);
                console.log(savePasswordSuccess ? "Password saved successfully." : "Failed to save password.");
            }
            return Client.initiate(baseURL, encryptionBaseVector, username, profile, x3dhUser, sessionCrypto);
        }
        catch (err) {
            logError(err);
            return failure(ErrorStrings.ProcessFailed);
        }
    }

    static async logIn(username: string, password: string, savePassword: boolean): Promise<Client | Failure> {
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
            const { clientConfirmationCode, sharedKeyBits, confirmServer } = await processAuthChallenge(verifierEntangled, verifierDerive, "now");
            const databaseAuthKeyBuffer = await esrp.disentanglePasswordToBits(passwordString, databaseAuthKeyDerive);
            const logInChallengeResponse: LogInChallengeResponse = { clientConfirmationCode, databaseAuthKeyBuffer };
            const resultConc: LogInResponse | Failure = await this.post("concludeLogIn", logInChallengeResponse);
            if ("reason" in resultConc) {
                logError(resultConc);
                return resultConc;
            }
            if (!(await confirmServer(resultConc.serverConfirmationCode))) {
                logError(new Error("Server confirmation code incorrect."))
                return failure(ErrorStrings.ProcessFailed);
            }
            const { encryptionBaseDerive, clientIdentitySigning, serverIdentityVerifying, profileData, x3dhInfo } = resultConc;
            const encryptionBase = await esrp.disentanglePasswordToBits(passwordString, encryptionBaseDerive);
            const encryptionBaseVector = await crypto.importRaw(encryptionBase);
            const { serverIdentityVerifyingKey } = (await crypto.deriveDecrypt(serverIdentityVerifying, encryptionBaseVector, "Server Identity Verifying Key")) ?? {};
            const clientIdentitySigningKey = await crypto.deriveUnwrap(encryptionBaseVector, clientIdentitySigning, "ECDSA", "Client Identity Signing Key", false);
            if (!encryptionBaseVector || !serverIdentityVerifyingKey || !clientIdentitySigningKey) {
                return failure(ErrorStrings.ProcessFailed);
            }
            const serverVerifyingKey = await crypto.importKey(serverIdentityVerifyingKey, "ECDSA", "public", false);
            const x3dhUser = await X3DHUser.importUser(x3dhInfo, encryptionBaseVector);
            const profile: Profile = await crypto.deriveDecrypt(profileData, encryptionBaseVector, "User Profile");
            if (!serverVerifyingKey || !x3dhUser || !profile) {
                return failure(ErrorStrings.ProcessFailed);
            }
            const sessionCrypto = new SessionCrypto(clientReference, sharedKeyBits, clientIdentitySigningKey, serverVerifyingKey);
            if (savePassword) {
                const savePasswordSuccess = await this.savePassword(username, passwordString, encryptionBase, databaseAuthKeyBuffer);
                console.log(savePasswordSuccess ? "Password saved successfully." : "Failed to save password.");
            }
            return Client.initiate(baseURL, encryptionBaseVector, username, profile, x3dhUser, sessionCrypto);
        }
        catch (err) {
            logError(err);
            return failure(ErrorStrings.ProcessFailed);
        }
    }

    static async logInSaved(): Promise<Client | Failure> {
        try {
            const { serverKeyBits, authData, coreData } = deserialize(fromBase64(window.localStorage.getItem("SavedAuth") || ""));
            if (!serverKeyBits) {
                logError("Saved details not found");
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
            const sharedKeyBits = await esrp.getSharedKeyBits(sharedSecret);
            const concludeLogInSaved: Username & LogInChallengeResponse = { username, clientConfirmationCode, databaseAuthKeyBuffer };
            const resultConc: LogInSavedResponse | Failure = await this.post("concludeLogInSaved", concludeLogInSaved);
            if ("reason" in resultConc) {
                logError(resultConc);
                return resultConc;
            }
            const { coreKeyBits, serverConfirmationCode, x3dhInfo, profileData, clientIdentitySigning, serverIdentityVerifying } = resultConc;
            if (!(await esrp.processConfirmationData(sharedSecret, serverConfirmationCode, serverConfirmationData))) {
                logError(new Error("Server confirmation code incorrect."));
                return failure(ErrorStrings.ProcessFailed);
            }
            const { encryptionBaseVector: encryptionBase } = await crypto.deriveDecrypt(coreData, coreKeyBits, "Core Data");
            if (!encryptionBase) {
                return failure(ErrorStrings.ProcessFailed);
            }
            const encryptionBaseVector = await crypto.importRaw(encryptionBase);
            const { serverIdentityVerifyingKey } = (await crypto.deriveDecrypt(serverIdentityVerifying, encryptionBaseVector, "Server Identity Verifying Key")) ?? {};
            const clientSigningKey = await crypto.deriveUnwrap(encryptionBaseVector, clientIdentitySigning, "ECDSA", "Client Identity Signing Key", false);
            const serverVerifyingKey = await crypto.importKey(serverIdentityVerifyingKey, "ECDSA", "public", false);
            const x3dhUser = await X3DHUser.importUser(x3dhInfo, encryptionBaseVector);
            const profile: Profile = await crypto.deriveDecrypt(profileData, encryptionBase, "User Profile");
            if (!profile || !x3dhUser) {
                return failure(ErrorStrings.ProcessFailed);
            }
            const sessionCrypto = new SessionCrypto(clientReference, sharedKeyBits, clientSigningKey, serverVerifyingKey);
            return Client.initiate(baseURL, encryptionBaseVector, username, profile, x3dhUser, sessionCrypto);
        }
        catch (err) {
            logError(err);
            return failure(ErrorStrings.ProcessFailed);
        }
    }

    static async userLogOut() {
        window.localStorage.removeItem("SavedAuth");
        await axInstance.post("/userLogOut", {});
        Client.dispose();
    }

    static async terminateCurrentSession() {
        navigator.sendBeacon(`${baseURL}/terminateCurrentSession`);
        Client.dispose();
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

    private static async post(resource: string, data: any) {
        const payload = serialize(data).toString("base64");
        try {
            const response = await axInstance.post(`/${resource}`, { payload });
            if (response?.status === 200) return deserialize(fromBase64(response.data.payload));
            else return {};
        }
        catch(err) {
            logError(err);
            return {};
        }
    }
}