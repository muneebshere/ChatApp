import _ from "lodash";
import * as crypto from "../shared/cryptoOperator";
import { Failure, ErrorStrings, Username, SignUpRequest, SignUpChallenge, SignUpChallengeResponse, NewUserData, LogInRequest, LogInChallenge, UserData, LogInChallengeResponse, LogInSavedRequest, SavePasswordRequest, LogInResponse, LogInSavedResponse, SavePasswordResponse, LogInPermitted, SignUpResponse } from "../shared/commonTypes";
import { failure, logError } from "../shared/commonFunctions";
import MongoHandlerCentral from "./MongoHandler";
import * as esrp from "../shared/ellipticSRP";
import SocketHandler from "./SocketHandler";
import { SessionCrypto } from "../shared/sessionCrypto";

type RunningClientSession = Readonly<{
    username: string,
    ipRep: string,
    clientReference: string,
    sessionReference: string,
    sharedKeyBitsBuffer: Buffer,
    clientIdentityVerifyingKey: Buffer,
    databaseAuthKeyBuffer: Buffer
}>;

type ServerSavedDetails = Readonly<{
    username: string, 
    authKeyBits: Buffer, 
    coreKeyBits: Buffer,
    laterConfirmation: Omit<esrp.ServerAuthChallengeLater, "verifierEntangled">,
}>;

type Temp = Readonly<{
    setAt: number,
    ipRep: string 
}>;

type ChallengeTemp = Temp & Readonly<{
    confirmClient: (confirmationCode: Buffer) => Promise<boolean>, 
    serverConfirmationCode: Buffer,
    sharedKeyBitsBuffer: Buffer,
}>;

type LogInTemp = Temp & Readonly<{ clientReference: string, clientIdentityVerifyingKey: Buffer, userData: UserData }>;

type RegisterChallengeTemp = ChallengeTemp & Omit<SignUpRequest, "clientEphemeralPublic">;

type LogInChallengeTemp = ChallengeTemp & Username & LogInTemp;

type LogInSavedChallengeTemp = Omit<ServerSavedDetails, "authKeyBits"> & LogInTemp;

export default class AuthHandler {
    static #authHandler: AuthHandler;
    readonly #registerChallengeTemp = new Map<string, RegisterChallengeTemp>();
    readonly #logInChallengeTemp = new Map<string, LogInChallengeTemp>();
    readonly #logInSavedTemp = new Map<string, LogInSavedChallengeTemp & { readonly setAt: number }>();
    readonly #serverIdentitySigningKey: CryptoKey;
    readonly #serverIdentityVerifyingKey: Buffer;


    static initiate(serverIdentitySigningKey: CryptoKey, serverIdentityVerifyingKey: Buffer) {
        this.#authHandler = this.#authHandler || new AuthHandler(serverIdentitySigningKey, serverIdentityVerifyingKey);
        return this.#authHandler;
    }

    private constructor(serverIdentitySigningKey: CryptoKey, serverIdentityVerifyingKey: Buffer) {
        this.#serverIdentitySigningKey = serverIdentitySigningKey;
        this.#serverIdentityVerifyingKey = serverIdentityVerifyingKey;
        setInterval(() => {
            const now = Date.now();
            MongoHandlerCentral.refreshRunningClientSessions(SocketHandler.sessionReferences);
            this.#registerChallengeTemp.forEach(({ setAt }, ref, map) => {
                if (now > setAt + 5000) map.delete(ref);
            });
            this.#logInChallengeTemp.forEach(({ setAt }, ref, map) => {
                if (now > setAt + 5000) map.delete(ref);
            });
            this.#logInSavedTemp.forEach(({ setAt }, ref, map) => {
                if (now > setAt + 5000) map.delete(ref);
            });
        }, 1000);
    }

    private async createSocketHandler(session: RunningClientSession, persist: false): Promise<SocketHandler>;
    private async createSocketHandler(session: RunningClientSession, persist: true): Promise<[SocketHandler, Buffer]>;
    private async createSocketHandler(session: RunningClientSession, persist: boolean) {
        const { username, ipRep, clientReference, sessionReference, clientIdentityVerifyingKey, databaseAuthKeyBuffer, sharedKeyBitsBuffer } = session;
        const sharedKeyBits = await crypto.importRaw(sharedKeyBitsBuffer);
        const databaseAuthKey = await crypto.importRaw(databaseAuthKeyBuffer);
        const clientVerifyingKey = await crypto.importKey(clientIdentityVerifyingKey, "ECDSA", "public", false);
        const mongoHandler = await MongoHandlerCentral.instantiateUserHandler(username, databaseAuthKey);
        if (!mongoHandler) return null;
        const sessionCrypto = new SessionCrypto(clientReference, sharedKeyBits, this.#serverIdentitySigningKey, clientVerifyingKey);
        const socketHandler = new SocketHandler(username, sessionReference, ipRep, mongoHandler, sessionCrypto);
        if (socketHandler) {
            if (persist) {
                const salt = crypto.getRandomVector(64);
                const sessionRecordKey = await crypto.deriveHKDF(sharedKeyBits, salt, "Session Record", 512);
                crypto.deriveEncrypt(session, sessionRecordKey, `Session Record: ${sessionReference}`).then((record) => MongoHandlerCentral.createRunningClientSession(sessionReference, record));
                return [socketHandler, salt];
            }
            return socketHandler;
        }
        else return [];
    }

    async restartCrashedSession(sessionReference: string, sessionRecordKey: Buffer) { 
        if (SocketHandler.getUsername(sessionReference)) return true;
        const crashedSession = await MongoHandlerCentral.getRunningClientSession(sessionReference);
        if (!crashedSession) return false;
        const sessionData: RunningClientSession = await crypto.deriveDecrypt(crashedSession, sessionRecordKey, `Session Record: ${sessionReference}`);
        if (!sessionData) return false;
        MongoHandlerCentral.refreshRunningClientSessions([sessionReference]);
        return !!(await this.createSocketHandler(sessionData, false));
    }

    async userExists(username: string): Promise<{ exists: boolean }> {
        const exists = await MongoHandlerCentral.userExists(username);
        return { exists };
    }

    async userLoginPermitted(username: string, ipRep: string): Promise<LogInPermitted> {
        const exists = await MongoHandlerCentral.userExists(username);
        if (!exists) return { login: false };
        const retries = await MongoHandlerCentral.getUserRetries(username, ipRep);
        const { tries, allowsAt } = retries;
        return { login: { tries, allowsAt } }
    }

    async initiateSignUp(ipRep: string, challengeReference: string, request: SignUpRequest): Promise<SignUpChallenge | Failure> {
        const { username, clientReference, clientEphemeralPublic, clientIdentityVerifyingKey, verifierPoint } = request;
        if (await MongoHandlerCentral.userExists(username)) return failure(ErrorStrings.InvalidRequest);
        const { confirmClient, sharedKeyBitsBuffer, serverConfirmationCode, verifierEntangled } = await esrp.serverSetupAuthChallenge(verifierPoint, clientEphemeralPublic, "now");
        this.#registerChallengeTemp.set(challengeReference, { ipRep, clientReference, username, clientIdentityVerifyingKey, serverConfirmationCode, confirmClient, verifierPoint, sharedKeyBitsBuffer, setAt: Date.now() });
        const serverIdentityVerifyingKey = this.#serverIdentityVerifyingKey;
        return { verifierEntangled, serverIdentityVerifyingKey };
    }

    async concludeSignUp(ipRep: string, challengeReference: string, sessionReference: string, response: SignUpChallengeResponse): Promise<SignUpResponse | Failure> {
        const { clientConfirmationCode, newUserDataSigned, databaseAuthKeyBuffer } = response;
        const registerChallenge = this.#registerChallengeTemp.get(challengeReference);
        if (!registerChallenge || registerChallenge.ipRep !== ipRep) return failure(ErrorStrings.InvalidReference);
        const { username, clientReference, clientIdentityVerifyingKey, serverConfirmationCode, confirmClient, sharedKeyBitsBuffer, verifierPoint } = registerChallenge;
        const sharedKeyBits = await crypto.importRaw(sharedKeyBitsBuffer);
        try {
            if (!(await confirmClient(clientConfirmationCode))) return failure(ErrorStrings.IncorrectData);
            const clientVerifyingKey = await crypto.importKey(clientIdentityVerifyingKey, "ECDSA", "public", false);
            const newUserData: NewUserData = await crypto.deriveDecryptVerify(sharedKeyBits, newUserDataSigned, Buffer.alloc(32), "New User Data", clientVerifyingKey);
            if (!newUserData) return failure(ErrorStrings.IncorrectData);
            const databaseAuthKey = await crypto.importRaw(databaseAuthKeyBuffer);
            if (await MongoHandlerCentral.createNewUser({ username, clientIdentityVerifyingKey, verifierPoint, ...newUserData }, databaseAuthKey)) {
                const sessionData = { username, ipRep, clientReference, sessionReference, sharedKeyBitsBuffer, clientIdentityVerifyingKey, databaseAuthKeyBuffer };
                const [socketHandler, sessionRecordKeyDeriveSalt] = await this.createSocketHandler(sessionData, true);
                if (!socketHandler) return failure(ErrorStrings.ProcessFailed);
                console.log(`Saved user: ${username}`);
                return { serverConfirmationCode, sessionRecordKeyDeriveSalt };
            }
            return failure(ErrorStrings.ProcessFailed);
        }
        catch (err) {
            logError(err)
            return failure(ErrorStrings.ProcessFailed, err);
        }
    }

    async initiateLogIn(ipRep: string, challengeReference: string, request: LogInRequest): Promise<LogInChallenge | Failure> {
        const { username, clientReference, clientEphemeralPublic } = request;
        if (!(await MongoHandlerCentral.userExists(username))) return failure(ErrorStrings.InvalidRequest);
        const { tries, allowsAt } = await MongoHandlerCentral.getUserRetries(username, ipRep);
        if (allowsAt && allowsAt > Date.now()) {
            return failure(ErrorStrings.TooManyWrongTries, { tries, allowsAt });
        }
        const { verifierDerive, verifierPoint, databaseAuthKeyDerive, clientIdentityVerifyingKey, userData } = (await MongoHandlerCentral.getLeanUser(username)) ?? {}; 
        if (!verifierDerive) return failure(ErrorStrings.IncorrectData);
        const { confirmClient, sharedKeyBitsBuffer, serverConfirmationCode, verifierEntangled } = await esrp.serverSetupAuthChallenge(verifierPoint, clientEphemeralPublic, "now");
        this.#logInChallengeTemp.set(challengeReference, { ipRep, serverConfirmationCode, confirmClient, sharedKeyBitsBuffer, username, clientReference, clientIdentityVerifyingKey, userData, setAt: Date.now() });
        return { verifierDerive, verifierEntangled, databaseAuthKeyDerive };
    }

    async concludeLogIn(ipRep: string, challengeReference: string, sessionReference: string, response: LogInChallengeResponse): Promise<LogInResponse | Failure> {
        const { clientConfirmationCode, databaseAuthKeyBuffer } = response;
        const logInChallenge = this.#logInChallengeTemp.get(challengeReference);
        if (!logInChallenge || logInChallenge.ipRep !== ipRep) return failure(ErrorStrings.InvalidReference);
        const { confirmClient, serverConfirmationCode, sharedKeyBitsBuffer, username, clientIdentityVerifyingKey, userData, clientReference } = logInChallenge;
        try {
            if (!(await confirmClient(clientConfirmationCode))) {
                let { tries } = await MongoHandlerCentral.getUserRetries(username, ipRep);
                tries ??= 0;
                tries++;
                if (tries >= 5) {
                    const forbidInterval = 1000 * (30 + 15 * (tries - 5));
                    const allowsAt = Date.now() + forbidInterval;
                    await MongoHandlerCentral.updateUserRetries(username, ipRep, allowsAt, tries);
                    return failure(ErrorStrings.TooManyWrongTries, { tries, allowsAt });
                }
                await MongoHandlerCentral.updateUserRetries(username, ipRep, null, tries);
                return failure(ErrorStrings.IncorrectPassword, { tries });   
            }
            else await MongoHandlerCentral.updateUserRetries(username, ipRep, null);
            const status = SocketHandler.getUserStatus(username, ipRep);
            if (status === "ActiveElsewhere") return failure(ErrorStrings.InvalidRequest, "Already Logged In Elsewhere");
            else if (status === "ActiveHere") SocketHandler.disposeUserSessions(username);
            const sessionData = { username, ipRep, clientReference, sessionReference, sharedKeyBitsBuffer, clientIdentityVerifyingKey, databaseAuthKeyBuffer };
            const [socketHandler, sessionRecordKeyDeriveSalt] = await this.createSocketHandler(sessionData, true);
            if (!socketHandler) return failure(ErrorStrings.ProcessFailed);
            console.log(`User logged in: ${username}`);
            return { serverConfirmationCode, sessionRecordKeyDeriveSalt, ...userData };
        }
        catch (err) {
            logError(err)
            return failure(ErrorStrings.ProcessFailed, err);
        }
    }

    async InitiateLogInSaved(ipRep: string, saveToken: string, request: LogInSavedRequest): Promise<(Username & { authKeyBits: Buffer } | Failure)> {
        const { savedAuthDetails } = await MongoHandlerCentral.getSavedAuth(saveToken, ipRep) ?? {};
        if (!savedAuthDetails) return failure(ErrorStrings.InvalidReference);
        const { clientReference, serverKeyBits } = request;
        const { username, authKeyBits, coreKeyBits, laterConfirmation }: ServerSavedDetails = await crypto.deriveDecrypt(savedAuthDetails, serverKeyBits, "Saved Auth") ?? {};
        if (!username) return failure(ErrorStrings.IncorrectData);
        const { clientIdentityVerifyingKey, userData } = (await MongoHandlerCentral.getLeanUser(username)) ?? {};
        this.#logInSavedTemp.set(username, { username, ipRep, clientReference, coreKeyBits, laterConfirmation, clientIdentityVerifyingKey, userData, setAt: Date.now() });
        return { username, authKeyBits };
    }

    async concludeLogInSaved(ipRep: string, sessionReference: string, { username, clientConfirmationCode, databaseAuthKeyBuffer }: LogInChallengeResponse & Username): Promise<LogInSavedResponse | Failure> {
        const logInSaved = this.#logInSavedTemp.get(username)
        if (!logInSaved || logInSaved.ipRep !== ipRep) return failure(ErrorStrings.InvalidReference);
        const { laterConfirmation, coreKeyBits, clientIdentityVerifyingKey, userData, clientReference } = logInSaved;
        const { clientConfirmationData, serverConfirmationCode, sharedSecret } = laterConfirmation;
        try {
            if (!(await esrp.processConfirmationData(sharedSecret, clientConfirmationCode, clientConfirmationData))) return failure(ErrorStrings.IncorrectData);
            const sharedKeyBitsBuffer = esrp.getSharedKeyBitsBuffer(sharedSecret);
            const status = SocketHandler.getUserStatus(username, ipRep);
            if (status === "ActiveElsewhere") return failure(ErrorStrings.InvalidRequest, "Already Logged In Elsewhere");
            else if (status === "ActiveHere") SocketHandler.disposeUserSessions(username);
            const sessionData = { username, ipRep, clientReference, sessionReference, sharedKeyBitsBuffer, clientIdentityVerifyingKey, databaseAuthKeyBuffer };
            const [socketHandler, sessionRecordKeyDeriveSalt] = await this.createSocketHandler(sessionData, true);
            if (!socketHandler) return failure(ErrorStrings.ProcessFailed);
            console.log(`User logged in saved: ${username}`);
            return { serverConfirmationCode, sessionRecordKeyDeriveSalt, coreKeyBits, ..._.omit(userData, "encryptionBaseDerive") };
        }
        catch (err) {
            logError(err)
            return failure(ErrorStrings.ProcessFailed, err);
        }
    }

    async savePassword(username: string, ipRep: string, saveToken: string, request: SavePasswordRequest): Promise<SavePasswordResponse | Failure> {
        console.log("Attempting save password");
        const { serverKeyBits, authKeyBits, coreKeyBits, clientEphemeralPublic } = request;
        const { verifierDerive, verifierPoint } = (await MongoHandlerCentral.getLeanUser(username)) ?? {};
        if (!verifierDerive) return failure(ErrorStrings.IncorrectData);
        const { verifierEntangled, ...laterConfirmation } = await esrp.serverSetupAuthChallenge(verifierPoint, clientEphemeralPublic, "later");
        const serverSavedDetails: ServerSavedDetails = { username, authKeyBits, coreKeyBits, laterConfirmation };
        const savedAuthDetails = await crypto.deriveEncrypt(serverSavedDetails, serverKeyBits, "Saved Auth");
        if (await MongoHandlerCentral.setSavedAuth(saveToken, ipRep, savedAuthDetails)) {
            return { verifierDerive, verifierEntangled };
        }
        else return failure(ErrorStrings.ProcessFailed);
    }
}