import _ from "lodash";
import { match, P } from "ts-pattern";
import axios, { Axios } from "axios";
import { io, Socket } from "socket.io-client";
import { Buffer } from "./node_modules/buffer";
import { stringify } from "safe-stable-stringify";
import { SessionCrypto } from "../../shared/sessionCrypto";
import { ChattingSession, SendingMessage, ViewChatRequest, X3DHUser } from "./e2e-encryption";
import * as crypto from "../../shared/cryptoOperator";
import { serialize, deserialize } from "../../shared/cryptoOperator";
import * as esrp from "../../shared/ellipticSRP";
import { ErrorStrings, Failure, Username, UserEncryptedData, PublishKeyBundlesRequest, RequestKeyBundleResponse, SocketClientSideEvents, randomFunctions, failure, PasswordEncryptedData, MessageHeader, ChatRequestHeader, StoredMessage, ChatData, DisplayMessage, Contact, ReplyingToInfo, SocketClientSideEventsKey, SocketServerSideEventsKey, SocketServerSideEvents, SocketClientRequestParameters, SocketClientRequestReturn, RegisterNewUserRequest, RegisterNewUserChallenge, NewUserData, Profile, RegisterNewUserChallengeResponse, LogInRequest, LogInChallenge, LogInChallengeResponse, UserData, DeliveryInfo  } from "../../shared/commonTypes";
import { DateTime } from "luxon";

const { getRandomVector, getRandomString } = randomFunctions();
axios.defaults.withCredentials = true;

export enum ClientEvent {
    Disconnected,
    Connecting,
    Reconnecting,
    FailedToConnect,
    Connected,
    ServerUnavailable,
    SigningIn,
    FailedSignIn,
    ReAuthenticating,
    FailedReAuthentication,
    CreatingNewUser,
    FailedCreateNewUser,
    CreatedNewUser,
    SignedIn,
    SigningOut,
    SignedOut
}

type ClientChatInterface = Readonly<{
    SendMessage: (data: MessageHeader, timeout?: number) => Promise<Failure>,
    GetUnprocessedMessages: (timeout?: number) => Promise<MessageHeader[] | Failure>,
    GetMessagesByNumber: (data: { limit: number, olderThan?: number }, timeout?: number) => Promise<StoredMessage[] | Failure>,
    GetMessagesUptoTimestamp: (data: { newerThan: number, olderThan?: number }, timeout?: number) => Promise<StoredMessage[] | Failure>,
    GetMessagesUptoId: (data: { messageId: string, olderThan?: number }, timeout?: number) => Promise<StoredMessage[] | Failure>,
    GetMessageById: (data: { messageId: string }, timeout?: number) => Promise<StoredMessage | Failure>,
    StoreMessage: (data: Omit<StoredMessage, "sessionId">, timeout?: number) => Promise<Failure>,
    MessageProcessed: (data: { messageId: string }, timeout?: number) => Promise<Failure>,
    UpdateChat: (data: Omit<Partial<ChatData> & Omit<ChatData, "chatDetails" | "exportedChattingSession">, "sessionId">, timeout?: number) => Promise<Failure>
}>;

type ClientChatRequestInterface = Readonly<{
    rejectRequest: (otherUser: string, sessionId: string, oneTimeKeyId: string) => Promise<boolean>,
    respondToRequest: (request: ChatRequestHeader, respondingAt: number) => Promise<boolean>
}>;

type SavedAuthData = Readonly<{
    username: string,
    laterConfirmation: esrp.ClientAuthChallengeLaterResult;
}>;

type SavedCoreData = Readonly<{

}>;

type RequestMap = Readonly<{
    [E in SocketClientSideEventsKey]: (arg: SocketClientRequestParameters[E], timeout?: number) => Promise<SocketClientRequestReturn[E] | Failure>
}>

function SocketHandler(socket: () => Socket, sessionCrypto: () => SessionCrypto, currentFileHash: Promise<string>, isConnected: () => boolean): RequestMap {

    async function request(event: SocketClientSideEventsKey, data: any, timeout = 0): Promise<any | Failure> {
        if (!isConnected()) {
            return {};
        }
        let { fileHash, payload } = await new Promise(async (resolve: (result: any) => void) => {
            socket().emit(event, (await sessionCrypto().signEncryptToBase64(data, event)),
                async (response: string) => resolve(response ? await sessionCrypto().decryptVerifyFromBase64(response, event) : {}));
            if (timeout > 0) {
                window.setTimeout(() => resolve({}), timeout);
            }
        })
        if (fileHash !== await currentFileHash) {
            window.history.go();
            return {};
        } else return payload;
    }

    function makeRequest(event: SocketClientSideEventsKey) {
        return (data: any, timeout = 0) => request(event, data, timeout);
    }

    const requestMap: any = {};
    let event: SocketClientSideEventsKey;
    for (event in SocketClientSideEvents) {
        requestMap[event] = makeRequest(event);
    }
    return requestMap as RequestMap;
}
export class Client {
    private readonly responseMap: Map<SocketServerSideEventsKey, any> = new Map([
        [SocketServerSideEvents.RoomRequested, this.roomRequested] as [SocketServerSideEventsKey, any],
        [SocketServerSideEvents.MessageReceived, this.messageReceived],
        [SocketServerSideEvents.ChatRequestReceived, this.chatRequestReceived]
    ]);
    private readonly url: string;
    private readonly axInstance: Axios;
    private notifyClientEvent: (clientEvent: ClientEvent) => void;
    private notifyChange: () => void;
    private connecting = false;
    private retryingConnect = false;
    private serverUnavailable = false;
    private reportDone: (arg0: any) => void = undefined;
    #socket: Socket;
    #profile: Profile;
    #username: string;
    #x3dhUser: X3DHUser;
    #sessionReference: string;
    #sessionCrypto: SessionCrypto
    #socketHandler: RequestMap;
    #encryptionBaseVector: CryptoKey;
    #fileHash: Promise<string>;
    private readonly chatList: string[] = [];
    private readonly chatSessionIdsList = new Map<string, Chat | ChatRequest | AwaitedRequest>();
    private readonly chatUsernamesList = new Map<string, Chat | ChatRequest | AwaitedRequest>();

    private readonly chatInterface: (sessionId: string) => ClientChatInterface = (sessionId) => ({
        SendMessage: (data, timeout = 0) => {
            return this.#socketHandler.SendMessage(data, timeout);
        },
        GetUnprocessedMessages: (timeout = 0) => {
            return this.#socketHandler.GetUnprocessedMessages({ sessionId }, timeout);
        },
        GetMessagesByNumber: (data, timeout = 0) => {
            return this.#socketHandler.GetMessagesByNumber({ sessionId, ...data }, timeout);
        },
        GetMessagesUptoTimestamp: (data, timeout = 0) => {
            return this.#socketHandler.GetMessagesUptoTimestamp({ sessionId, ...data }, timeout);
        },
        GetMessagesUptoId: (data, timeout = 0) => {
            return this.#socketHandler.GetMessagesUptoId({ sessionId, ...data }, timeout);
        },
        GetMessageById: (data, timeout = 0) => {
            return this.#socketHandler.GetMessageById({ sessionId, ...data }, timeout);
        },
        StoreMessage: (data, timeout = 0) => {
            return this.#socketHandler.StoreMessage({ sessionId, ...data }, timeout);
        },
        MessageProcessed: (data, timeout?: number) => {
            return this.#socketHandler.MessageProcessed({ sessionId, ...data }, timeout);
        },
        UpdateChat: (data, timeout = 0) => {
            return this.#socketHandler.UpdateChat({ sessionId, ...data }, timeout);
        }
    })

    private addChat(chat: Chat | ChatRequest | AwaitedRequest) {
        this.chatSessionIdsList.set(chat.sessionId, chat);
        this.chatUsernamesList.set(chat.otherUser, chat);
        this.chatList.push(chat.otherUser);
        this.notifyChange?.();
    }

    private removeChat(key: string, keyType: "username" | "sessionId") {
        const chat = keyType === "username" ? this.chatUsernamesList.get(key) : this.chatSessionIdsList.get(key);
        this.chatSessionIdsList.delete(chat.sessionId);
        this.chatUsernamesList.delete(chat.otherUser);
        _.remove(this.chatList, ([user, _]) => user === chat.otherUser);
        if (chat.type === "Chat") {
            chat.disconnectRoom();
        }
        this.notifyChange?.();
    }

    public getChatByUser(otherUser: string): Chat | ChatRequest | AwaitedRequest {
        return this.chatUsernamesList.get(otherUser);
    }

    public getChatDetailsByUser(otherUser: string): { displayName?: string, contactName?: string, profilePicture?: string, lastActive: number } {
        const chat = this.chatUsernamesList.get(otherUser);
        if (!chat) return null;
        const { lastActive } = chat;
        if ("contactDetails" in chat) {
            const { contactDetails: { displayName, profilePicture, contactName } } = chat;
            return { displayName, contactName, profilePicture, lastActive };
        }
        else {
            return { displayName: otherUser, lastActive };
        }
    }

    public get chatsList() {
        return _.orderBy(this.chatList, [(chat) => this.getChatByUser(chat).lastActive], ["desc"]);
    }

    public get username(): string {
        return this.#username;
    }

    public get profile(): Profile {
        return { ...this.#profile };
    }

    public get isConnected(): boolean {
        return this.#socket?.connected ?? false;
    }

    public get isSignedIn(): boolean {
        return !!this.#username;
    }

    constructor(url: string) {
        this.url = url;
        this.axInstance = axios.create({ baseURL: `${this.url}/`, maxRedirects: 0 });
        this.#fileHash = this.calculateFileHash();
    }

    subscribeStatusChange(notifyCallback?: (status: ClientEvent) => void) {
        if (notifyCallback) this.notifyClientEvent = notifyCallback;
    }

    subscribeChange(notifyCallback?: () => void) {
        if (notifyCallback) this.notifyChange = notifyCallback;
    }

    private async calculateFileHash() {
        const response = await fetch("./main.js");
        const fileBuffer = await response.arrayBuffer();
        return crypto.digest("SHA-256", fileBuffer);
    }

    async establishSession() {
        if (!this.isConnected) {
            this.notifyClientEvent?.(ClientEvent.Connecting);
            this.connecting = true;
            const { privateKey, publicKey } = await crypto.generateKeyPair("ECDH");
            const { privateKey: signingKey, publicKey: verifyingKey } = await crypto.generateKeyPair("ECDSA");
            const sessionReference = this.#sessionReference ?? getRandomString(15, "base64");
            const publicDHKey = (await crypto.exportKey(publicKey)).toString("base64");
            const publicVerifyingKey = (await crypto.exportKey(verifyingKey)).toString("base64");
            const { sessionId, serverPublicKey, verifyingKey: serverVerifying } = (await this.axInstance.post("/registerKeys", { sessionReference, publicDHKey, publicVerifyingKey }).catch(() => null))?.data || {};
            if (!serverPublicKey) {
                this.reportDone?.(null);
                return;
            }
            console.log(`Keys registered from url ${this.url} with sessionReference ${sessionReference} and sessionID ${sessionId}`);
            const serverVerifyingKey = await crypto.importKey(fromBase64(serverVerifying), "ECDSA", "public", true);
            const serverPublicKeyImported = await crypto.importKey(fromBase64(serverPublicKey), "ECDH", "public", true);
            const sessionKeyBits = await crypto.deriveSymmetricBitsKey(privateKey, serverPublicKeyImported, 512);
            const fileHash = await this.#fileHash;
            const sessionSigned = await crypto.sign(fromBase64(sessionReference), signingKey);
            const auth = { sessionReference, sessionSigned, fileHash };
            this.#socket = io(this.url, { auth, withCredentials: true });
            this.#socket.on("disconnect", this.retryConnect.bind(this));
            let nevermind = false;
            let timeout: number = null;
            const success = await new Promise<boolean>((resolve) => {
                this.#socket.once(SocketServerSideEvents.CompleteHandshake, (ref, latestFileHash, respond) => {
                    const finalize = (complete: boolean) => {
                        respond(complete);
                        resolve(complete);
                    }
                    try {
                        if (latestFileHash !== fileHash) {
                            console.log("Script file outdated.");
                            window.history.go();
                            finalize(false);
                            return;
                        }
                        if (nevermind) {
                            console.log("Nevermind");
                            console.log(`Connected with session reference: ${sessionReference} and socketId: ${this.#socket.id}`);
                            finalize(false);
                            return;
                        }
                        if (ref !== sessionReference) {
                            this.serverUnavailable = !ref;
                            finalize(false);
                            return;
                        }
                        this.#sessionReference = sessionReference;
                        this.#sessionCrypto = new SessionCrypto(sessionReference, sessionKeyBits, signingKey, serverVerifyingKey);
                        this.#socketHandler = SocketHandler(() => this.#socket, () => this.#sessionCrypto, this.#fileHash, () => this.isConnected);
                        console.log(`Connected with session reference: ${sessionReference} and socketId: ${this.#socket.id}`);
                        if (this.#username) {
                            this.notifyClientEvent?.(ClientEvent.SignedOut);
                            this.#profile = null;
                            this.#username = null;
                            this.#x3dhUser = null;
                        }
                        finalize(true);
                    }
                    catch (err) {
                        logError(err);
                        finalize(false);
                    }
                });
                timeout = window.setTimeout(() => resolve(false), 15000);
                this.#socket.io.on("error", (error) => {
                    logError(error);
                    if ((error as any).type === "TransportError") {
                        this.serverUnavailable = true;
                        this.notifyClientEvent?.(ClientEvent.ServerUnavailable);
                        console.log("Server unavailable.");
                        resolve(false);
                    }
                });
                console.log(`Connecting with session reference: ${sessionReference} and socketId: ${this.#socket.id}`);
                this.#socket.connect();
            });
            nevermind = true;
            this.connecting = false;
            window.clearTimeout(timeout);
            console.log(success && this.isConnected ? "Secure session established." : "Failed to establish secure session.");
            if (this.serverUnavailable) {
            }
            this.notifyClientEvent?.(this.isConnected ? ClientEvent.Connected : ClientEvent.FailedToConnect);
            if (!success || !this.isConnected) {
                this.#socket?.offAny?.();
                this.#socket?.disconnect?.();
                this.#socket = null;
                this.retryConnect("");
            }
            else {
                for (const [event, response] of this.responseMap.entries()) {
                    this.#socket.on(event, async (data: string, respond) => await this.respond(event, data, response.bind(this), respond));
                }
            }
            this.reportDone?.(null);
        }
    }

    private async retryConnect(reason: String) {
        if (this.serverUnavailable || !window.navigator.onLine) return;
        if (this.retryingConnect) return;
        this.#socket?.offAny?.();
        this.#socket?.disconnect?.();
        this.#socket = null;
        this.notifyClientEvent?.(ClientEvent.Disconnected);
        if (reason === "io client disconnect") return;
        this.retryingConnect = true;
        while (!this.isConnected && !this.serverUnavailable || window.navigator.onLine) {
            const wait = new Promise((resolve, _) => {
                this.reportDone = resolve;
                window.setTimeout(() => resolve(null), 10000);
            });
            if (!this.connecting) {
                console.log("Retrying connect");
                this.notifyClientEvent?.(ClientEvent.Reconnecting);
                this.establishSession();
            }
            await wait;
            this.reportDone = undefined;
        }
        this.retryingConnect = false;
    }

    async checkUsernameExists(username: string) {
        const result = await this.#socketHandler.UsernameExists({ username });
        if ("reason" in result) {
            throw "Can't determine if username exists.";
        }
        return result.exists;
    }

    async userLogInPermitted(username: string): Promise<{ tries: number, allowsAt: number }> {
        const result = await this.#socketHandler.UserLoginPermitted({ username });
        if ("reason" in result) {
            throw "Can't determine if username login is permitted.";
        }
        return result;
    }

    async constructNewUser(profile: Profile, passwordString: string, encryptionBaseVector: Buffer, clientIdentitySigningKey: PasswordEncryptedData, serverIdentityVerifyingKey: PasswordEncryptedData): Promise<NewUserData> {
        const { username } = profile;
        this.#encryptionBaseVector = await crypto.importRaw(encryptionBaseVector);
        const encryptionBase = await this.passwordEncrypt(passwordString, { encryptionBaseVector }, "Encryption Base");
        const x3dhUser = await X3DHUser.new(username, this.#encryptionBaseVector);
        if (!x3dhUser) {
            this.notifyClientEvent?.(ClientEvent.FailedCreateNewUser);
            throw new Error("Failed to create user");
        }
        const keyBundles = await x3dhUser.publishKeyBundles();
        const x3dhInfo = await x3dhUser.exportUser();
        const profileData = await crypto.deriveEncrypt(profile, this.#encryptionBaseVector, "User Profile");
        this.#x3dhUser = x3dhUser;
        return { profileData, encryptionBase, x3dhInfo, keyBundles, clientIdentitySigningKey, serverIdentityVerifyingKey };
    }

    async signUp(profile: Profile, password: string, savePassword: boolean) {
        if (!this.isConnected) return failure(ErrorStrings.NoConnectivity);
        this.notifyClientEvent?.(ClientEvent.CreatingNewUser);
        try {
            const { username } = profile;
            const passwordString = `${username}#${password}`
            const { verifierSalt, verifierPointHex } = esrp.generateClientRegistration(passwordString);
            const { clientEphemeralPublicHex, processAuthChallenge } = await esrp.clientSetupAuthProcess(passwordString);
            const [identityMasterKeyBits, pInfo] = await crypto.deriveMasterKeyBits(passwordString);
            const hSalt = crypto.getRandomVector(32);
            const identitySigningKeypair = await crypto.generateKeyPair("ECDSA");
            const { exportedPublicKey: clientIdentityVerifyingKey, wrappedPrivateKey: ciphertext } = await crypto.exportSigningKeyPair(identitySigningKeypair, identityMasterKeyBits, hSalt, "Client Identity Signing Key");
            const clientIdentitySigningKey: PasswordEncryptedData = { ciphertext, hSalt, ...pInfo };
            const registerNewUserRequest: RegisterNewUserRequest = {
                username,
                verifierSalt, 
                verifierPointHex,
                clientEphemeralPublicHex,
                clientIdentityVerifyingKey                
            };
            const resultInit = await this.#socketHandler.InitiateRegisterNewUser(registerNewUserRequest);
            if ("reason" in resultInit) {
                this.notifyClientEvent?.(ClientEvent.FailedCreateNewUser);
                logError(resultInit);
                return resultInit;
            }
            const { challengeReference, serverConfirmationCode, serverIdentityVerifyingKey, verifierEntangledHex } = resultInit;
            const { clientConfirmationCode, sharedKeyBits, confirmServer } = await processAuthChallenge(verifierSalt, verifierEntangledHex, "now");
            const serverVerifyingKey = await this.passwordEncrypt(passwordString, { serverIdentityVerifyingKey }, "Server Verifying Key");
            const encryptionBaseVector = getRandomVector(64);
            const newUserData = await this.constructNewUser(profile, passwordString, encryptionBaseVector, clientIdentitySigningKey, serverVerifyingKey);
            const newUserDataSigned = await crypto.deriveSignEncrypt(sharedKeyBits, newUserData, Buffer.alloc(32), "New User Data", identitySigningKeypair.privateKey);
            const concludeRegisterNewUser: RegisterNewUserChallengeResponse = { challengeReference, clientConfirmationCode, newUserDataSigned };
            const resultConc = await this.#socketHandler.ConcludeRegisterNewUser(concludeRegisterNewUser);
            if (resultConc?.reason) {
                this.#encryptionBaseVector = null;
                this.#x3dhUser = null;
                this.notifyClientEvent?.(ClientEvent.FailedCreateNewUser);
                logError(resultConc);
                return resultConc;
            }
            if (!(await confirmServer(serverConfirmationCode))) {
                this.notifyClientEvent?.(ClientEvent.FailedCreateNewUser);
                logError(new Error("Server confirmation code incorrect."))
                return failure(ErrorStrings.ProcessFailed);
            }
            this.#sessionCrypto = new SessionCrypto(this.#sessionReference, sharedKeyBits, identitySigningKeypair.privateKey, await crypto.importKey(serverIdentityVerifyingKey, "ECDSA", "public", false));
            const switched = await new Promise<boolean>((resolve) => {
                this.#socket?.emit("SwitchSessionCrypto", this.#sessionReference, (response: boolean) => resolve(response));
                setTimeout(() => resolve(false), 2000);
            });
            if (!switched) {
                this.#sessionCrypto = null;
                this.#encryptionBaseVector = null;
                this.notifyClientEvent?.(ClientEvent.FailedCreateNewUser);
                return failure(ErrorStrings.ProcessFailed);
            }
            this.#username = username;
            this.#profile = profile;
            this.notifyClientEvent?.(ClientEvent.CreatedNewUser);
            this.notifyClientEvent?.(ClientEvent.SignedIn);
            if (savePassword) {
                const exportedIdentitySigningKey = await crypto.exportKey(identitySigningKeypair.privateKey);
                await this.savePassword(username, passwordString, encryptionBaseVector, exportedIdentitySigningKey, serverIdentityVerifyingKey);
            }
            return { reason: null };
        }
        catch (err) {
            logError(err);
            this.notifyClientEvent?.(ClientEvent.FailedCreateNewUser);
            return failure(ErrorStrings.ProcessFailed);
        }
    }

    async logIn(username: string, password: string, savePassword: boolean) {
        if (!this.isConnected) return failure(ErrorStrings.NoConnectivity);
        if (this.username) return failure(ErrorStrings.InvalidRequest);
        try {
            const passwordString = `${username}#${password}`;
            const { clientEphemeralPublicHex, processAuthChallenge } = await esrp.clientSetupAuthProcess(passwordString);
            const logInRequest: LogInRequest = { username, clientEphemeralPublicHex };
            const resultInit = await this.#socketHandler.InitiateLogIn(logInRequest);
            if ("reason" in resultInit) {
                this.notifyClientEvent?.(ClientEvent.FailedSignIn);
                logError(resultInit);
                return resultInit;
            }
            const { challengeReference, serverConfirmationCode, verifierEntangledHex, verifierSalt } = resultInit;
            const { clientConfirmationCode, sharedKeyBits, confirmServer } = await processAuthChallenge(verifierSalt, verifierEntangledHex, "now");
            const logInChallengeResponse: LogInChallengeResponse = { challengeReference, clientConfirmationCode };
            const resultConc = await this.#socketHandler.ConcludeLogIn(logInChallengeResponse);
            if ("reason" in resultConc) {
                this.notifyClientEvent?.(ClientEvent.FailedSignIn);
                logError(resultConc);
                return resultConc;
            }
            const { clientIdentitySigningKey: { ciphertext, hSalt, ...pInfo }, encryptionBase, profileData, serverIdentityVerifyingKey: serverIdentityVerifying, x3dhInfo } = resultConc;
            const { encryptionBaseVector } = (await this.passwordDecrypt(passwordString, encryptionBase, "Encryption Base")) ?? {};
            const { serverIdentityVerifyingKey } = (await this.passwordDecrypt(passwordString, serverIdentityVerifying, "Server Verifying Key")) ?? {};
            const identityMasterKeyBits = await crypto.deriveMasterKeyBits(passwordString, pInfo);
            const clientIdentitySigningKey = await crypto.deriveUnwrap(identityMasterKeyBits, ciphertext, hSalt, "ECDSA", "Client Identity Signing Key", false);
            if (!encryptionBaseVector || !serverIdentityVerifyingKey || !clientIdentitySigningKey) {
                this.notifyClientEvent?.(ClientEvent.FailedSignIn);
                return failure(ErrorStrings.ProcessFailed);
            }
            const serverVerifyingKey = await crypto.importKey(serverIdentityVerifyingKey, "ECDSA", "public", false);
            const x3dhUser = await X3DHUser.importUser(x3dhInfo, encryptionBaseVector);
            const profile: Profile = await crypto.deriveDecrypt(profileData, encryptionBaseVector, "User Profile");
            if (!serverVerifyingKey || !x3dhUser || !profile) {
                this.notifyClientEvent?.(ClientEvent.FailedSignIn);
                return failure(ErrorStrings.ProcessFailed);
            }
            if (!(await confirmServer(serverConfirmationCode))) {
                this.#sessionCrypto = null;
                this.#encryptionBaseVector = null;
                this.notifyClientEvent?.(ClientEvent.FailedSignIn);
                logError(new Error("Server confirmation code incorrect."));
                return failure(ErrorStrings.ProcessFailed);
            }
            this.#encryptionBaseVector = encryptionBaseVector;
            this.#sessionCrypto = new SessionCrypto(this.#sessionReference, sharedKeyBits, clientIdentitySigningKey, serverVerifyingKey);
            const switched = await new Promise<boolean>((resolve) => {
                this.#socket?.emit("SwitchSessionCrypto", this.#sessionReference, (response: boolean) => resolve(response));
                setTimeout(() => resolve(false), 2000);
            });
            if (!switched) {
                this.#sessionCrypto = null;
                this.#encryptionBaseVector = null;
                this.notifyClientEvent?.(ClientEvent.FailedSignIn);
                return failure(ErrorStrings.ProcessFailed);
            }
            this.#username = username;
            this.#profile = profile;
            this.#x3dhUser = x3dhUser;
            if (savePassword) {
                const exportedIdentitySigningKey = await crypto.exportKey(await crypto.deriveUnwrap(identityMasterKeyBits, ciphertext, hSalt, "ECDSA", "Client Identity Signing Key", true));
                await this.savePassword(username, passwordString, encryptionBaseVector, exportedIdentitySigningKey, serverIdentityVerifyingKey);
            }
            await this.loadUser();
            this.notifyClientEvent?.(ClientEvent.SignedIn);
            return { reason: null };
        }
        catch (err) {
            logError(err);
            this.notifyClientEvent?.(ClientEvent.FailedSignIn);
            return failure(ErrorStrings.ProcessFailed);
        }
    }

    async logInSaved() {
        if (!this.isConnected) return failure(ErrorStrings.NoConnectivity);
        if (this.username) return failure(ErrorStrings.InvalidRequest);
        try {
            const { serverKeyBits, authData, coreData } = deserialize(Buffer.from(window.localStorage.getItem("SavedAuth") || "", "base64"));
            if (!serverKeyBits) {
                this.notifyClientEvent?.(ClientEvent.FailedSignIn);
                logError("Saved details not found");
                return failure(ErrorStrings.ProcessFailed);
            };
            const resultInit = await this.#socketHandler.InitiateLogInSaved({ serverKeyBits });
            if ("reason" in resultInit) {
                this.notifyClientEvent?.(ClientEvent.FailedSignIn);
                logError(resultInit);
                return resultInit;
            }
            const { authKeyBits } = resultInit;
            const { username, laterConfirmation }: SavedAuthData = await crypto.deriveDecrypt(authData, authKeyBits, "Auth Data");
            const { sharedSecret, clientConfirmationCode, serverConfirmationData } = laterConfirmation;
            const sharedKeyBits = await esrp.getSharedKeyBits(sharedSecret);
            const resultConc = await this.#socketHandler.ConcludeLogInSaved({ username, clientConfirmationCode });
            if ("reason" in resultConc) {
                this.notifyClientEvent?.(ClientEvent.FailedSignIn);
                logError(resultConc);
                return resultConc;
            }
            const { coreKeyBits, serverConfirmationCode, userData: { x3dhInfo, profileData } } = resultConc;
            if (!(await esrp.processConfirmationData(sharedSecret, serverConfirmationCode, serverConfirmationData))) {
                this.notifyClientEvent?.(ClientEvent.FailedSignIn);
                logError(new Error("Server confirmation code incorrect."));
                return failure(ErrorStrings.ProcessFailed);
            }
            const { encryptionBaseVector, clientIdentitySigningKey, serverIdentityVerifyingKey } = await crypto.deriveDecrypt(coreData, coreKeyBits, "Core Data");
            if (!encryptionBaseVector || !serverIdentityVerifyingKey || !clientIdentitySigningKey) {
                this.notifyClientEvent?.(ClientEvent.FailedSignIn);
                return failure(ErrorStrings.ProcessFailed);
            }
            const serverVerifyingKey = await crypto.importKey(serverIdentityVerifyingKey, "ECDSA", "public", false);
            const clientSigningKey = await crypto.importKey(clientIdentitySigningKey, "ECDSA", "private", false);
            this.#encryptionBaseVector = await crypto.importRaw(encryptionBaseVector);
            const x3dhUser = await X3DHUser.importUser(x3dhInfo, encryptionBaseVector);
            const profile: Profile = await crypto.deriveDecrypt(profileData, encryptionBaseVector, "User Profile");
            if (!profile || !x3dhUser) {
                this.notifyClientEvent?.(ClientEvent.FailedSignIn);
                return failure(ErrorStrings.ProcessFailed);
            }
            this.#sessionCrypto = new SessionCrypto(this.#sessionReference, sharedKeyBits, clientSigningKey, serverVerifyingKey);
            const switched = await new Promise<boolean>((resolve) => {
                this.#socket?.emit("SwitchSessionCrypto", this.#sessionReference, (response: boolean) => resolve(response));
                setTimeout(() => resolve(false), 2000);
            });
            if (switched) {
                this.#username = username;
                this.#profile = profile;
                this.#x3dhUser = x3dhUser;
                await this.loadUser();
                this.notifyClientEvent?.(ClientEvent.SignedIn);
                return { reason: null };
            }
            else {
                this.#sessionCrypto = null;
                this.#encryptionBaseVector = null;
                this.notifyClientEvent?.(ClientEvent.FailedSignIn);
                return failure(ErrorStrings.ProcessFailed);
            }
        }
        catch (err) {
            logError(err);
            this.notifyClientEvent?.(ClientEvent.FailedSignIn);
            return failure(ErrorStrings.ProcessFailed);
        }
    }

    async loadUser() {
        for (const { sessionId, messageId, timestamp, otherUser, text } of this.#x3dhUser.pendingChatRequests) {
            const awaited = AwaitedRequest(otherUser, sessionId, messageId, timestamp, text );
            this.addChat(awaited);
            const result = await this.#socketHandler.GetUnprocessedMessages({ sessionId });
            if ("reason" in result) {
                logError(result.reason);
                return;
            }
            const firstResponse = _.orderBy(result, ["timestamp"], ["asc"])[0];
            await this.receiveRequestResponse(firstResponse);
        }
        await this.loadChats();
        await this.loadRequests();
    }

    async sendChatRequest(otherUser: string, firstMessage: string, madeAt: number): Promise<Failure> {
        if (!this.isConnected) return failure(ErrorStrings.NoConnectivity);
        if (!(await this.checkUsernameExists(otherUser))) return failure(ErrorStrings.InvalidRequest);
        const keyBundleResponse = await this.#socketHandler.RequestKeyBundle({ username: otherUser });
        if ("reason" in keyBundleResponse) {
            logError(keyBundleResponse);
            return keyBundleResponse;
        }
        const { keyBundle } = keyBundleResponse;
        const { profile } = this;
        const messageId = getRandomString(15, "hex");
        const result = await this.#x3dhUser.generateChatRequest(keyBundle, messageId, firstMessage, madeAt, profile, async (chatRequest) => {
            const result = await this.#socketHandler.SendChatRequest(chatRequest);
            if (result.reason) {
                logError(result);
                return false;
            }
            return true;
        });
        if (typeof result === "string") {
            logError(result);
            return failure(ErrorStrings.ProcessFailed, result);
        }
        const [{ sessionId, timestamp }, x3dhInfo] = result;
        const { reason } = await this.#socketHandler.UpdateX3DHUser({ x3dhInfo, username: this.username });
        if (reason) {
            logError(reason);
            return failure(ErrorStrings.ProcessFailed);
        }
        this.addChat(AwaitedRequest(otherUser, sessionId, messageId, timestamp, firstMessage));
        return { reason: null };
    }

    async userLogOut(): Promise<Failure> {
        if (!this.#username && !this.isConnected) return;
        this.notifyClientEvent?.(ClientEvent.SigningOut);
        const username = this.#username;
        this.#username = null;
        this.#x3dhUser = null;
        this.#encryptionBaseVector = null;
        await this.#socketHandler.LogOut({ username });
        this.notifyClientEvent?.(ClientEvent.SignedOut);
        await this.retryConnect("");
    }

    async terminateCurrentSession(end = true) {
        await this.#socketHandler.TerminateCurrentSession([]);
        console.log(`Terminating session: reference #${this.#sessionReference}`);
        this.#username = null;
        this.#x3dhUser = null;
        this.#sessionReference = null;
        this.#socketHandler = null;
        if (!end) {
            await this.retryConnect("");
        }
    }

    private async passwordEncrypt(passwordString: string, data: any, purpose: string): Promise<PasswordEncryptedData> {
        const [masterKeyBits, pInfo] = await crypto.deriveMasterKeyBits(`${passwordString}`);
        const hSalt = getRandomVector(48);
        const encrypted = await crypto.deriveSignEncrypt(masterKeyBits, data, hSalt, purpose);
        return { ...encrypted, ...pInfo, hSalt };
    }

    private async passwordDecrypt(passwordString: string, data: PasswordEncryptedData, purpose: string): Promise<any> {
        const { ciphertext, hSalt, ...pInfo } = data;
        const masterKeyBits = await crypto.deriveMasterKeyBits(`${passwordString}`, pInfo);
        return await crypto.deriveDecryptVerify(masterKeyBits, { ciphertext }, hSalt, purpose);
    }

    private async savePassword(username: string, passwordString: string, encryptionBaseVector: Buffer, clientIdentitySigningKey: Buffer, serverIdentityVerifyingKey: Buffer) {
        const coreKeyBits = getRandomVector(32);
        const authKeyBits = getRandomVector(32);
        const serverKeyBits = getRandomVector(32);
        const coreKeyBitsBase64 = coreKeyBits.toString("base64");
        const authKeyBitsBase64 = authKeyBits.toString("base64");
        const serverKeyBitsBase64 = serverKeyBits.toString("base64");
        const coreData = await crypto.deriveEncrypt({ encryptionBaseVector, clientIdentitySigningKey, serverIdentityVerifyingKey }, coreKeyBits, "Core Data");
        const { clientEphemeralPublicHex, processAuthChallenge } = await esrp.clientSetupAuthProcess(passwordString);
        const socketId = this.#socket.id;
        const sessionReference = this.#sessionReference;
        const response = await this.axInstance.post("/savePassword", { socketId, sessionReference, coreKeyBitsBase64, authKeyBitsBase64, serverKeyBitsBase64, clientEphemeralPublicHex });
        if (response?.status === 200) {
            const { verifierSaltBase64, verifierEntangledHex } = response.data;
            const verifierSalt = Buffer.from(verifierSaltBase64, "base64");
            const laterConfirmation = await processAuthChallenge(verifierSalt, verifierEntangledHex, "later");
            const authData = await crypto.deriveEncrypt({ username, laterConfirmation }, authKeyBits, "Auth Data");
            const savedAuth = serialize({ serverKeyBits, authData, coreData }).toString("base64");
            window.localStorage.setItem("SavedAuth", savedAuth);
            return true;
        }
        else return false;
    }

    private async loadChats() {
        const chatsData = await this.#socketHandler.GetAllChats([]);
        if ("reason" in chatsData) return;
        const chats = await Promise.all(chatsData.map((chatData) => Chat.instantiate(this.#username, this.#encryptionBaseVector, this.chatInterface(chatData.sessionId), chatData)));
        for (const chat of chats) {
            this.addChat(chat);
        }
        await Promise.all(chats.map((chat) => this.requestRoom(chat)));
    }

    private async loadRequest(request: ChatRequestHeader) {
        const result = await this.#x3dhUser.viewChatRequest(request);
        if (typeof result === "string") {
            logError(result);
            return false;
        }
        if (this.chatUsernamesList.get(result.profile.username)?.type === "ChatRequest") {
            logError("Duplicate request.");
            this.rejectRequest(request.sessionId, request.yourOneTimeKeyIdentifier);
            return false;
        }
        const chatRequest = new ChatRequest(request, {
            respondToRequest: (request: ChatRequestHeader, respondingAt: number) => this.respondToRequest(request, respondingAt),
            rejectRequest: (sessionId: string, oneTimeKeyId: string) => this.rejectRequest(sessionId, oneTimeKeyId)
        }, result);
        this.addChat(chatRequest);
        return true;
    }

    private async loadRequests() {
        const requests = await this.#socketHandler.GetAllRequests([]);
        if ("reason" in requests) {
            logError(requests);
            return false;
        }
        const successes = await allSettledResults(requests.map((r) => this.loadRequest(r)));
        return successes.every((s) => s);
    }

    private async respondToRequest(request: ChatRequestHeader, respondingAt: number) {
        const { sessionId } = request;
        const { profile: myProfile } = this;
        const viewChatRequest = await this.#x3dhUser.viewChatRequest(request);
        const exportedChattingSession = await this.#x3dhUser.acceptChatRequest(request, respondingAt, myProfile, async (response) => {
            const sent = await this.#socketHandler.SendMessage(response);
            if (sent.reason) {
                logError(sent);
                return false;
            }
            return true;
        });
        if (typeof exportedChattingSession === "string" || typeof viewChatRequest === "string") {
            logError(exportedChattingSession);
            return false;
        }
        const { profile, text, messageId, timestamp } = viewChatRequest;
        const lastActive = respondingAt;
        const chatDetails = await crypto.deriveEncrypt(profile, this.#encryptionBaseVector, "ContactDetails");
        const chatData = { chatDetails, exportedChattingSession, lastActive, sessionId };
        await this.#socketHandler.CreateChat(chatData);
        await this.#socketHandler.DeleteChatRequest({ sessionId });
        const newChat = await Chat.instantiate(this.#username, this.#encryptionBaseVector, this.chatInterface(sessionId), chatData, { text, messageId, sentByMe: false, timestamp });
        this.removeChat(sessionId, "sessionId");
        this.addChat(newChat);
        return true;
    }

    private async rejectRequest(sessionId: string, oneTimeKeyId: string) {
        const result = await this.#socketHandler.DeleteChatRequest({ sessionId });
        if (result.reason) {
            logError(result);
            return false;
        }
        this.#x3dhUser.disposeOneTimeKey(oneTimeKeyId);
        this.removeChat(sessionId, "sessionId");
        return true;
    }

    private async receiveRequestResponse(message: MessageHeader) {
        const { sessionId } = message;
        const awaitedRequest = this.chatSessionIdsList.get(sessionId);
        if (!awaitedRequest || awaitedRequest.type !== "AwaitedRequest") {
            return false;
        }
        const response = await this.#x3dhUser.receiveChatRequestResponse(message);
        if (typeof response === "string") {
            logError(response);
            return false;
        }
        const { messageId, text, timestamp } = awaitedRequest.chatMessage.displayMessage;
        const [{ profile, respondedAt }, exportedChattingSession] = response;
        const chatDetails = await crypto.deriveEncrypt(profile, this.#encryptionBaseVector, "ContactDetails");
        const chatData = { chatDetails, exportedChattingSession, lastActive: respondedAt, sessionId };
        const { reason } = await this.#socketHandler.CreateChat(chatData);
        if (reason) {
            logError(reason);
            return false;
        }
        const x3dhInfo = await this.#x3dhUser.deleteWaitingRequest(sessionId);
        const { reason: r2 } = await this.#socketHandler.UpdateX3DHUser({ x3dhInfo, username: this.username });
        if (r2) {
            logError(r2);
        }
        await this.#socketHandler.MessageProcessed({ sessionId, messageId });
        const newChat = await Chat.instantiate(this.#username, this.#encryptionBaseVector, this.chatInterface(sessionId), chatData, { messageId, text, timestamp, sentByMe: true, deliveredAt: respondedAt });
        this.removeChat(sessionId, "sessionId");
        this.addChat(newChat);
        await this.requestRoom(newChat);
        return true;
    }

    private async respond(event: string, data: string, responseBy: (arg0: any) => any, respondAt: (arg0: string) => void) {
        const respond = async (response: any) => {
            respondAt(await this.#sessionCrypto.signEncryptToBase64(response, event));
        }
        try {
            const decryptedData = await this.#sessionCrypto.decryptVerifyFromBase64(data, event);
            if (!decryptedData) await respond(failure(ErrorStrings.DecryptFailure));
            else {
                const response = await responseBy(decryptedData);
                if (!response) await respond(failure(ErrorStrings.ProcessFailed));
                else {
                    respond(response);
                }
            }
        }
        catch (err) {
            logError(err)
            respond(failure(ErrorStrings.ProcessFailed, err));
        }
    }

    private awaitServerRoomReady(otherUsername: string) {
        return new Promise<boolean>((resolve) => {
            const response = (withUser: string) => {
                if (withUser === otherUsername) {
                    this.#socket.off(SocketServerSideEvents.ServerRoomReady, response);
                    resolve(true);
                }
            };
            this.#socket.on(SocketServerSideEvents.ServerRoomReady, response);
            setTimeout(() => {
                this.#socket.off(SocketServerSideEvents.ServerRoomReady, response);
                resolve(false);
            }, 1000);
        });
    }

    private async roomRequested({ username }: Username) {
        if (username === this.#username) return failure(ErrorStrings.InvalidRequest);
        const chat = this.chatUsernamesList.get(username);
        if (!chat || chat.type !== "Chat") return failure(ErrorStrings.InvalidRequest);
        this.awaitServerRoomReady(username).then((ready) => {
            if (ready) {
                chat.establishRoom(this.#sessionCrypto, this.#socket);
            }
        })
        return { reason: null };
    }

    private async requestRoom(chat: Chat) {
        const waitReady = this.awaitServerRoomReady(chat.otherUser);
        const response = await this.#socketHandler.RequestRoom({ username: chat.otherUser });
        if (response.reason) {
            return response;
        }

        const confirmed = await waitReady.then(async (ready) => {
            return ready ? await chat.establishRoom(this.#sessionCrypto, this.#socket) : false;
        });
        if (!confirmed) return failure(ErrorStrings.ProcessFailed);
        return { reason: null };
    }

    private async messageReceived(message: MessageHeader) {
        const { sessionId } = message;
        return await match(this.chatSessionIdsList.get(sessionId)?.type)
            .with("Chat", () => (this.chatSessionIdsList.get(sessionId) as Chat)?.messageReceived(message))
            .with("AwaitedRequest", () => this.receiveRequestResponse(message))
            .otherwise(async () => false);
    }

    private async chatRequestReceived(message: ChatRequestHeader) {
        return await this.loadRequest(message);
    }
}

export type AwaitedRequest = Readonly<{
    sessionId: string,
    otherUser: string,
    lastActive: number,
    chatMessage: ChatMessage,
    type: "AwaitedRequest"
}>

type MessageContent = Readonly<{
    text: string;
    timestamp: number;
    replyId?: string;
}>;

function AwaitedRequest(otherUser: string, sessionId: string, messageId: string, timestamp: number, text: string): AwaitedRequest {
    return { 
        sessionId,
        otherUser, 
        lastActive: timestamp, 
        chatMessage: new ChatMessage({ 
            messageId, 
            text, 
            timestamp,
            sentByMe: true,
            delivery: {
                delivered: false, 
                seen: false 
            } 
        }, null), 
        type: "AwaitedRequest" };
}

export class ChatRequest {
    readonly type = "ChatRequest";
    readonly otherUser: string;
    readonly contactDetails: Readonly<{ displayName: string, contactName?: string, profilePicture: string }>;
    readonly chatMessage: ChatMessage;
    readonly lastActive: number;
    readonly sessionId: string;
    private readonly chatRequestHeader: ChatRequestHeader;
    private readonly clientInterface: ClientChatRequestInterface;

    constructor(chatRequestHeader: ChatRequestHeader, clientInterface: ClientChatRequestInterface, viewRequest: ViewChatRequest) {
        const { text, messageId, timestamp, profile: { username: otherUser, ...contactDetails } } = viewRequest;
        this.sessionId = chatRequestHeader.sessionId;
        this.otherUser = otherUser;
        this.contactDetails = contactDetails;
        this.chatMessage = new ChatMessage({ messageId, text, timestamp, sentByMe: false }, null);
        this.lastActive = timestamp;
        this.chatRequestHeader = chatRequestHeader;
        this.clientInterface = clientInterface;
    }

    async rejectRequest() {
        return await this.clientInterface.rejectRequest(this.otherUser, this.sessionId, this.chatRequestHeader.yourOneTimeKeyIdentifier);
    }
    async respondToRequest(respondingAt: number) {
        return await this.clientInterface.respondToRequest(this.chatRequestHeader, respondingAt);
    }
}

type ChatEvent = "room-established" | "room-disconnected" | "typing-change" | "new-received" | "added" | "loading-earlier" | "loaded-earlier" | "received-new"

export class Chat {
    private disposed = false;
    private readonly loadingBatch = 10;
    private loadedUpto = Date.now();
    private lastActive_: number;
    private lastActivity_: DisplayMessage;
    private otherTyping: boolean;
    private typingTimeout: number;
    private notify: (event: ChatEvent) => void;
    private notifyActivity: () => void;
    private readonly messagesList = new Map<string, ChatMessage>();
    private readonly chatMessageLists = new Map<string, ChatMessageListInternal>();
    private readonly clientInterface: ClientChatInterface;
    readonly type = "Chat";
    readonly sessionId: string;
    readonly me: string;
    readonly otherUser: string;
    readonly contactDetails: Omit<Contact, "username">;
    readonly #chattingSession: ChattingSession;
    readonly #encryptionBaseVector: CryptoKey;
    #sessionCrypto: SessionCrypto;
    #socket: Socket;

    get hasRoom() { return !!this.#sessionCrypto; }

    get lastActive() { return this.lastActive_; }

    get messages() { 
        return Array.from(this.chatMessageLists.entries())
                .sort(([d1,], [d2,]) => DateTime.fromISO(d1).toMillis() - DateTime.fromISO(d2).toMillis())
                .map(([d, l]) => l.exposeList);
    }

    get isOtherTyping() { return this.otherTyping; }

    private set isOtherTyping(value: boolean) {
        window.clearTimeout(this.typingTimeout);
        if (this.otherTyping !== value) {
            this.otherTyping = value;
            this.notify?.("typing-change");
        }
        if (value) {
            this.typingTimeout = window.setTimeout(() => {
                this.isOtherTyping = false;
            }, 3000);
        }
    }

    subscribe(notifyAdded: (event: ChatEvent) => void) {
        this.notify = notifyAdded;
    }

    unsubscribe() {
        this.notify = null;
    }

    subscribeActivity(notifyActivity: () => void) {
        this.notifyActivity = notifyActivity;
    }

    unsubscribeActivity() {
        this.notifyActivity = null;
    }

    disconnectRoom() {
        this.#socket?.off(`${this.otherUser} -> ${this.me}`);
        this.#socket = null;
        this.#sessionCrypto = null;
        this.disposed = true;
        this.notify?.("room-disconnected");
    }

    private constructor(sessionId: string, me: string, recipientDetails: Contact, encryptionBaseVector: CryptoKey, clientInterface: ClientChatInterface, chattingSession: ChattingSession) {
        this.sessionId = sessionId;
        this.me = me;
        const { username: recipient, ...contactDetails } = recipientDetails;
        this.otherUser = recipient;
        this.contactDetails = contactDetails;
        this.clientInterface = clientInterface;
        this.#encryptionBaseVector = encryptionBaseVector;
        this.#chattingSession = chattingSession;
    }

    static async instantiate(me: string, encryptionBaseVector: CryptoKey, clientInterface: ClientChatInterface, chatData: ChatData, firstMessage?: { messageId: string, text: string, timestamp: number, sentByMe: boolean, deliveredAt?: number }) {
        const { chatDetails, exportedChattingSession, lastActive, sessionId } = chatData;
        const contactDetails: Contact = await crypto.deriveDecrypt(chatDetails, encryptionBaseVector, "ContactDetails");
        const chattingSession = await ChattingSession.importSession(exportedChattingSession, encryptionBaseVector);
        const chat = new Chat(sessionId, me, contactDetails, encryptionBaseVector, clientInterface, chattingSession);
        chat.lastActive_ = lastActive;
        if (firstMessage) {
            const { messageId, text, timestamp, sentByMe, deliveredAt: deliveredAt } = firstMessage;
            const delivery = { delivered: deliveredAt, seen: deliveredAt };
            await chat.encryptStoreMessage({ messageId, text, timestamp, sentByMe, delivery }, false);
        }
        chat.loadNext().then(() => chat.loadUnprocessedMessages());
        return chat;
    }

    async establishRoom(sessionCrypto: SessionCrypto, socket: Socket) {
        if (this.disposed) {
            return false;
        }
        const confirmed = await new Promise((resolve) => {
            socket.once(this.otherUser, (confirmation: string) => resolve(confirmation === "confirmed"));
            socket?.emit(SocketServerSideEvents.ClientRoomReady, this.otherUser);
            window.setTimeout(() => resolve(false), 1000);
        })
        if (!confirmed) {
            socket.off(this.otherUser);
            return false;
        }
        this.#sessionCrypto = sessionCrypto;
        this.#socket = socket;
        this.#socket.on(`${this.otherUser} -> ${this.me}`, this.receiveMessage.bind(this));
        this.#socket.on("disconnect", () => {
            this.disconnectRoom();
        })
        this.loadUnprocessedMessages();
        this.notify?.("room-established");
    }

    async sendMessage(messageContent: MessageContent) {
        if (this.disposed) {
            return false;
        }
        const { text, timestamp, replyId } = messageContent;
        const messageId = getRandomString(15, "hex");
        const sendingMessage = { messageId, text, timestamp, replyingTo: replyId };
        const replyingTo = await this.populateReplyingTo(replyId);
        if (replyingTo === undefined) {
            logError("Failed to come up with replied-to message.");
            return false;
        }
        const displayMessage: DisplayMessage ={ 
            messageId, 
            text,
            replyingTo,
            timestamp,
            sentByMe: true,
            delivery: null
        };
        this.addMessageToList(displayMessage);
        const encryptedMessage = crypto.deriveEncrypt(displayMessage, this.#encryptionBaseVector, this.sessionId).then((content) => ({ messageId, timestamp, content }));
        const exportedChattingSession = await this.#chattingSession.sendMessage(sendingMessage, async (header) => await this.dispatch(header, true));
        if (typeof exportedChattingSession === "string") {
            logError(exportedChattingSession);
            return false;
        }
        await this.clientInterface.StoreMessage(await encryptedMessage);
        this.messagesList.get(messageId)?.signalEvent("sent", Date.now());
        const { lastActive_: lastActive } = this;
        await this.clientInterface.UpdateChat({ lastActive, exportedChattingSession });
        return true;
    }

    async sendEvent(event: "typing" | "stopped-typing", timestamp: number): Promise<boolean>;
    async sendEvent(event: "delivered" | "seen", timestamp: number, reportingAbout: string): Promise<boolean>;
    async sendEvent(event: "typing" | "stopped-typing" | "delivered" | "seen", timestamp: number, reportingAbout?: string): Promise<boolean> {
        if (this.disposed) {
            return false;
        }
        const sendWithoutRoom = event === "delivered" || event === "seen";
        if (!sendWithoutRoom && !this.hasRoom) {
            return false;
        }
        const messageId = getRandomString(15, "hex");
        const sendingMessage: SendingMessage =
            event === "delivered" || event === "seen"
                ? { messageId, timestamp, event, reportingAbout }
                : { messageId, timestamp, event };
        const exportedChattingSession = await this.#chattingSession.sendMessage(sendingMessage, async (header) => {
            const success = await this.dispatch(header, sendWithoutRoom);
            if (success && (event === "delivered" || event === "seen")) {
                const message = await this.getMessageById(reportingAbout);
                const delivery = calculateDelivery(message.delivery, event, timestamp);
                await this.encryptStoreMessage({ ...message, delivery }, false);
            }
            return success;
        });
        if (typeof exportedChattingSession === "string") {
            logError(exportedChattingSession);
            return false;
        }
        const { lastActive_: lastActive } = this;
        await this.clientInterface.UpdateChat({ lastActive, exportedChattingSession });
    }

    private async dispatch(header: MessageHeader, sendWithoutRoom: boolean) {
        let tries = 0;
        let success = false;
        const dispatchEvent = `${this.me} -> ${this.otherUser}`;
        if (this.hasRoom) {
            while (!success && tries <= 10) {
                tries++;
                success = await new Promise<boolean>(async (resolve) => {
                    this.#socket?.emit(dispatchEvent, await this.#sessionCrypto.signEncryptToBase64(header, dispatchEvent), (response: boolean) => resolve(response));
                    window.setTimeout(() => resolve(false), 5000);
                });
            }
        }
        else if (sendWithoutRoom) {
            while (!success && tries <= 10) {
                tries++;
                success = !(await this.clientInterface.SendMessage(header)).reason;
            }
        }
        return success;
    }

    async loadNext() {
        if (this.disposed) {
            return;
        }
        const messages = await this.clientInterface.GetMessagesByNumber({ limit: this.loadingBatch, olderThan: this.loadedUpto });
        if ("reason" in messages) {
            logError(messages);
            return;
        }
        await this.decryptPushMessages(messages);
    }

    async loadUptoId(messageId: string) {
        if (this.disposed) {
            return;
        }
        const messages = await this.clientInterface.GetMessagesUptoId({ messageId, olderThan: this.loadedUpto });
        if ("reason" in messages) {
            logError(messages);
            return;
        }
        await this.decryptPushMessages(messages);
    }

    async loadUptoTime(newerThan: number) {
        if (this.disposed) {
            return;
        }
        const messages = await this.clientInterface.GetMessagesUptoTimestamp({ newerThan, olderThan: this.loadedUpto });
        if ("reason" in messages) {
            logError(messages);
            return;
        }
        await this.decryptPushMessages(messages);
    }

    async messageReceived(message: MessageHeader) {
        if (this.disposed) {
            return false;
        }
        return await this.processEncryptedMessage(message);
    }

    private addMessageToList(message: DisplayMessage) {
        const { messageId, timestamp } = message;
        const date = DateTime.fromMillis(timestamp).toISODate();
        let chatMessageList = this.chatMessageLists.get(date);
        if (chatMessageList) {
            chatMessageList.add(message);
        }
        else {
            chatMessageList = 
            ChatMessageListInternal.construct(message, (event, timestamp, reportingAbout) => this.sendEvent(event, timestamp, reportingAbout));
            this.chatMessageLists.set(date, chatMessageList);
            this.notify?.("added");
        }
        this.messagesList.set(messageId, chatMessageList.messageById(messageId));
        if (timestamp < this.loadedUpto) {
            this.loadedUpto = timestamp;
        }
        else if (timestamp > this.lastActive_) {
            this.lastActive_ = timestamp;
            this.lastActivity_ = message;
            this.notify?.("received-new");
            this.notifyActivity?.();
        }
    }

    private async receiveMessage(data: string, ack: (recv: boolean) => void) {
        if (!data) {
            ack(false);
            return;
        }
        if (data === "disconnected") {
            this.#socket?.off(`${this.otherUser} -> ${this.me}`);
            this.#socket = null;
            this.#sessionCrypto = null;
            return;
        }
        try {
            const decryptedData: MessageHeader = await this.#sessionCrypto.decryptVerifyFromBase64(data, `${this.otherUser} -> ${this.me}`);
            if (!decryptedData) {
                ack(false);
            }
            else {
                ack(await this.processEncryptedMessage(decryptedData));
            }
        }
        catch (e: any) {
            logError(e);
            ack(false);
        }
    }

    private async decryptPushMessages(messages: StoredMessage[]) {
        await Promise.all(messages.map(async (message) => {
            const displayMessage: DisplayMessage = await crypto.deriveDecrypt(message.content, this.#encryptionBaseVector, this.sessionId);
            this.addMessageToList(displayMessage);
        }));
    }

    private async encryptStoreMessage(message: DisplayMessage, wasUnprocessed: boolean) {
        const { messageId, timestamp, sentByMe } = message;
        const encryptedContent = await crypto.deriveEncrypt(message, this.#encryptionBaseVector, this.sessionId);
        const encryptedMessage = { messageId, timestamp, content: encryptedContent };
        await this.clientInterface.StoreMessage(encryptedMessage);
        if (wasUnprocessed || sentByMe) {
            await this.clientInterface.MessageProcessed({ messageId });
        }
    }

    private async processEncryptedMessage(encryptedMessage: MessageHeader): Promise<boolean> {
        const { messageId } = encryptedMessage;
        const exportedChattingSession = await this.#chattingSession.receiveMessage(encryptedMessage, async (messageBody) => {
            const { sender, timestamp } = messageBody;
            if (sender !== this.otherUser) {
                return false;
            }
            let displayMessage: DisplayMessage;
            if ("event" in messageBody) {
                if (messageBody.event !== "delivered" && messageBody.event !== "seen") {
                    if ((Date.now() - timestamp) < 5000) {
                        this.isOtherTyping = messageBody.event === "typing";
                    }
                    return true;
                }
                const { event, reportingAbout } = messageBody;
                const chatMessage = this.messagesList.get(reportingAbout);
                if (chatMessage) {
                    chatMessage.signalEvent(event, timestamp);
                    displayMessage = chatMessage.displayMessage;
                }
                else {
                    const storedMessage = await this.getMessageById(messageId);
                    if (storedMessage) {
                        const delivery = calculateDelivery(storedMessage.delivery, event, timestamp);
                        displayMessage = { ...storedMessage, delivery };
                    }
                }
            }
            else {
                const { text, replyingTo: replyId } = messageBody;
                const replyingTo = await this.populateReplyingTo(replyId);
                if (replyingTo === undefined) {
                    logError("Failed to come up with replied-to message.");
                    return false;
                }
                displayMessage = { messageId, timestamp, text, replyingTo, sentByMe: false };
                this.addMessageToList(displayMessage);
            }
            await this.encryptStoreMessage(displayMessage, true);
            return true;
        });
        if (typeof exportedChattingSession === "string") {
            if (exportedChattingSession === "Receving Ratchet Number Mismatch") {
                await this.clientInterface.MessageProcessed({ messageId });
            }
            logError(exportedChattingSession);
            return false;
        };
        const { lastActive_: lastActive } = this;
        await this.clientInterface.UpdateChat({ lastActive, exportedChattingSession });
        return true;
    }

    private async populateReplyingTo(id: string): Promise<ReplyingToInfo> {
        if (!id) return null;
        const repliedTo = await this.getMessageById(id);
        const replyToOwn = repliedTo.sentByMe;
        const displayText = truncateText(repliedTo.text);
        return { id, replyToOwn, displayText };
    }

    private async getMessageById(messageId: string): Promise<DisplayMessage> {
        if (!messageId) return null;
        if (this.messagesList.has(messageId)) return this.messagesList.get(messageId).displayMessage;
        const fetched = await this.clientInterface.GetMessageById({ messageId });
        if ("reason" in fetched) {
            logError(fetched);
            return undefined;
        };
        return await crypto.deriveDecrypt(fetched.content, this.#encryptionBaseVector, this.sessionId);
    }

    private async loadUnprocessedMessages() {
        let unprocessedMessages = await this.clientInterface.GetUnprocessedMessages();
        if ("reason" in unprocessedMessages) {
            logError(unprocessedMessages.reason);
            return;
        }
        unprocessedMessages = _.sortBy(unprocessedMessages, ["sendingRatchetNumber", "sendingChainNumber"]);
        for (const message of unprocessedMessages) {
            await this.processEncryptedMessage(message);
        }
    }
}

class ChatMessageListInternal {
    readonly date: string;
    private indexedMessages = new Map<string, ChatMessage>();
    private messages: ChatMessage[] = [];
    private notifyAdded: () => void;
    private sendEvent: (event: "delivered" | "seen", timestamp: number, reportingAbout: string) => void;
    private earliest: number;
    private latest: number;
    private exposedList: ChatMessageList;

    static construct(message: DisplayMessage, sendEvent: (event: "delivered" | "seen", timestamp: number, reportingAbout: string) => void) {
        const internalList = new ChatMessageListInternal(message, sendEvent);
        internalList.exposedList = new ChatMessageList(internalList);
        return internalList;
    }

    private constructor(message: DisplayMessage, sendEvent: (event: "delivered" | "seen", timestamp: number, reportingAbout: string) => void) {
        const { timestamp } = message;
        this.date = DateTime.fromMillis(timestamp).toISODate();
        this.sendEvent = sendEvent;
        this.latest = timestamp;
        this.earliest = this.latest + 1;
        this.add(message);
    }

    public get messageList() {
        return [...this.messages];
    }

    public get exposeList() {
        return this.exposedList;
    }

    messageById(messageId: string) {
        return this.indexedMessages.get(messageId);
    }

    subscribe(notifyAdded: () => void) {
        this.notifyAdded = notifyAdded;
    }

    unsubscribe() {
        this.notifyAdded = null;
    }

    add(displayMessage: DisplayMessage) {
        const { messageId, timestamp, sentByMe } = displayMessage;
        let message: ChatMessage;
        const sendEvent = 
            sentByMe 
                ? null
                : (event: "delivered" | "seen", timestamp: number) => this.sendEvent(event, timestamp, messageId);
        if (timestamp < this.earliest) {            
            message = new ChatMessage(displayMessage, null, sendEvent);
            const previous = this.messages[0];
            this.messages.unshift(message);
            previous?.updateFirst(sentByMe !== previous.displayMessage.sentByMe);
            this.earliest = timestamp;
        }
        else if (timestamp > this.latest) {
            const lastSentByMe = this.messages.slice(-1)[0].displayMessage.sentByMe;
            message = new ChatMessage(displayMessage, sentByMe !== lastSentByMe, sendEvent);
            this.messages.push(message);
            this.latest = timestamp;
        }
        if (message) {
            this.indexedMessages.set(messageId, message);
            this.notifyAdded?.();
        }
        else logError(new Error("New message cannot be added in the middle."));
    }
}

export class ChatMessageList {
    private internalList: ChatMessageListInternal;

    constructor(internalList: ChatMessageListInternal) {
        this.internalList = internalList;
    }

    public get date() {
        return this.internalList.date;
    }

    public get messageList() {
        return this.internalList.messageList;
    }

    subscribe(notifyAdded: () => void) {
        this.internalList.subscribe(notifyAdded);
    }

    unsubscribe() {
        this.internalList.unsubscribe();
    }
}

export class ChatMessage {
    private message: DisplayMessage;
    private isFirst: null | boolean;
    private notifyChange: (event: "first" | "sent" | "delivered" | "seen") => void;
    readonly signalEvent: (event: "sent" | "delivered" | "seen", timestamp: number) => void;

    public get messageId() {
        return this.displayMessage.messageId;
    }

    public get displayMessage() {
        return this.message;
    }

    public get isFirstOfType() {
        return this.isFirst === null || this.isFirst;
    }

    public updateFirst(isFirst: boolean) {
        if (this.isFirst === null || isFirst !== null || this.isFirst !== isFirst) {
            this.isFirst = isFirst;
            this.notifyChange?.("first");
        }

    }

    subscribe(notifyChange: (event: "first" | "sent" | "delivered" | "seen") => void) {
        this.notifyChange = notifyChange;
    }

    unsubscribe() {
        this.notifyChange = null;
    }

    constructor(displayMessage: DisplayMessage, 
        isFirst: boolean,
        signalEvent?: (event: "delivered" | "seen", timestamp: number) => void) {
            this.message = displayMessage;
            this.isFirst = isFirst;
            this.signalEvent = (event, timestamp) => {
                const prevDelivery = this.message.delivery;
                let newDelivery: DeliveryInfo;
                if (event === "sent") {
                    newDelivery = prevDelivery || {
                        delivered: false,
                        seen: false
                    };
                }
                else {
                    newDelivery = calculateDelivery(prevDelivery, event, timestamp);
                }
                if (!_.isEqual(newDelivery, prevDelivery)) {
                    this.message = { ...this.message, delivery: newDelivery };
                    this.notifyChange?.(event);
                    if (event !== "sent") signalEvent?.(event, timestamp);
                }
            }
            if (!displayMessage.sentByMe && !displayMessage.delivery?.delivered) {
                this.signalEvent("delivered", Date.now());
            }
    }
}

function calculateDelivery(prevDelivery: DeliveryInfo, event: "delivered" | "seen", timestamp: number) {
    const { delivered, seen } = prevDelivery || {};
    let newDelivery: DeliveryInfo;
    if (event === "delivered") {
        newDelivery = {
            delivered: delivered && delivered < timestamp ? delivered : timestamp,
            seen: seen || false
        };
    }
    else {
        newDelivery = {
            delivered: delivered || timestamp,
            seen: seen || timestamp
        };
    }
    return newDelivery;
}

function logError(err: any): void {
    const message = err.message;
    if (message) {
        console.log(`${message}`);
    }
    else {
        console.log(`${stringify(err)}`);
    }
    console.trace();
}

function truncateText(text: string) {
    const maxChar = 200;
    if (!text) return null;
    if (text.length <= maxChar) return text;
    const truncate = text.indexOf(" ", maxChar);
    return `${text.slice(0, truncate)} ...`;
}

function fromBase64(data: string) {
    return Buffer.from(data, "base64");
}

async function allSettledResults<T>(promises: Promise<T>[]) {
    return (await Promise.allSettled(promises)).filter((result) => result.status === "fulfilled").map((result) => (result as PromiseFulfilledResult<T>).value);
}