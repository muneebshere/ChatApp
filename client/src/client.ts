import _ from "lodash";
import { match } from "ts-pattern";
import axios, { Axios } from "axios";
import { io, Socket } from "socket.io-client";
import { SessionCrypto } from "../../shared/sessionCrypto";
import {  X3DHUser } from "./e2e-encryption";
import * as crypto from "../../shared/cryptoOperator";
import { serialize, deserialize } from "../../shared/cryptoOperator";
import * as esrp from "../../shared/ellipticSRP";
import { allSettledResults, failure, fromBase64, logError, randomFunctions } from "../../shared/commonFunctions";
import { ErrorStrings, Failure, Username, SocketClientSideEvents, PasswordEncryptedData, MessageHeader, ChatRequestHeader, StoredMessage, ChatData, SocketClientSideEventsKey, SocketServerSideEventsKey, SocketServerSideEvents, SocketClientRequestParameters, SocketClientRequestReturn, RegisterNewUserRequest, NewUserData, Profile, RegisterNewUserChallengeResponse, LogInRequest, LogInChallengeResponse, MessageIdentifier, ChatIdentifier, Receipt, UserEncryptedData, SessionIdentifier, HeaderIdentifier, Backup  } from "../../shared/commonTypes";
import { noProfilePictureImage } from "./noProfilePictureImage";
import { AwaitedRequest, Chat, ChatDetails, ChatRequest } from "./chatClasses";

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

export type ClientChatInterface = Readonly<{
    SendMessage: (data: MessageHeader, timeout?: number) => Promise<Failure>,
    GetMessageHeaders: (data: SessionIdentifier & { fromAlias: string }, timeout?: number) => Promise<MessageHeader[] | Failure>,
    GetMessagesByNumber: (data: ChatIdentifier & { limit: number, olderThanTimemark: number }, timeout?: number) => Promise<StoredMessage[] | Failure>,
    GetMessagesUptoTimestamp: (data: ChatIdentifier & { newerThanTimemark: number, olderThanTimemark: number }, timeout?: number) => Promise<StoredMessage[] | Failure>,
    GetMessagesUptoId: (data: MessageIdentifier & { olderThanTimemark: number }, timeout?: number) => Promise<StoredMessage[] | Failure>,
    GetMessageById: (data: MessageIdentifier, timeout?: number) => Promise<StoredMessage | Failure>,
    StoreMessage: (data: StoredMessage, timeout?: number) => Promise<Failure>,
    MessageHeaderProcessed: (data: SessionIdentifier & HeaderIdentifier, timeout?: number) => Promise<Failure>,
    UpdateChat: (data: Partial<ChatData> & Omit<ChatData, "chatDetails" | "exportedChattingSession">, timeout?: number) => Promise<Failure>,
    StoreBackup(data: Backup, timeout?: number): Promise<Failure>,
    GetBackupById(data: HeaderIdentifier & { byAlias: string }, timeout?: number): Promise<Backup | Failure>,
    BackupProcessed(data: HeaderIdentifier & { byAlias: string }, timeout?: number): Promise<Failure>,
    SendReceipt(data: Receipt, timeout?: number): Promise<Failure>,
    GetAllReceipts(data: SessionIdentifier, timeout?: number): Promise<Receipt[] | Failure>,
    ClearAllReceipts(data: SessionIdentifier, timeout?: number): Promise<Failure>,
    isConnected(): boolean,
    notifyClient: (timeout?: number) => void
}>;

export type ClientChatRequestInterface = Readonly<{
    rejectRequest: (otherUser: string, sessionId: string, oneTimeKeyId: string) => Promise<boolean>,
    acceptRequest: (request: ChatRequestHeader, respondingAt: number) => Promise<boolean>
}>;

type SavedAuthData = Readonly<{
    username: string,
    laterConfirmation: esrp.ClientAuthChallengeLaterResult;
    databaseAuthKeyBuffer: Buffer;
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
export default class Client {
    private readonly responseMap: Map<SocketServerSideEventsKey, any> = new Map([
        [SocketServerSideEvents.RoomRequested, this.roomRequested] as [SocketServerSideEventsKey, any],
        [SocketServerSideEvents.MessageReceived, this.messageReceived],
        [SocketServerSideEvents.ChatRequestReceived, this.chatRequestReceived],
        [SocketServerSideEvents.ReceiptReceived, this.receiptReceived]
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
    #chatIds: string[];
    #x3dhUser: X3DHUser;
    #sessionReference: string;
    #sessionCrypto: SessionCrypto
    #socketHandler: RequestMap;
    #encryptionBaseVector: CryptoKey;
    #fileHash: Promise<string>;
    private readonly chatList: string[] = [];
    private readonly chatSessionIdsList = new Map<string, Chat | ChatRequest | AwaitedRequest>();
    private readonly chatUsernamesList = new Map<string, Chat | ChatRequest | AwaitedRequest>();

    private readonly chatInterface: ClientChatInterface = {
        SendMessage: (data, timeout = 0) => {
            return this.#socketHandler.SendMessage(data, timeout);
        },
        GetMessageHeaders: (data, timeout = 0) => {
            return this.#socketHandler.GetMessageHeaders(data, timeout);
        },
        GetMessagesByNumber: (data, timeout = 0) => {
            return this.#socketHandler.GetMessagesByNumber(data, timeout);
        },
        GetMessagesUptoTimestamp: (data, timeout = 0) => {
            return this.#socketHandler.GetMessagesUptoTimestamp(data, timeout);
        },
        GetMessagesUptoId: (data, timeout = 0) => {
            return this.#socketHandler.GetMessagesUptoId(data, timeout);
        },
        GetMessageById: (data, timeout = 0) => {
            return this.#socketHandler.GetMessageById(data, timeout);
        },
        StoreMessage: (data, timeout = 0) => {
            return this.#socketHandler.StoreMessage(data, timeout);
        },
        MessageHeaderProcessed: (data, timeout?: number) => {
            return this.#socketHandler.MessageHeaderProcessed(data, timeout);
        },
        UpdateChat: (data, timeout = 0) => {
            return this.#socketHandler.UpdateChat(data, timeout);
        },
        StoreBackup: (data, timeout = 0) => {
            return this.#socketHandler.StoreBackup(data, timeout);
        },
        GetBackupById: (data, timeout = 0) => {
            return this.#socketHandler.GetBackupById(data, timeout);
        },
        BackupProcessed: (data, timeout = 0) => {
            return this.#socketHandler.BackupProcessed(data, timeout);
        },
        SendReceipt: (data, timeout = 0) => {
            return this.#socketHandler.SendReceipt(data, timeout);
        },
        GetAllReceipts: (data, timeout = 0) => {
            return this.#socketHandler.GetAllReceipts(data, timeout);
        },
        ClearAllReceipts: (data, timeout = 0) => {
            return this.#socketHandler.ClearAllReceipts(data, timeout);
        },
        isConnected: () => this.isConnected,
        notifyClient: () => this.notifyChange?.()
    };

    private addChat(chat: Chat | ChatRequest | AwaitedRequest) {
        this.chatSessionIdsList.set(chat.sessionId, chat);
        this.chatUsernamesList.set(chat.otherUser, chat);
        this.chatList.push(chat.otherUser);
        this.notifyChange?.();
    }

    private removeChat(key: string, keyType: "username" | "sessionId", dontNotify = false) {
        const chat = keyType === "username" ? this.chatUsernamesList.get(key) : this.chatSessionIdsList.get(key);
        this.chatSessionIdsList.delete(chat.sessionId);
        this.chatUsernamesList.delete(chat.otherUser);
        _.remove(this.chatList, ([user, _]) => user === chat.otherUser);
        if (chat.type === "Chat") {
            chat.disconnectRoom();
        }
        dontNotify || this.notifyChange?.();
    }

    public getChatByUser(otherUser: string): Chat | ChatRequest | AwaitedRequest {
        return this.chatUsernamesList.get(otherUser);
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
        return crypto.digestToBase64("SHA-256", fileBuffer);
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

    async userLogInPermitted(username: string): Promise<{ tries: number, allowsAt: number, isAlreadyOnline: boolean }> {
        const result = await this.#socketHandler.UserLoginPermitted({ username });
        if ("reason" in result) {
            throw "Can't determine if username login is permitted.";
        }
        return result;
    }

    async constructNewUser(profile: Profile, passwordString: string, encryptionBaseVector: Buffer, databaseAuthKeyBuffer: Buffer, clientIdentitySigningKey: PasswordEncryptedData, serverIdentityVerifyingKey: PasswordEncryptedData): Promise<NewUserData> {
        const { username } = profile;
        this.#encryptionBaseVector = await crypto.importRaw(encryptionBaseVector);
        const encryptionBase = await this.passwordEncrypt(passwordString, { encryptionBaseVector }, "Encryption Base");
        const databaseAuthKey = await this.passwordEncrypt(passwordString, { databaseAuthKeyBuffer }, "DatabaseAuthKey");
        const x3dhUser = await X3DHUser.new(username, this.#encryptionBaseVector);
        if (!x3dhUser) {
            this.notifyClientEvent?.(ClientEvent.FailedCreateNewUser);
            throw new Error("Failed to create user");
        }
        const keyBundles = await x3dhUser.publishKeyBundles();
        const x3dhInfo = await x3dhUser.exportUser();
        const chatIds = this.#chatIds = [];
        const profileData = await crypto.deriveEncrypt(profile, this.#encryptionBaseVector, "User Profile");
        const chatsData = await  crypto.deriveEncrypt({ chatIds }, this.#encryptionBaseVector, "Chats Data");
        this.#x3dhUser = x3dhUser;
        return { userData: { profileData, encryptionBase, x3dhInfo, clientIdentitySigningKey, serverIdentityVerifyingKey, chatsData }, databaseAuthKey, keyBundles };
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
            const { challengeReference, serverConfirmationCode, serverIdentityVerifyingKey, verifierEntangledHex, databaseAuthKeyEncrypted } = resultInit;
            const { clientConfirmationCode, sharedKeyBits, confirmServer } = await processAuthChallenge(verifierSalt, verifierEntangledHex, "now");
            const { databaseAuthKeyBuffer } = await crypto.deriveDecrypt(databaseAuthKeyEncrypted, sharedKeyBits, "DatabaseAuthKey");
            const serverVerifyingKey = await this.passwordEncrypt(passwordString, { serverIdentityVerifyingKey }, "Server Verifying Key");
            const encryptionBaseVector = getRandomVector(64);
            const newUserData = await this.constructNewUser(profile, passwordString, encryptionBaseVector, databaseAuthKeyBuffer, clientIdentitySigningKey, serverVerifyingKey);
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
                await this.savePassword(username, passwordString, encryptionBaseVector, exportedIdentitySigningKey, serverIdentityVerifyingKey, databaseAuthKeyBuffer);
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
            const { challengeReference, serverConfirmationCode, verifierEntangledHex, verifierSalt, databaseAuthKey } = resultInit;
            const { clientConfirmationCode, sharedKeyBits, confirmServer } = await processAuthChallenge(verifierSalt, verifierEntangledHex, "now");
            let { databaseAuthKeyBuffer } = (await this.passwordDecrypt(passwordString, databaseAuthKey, "DatabaseAuthKey")) || {};
            databaseAuthKeyBuffer ||= Buffer.alloc(64);
            const logInChallengeResponse: LogInChallengeResponse = { challengeReference, clientConfirmationCode, databaseAuthKeyBuffer };
            const resultConc = await this.#socketHandler.ConcludeLogIn(logInChallengeResponse);
            if ("reason" in resultConc) {
                this.notifyClientEvent?.(ClientEvent.FailedSignIn);
                logError(resultConc);
                return resultConc;
            }
            const { clientIdentitySigningKey: { ciphertext, hSalt, ...pInfo }, encryptionBase, profileData, serverIdentityVerifyingKey: serverIdentityVerifying, x3dhInfo, chatsData } = resultConc;
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
            const { chatIds } = await crypto.deriveDecrypt(chatsData, encryptionBaseVector, "Chats Data");
            if (!serverVerifyingKey || !x3dhUser || !profile || !chatIds) {
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
            this.#chatIds = chatIds;
            if (savePassword) {
                const exportedIdentitySigningKey = await crypto.exportKey(await crypto.deriveUnwrap(identityMasterKeyBits, ciphertext, hSalt, "ECDSA", "Client Identity Signing Key", true));
                await this.savePassword(username, passwordString, encryptionBaseVector, exportedIdentitySigningKey, serverIdentityVerifyingKey, databaseAuthKeyBuffer);
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
            const { username, laterConfirmation, databaseAuthKeyBuffer }: SavedAuthData = await crypto.deriveDecrypt(authData, authKeyBits, "Auth Data");
            const { sharedSecret, clientConfirmationCode, serverConfirmationData } = laterConfirmation;
            const sharedKeyBits = await esrp.getSharedKeyBits(sharedSecret);
            const resultConc = await this.#socketHandler.ConcludeLogInSaved({ username, clientConfirmationCode, databaseAuthKeyBuffer });
            if ("reason" in resultConc) {
                this.notifyClientEvent?.(ClientEvent.FailedSignIn);
                logError(resultConc);
                return resultConc;
            }
            const { coreKeyBits, serverConfirmationCode, userData: { x3dhInfo, profileData, chatsData } } = resultConc;
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
            const { chatIds } = await crypto.deriveDecrypt(chatsData, encryptionBaseVector, "Chats Data");
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
                this.#chatIds = chatIds;
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
        for (const { sessionId, myAlias, otherAlias, messageId, timestamp, otherUser, text } of this.#x3dhUser.pendingChatRequests) {
            const awaited = new AwaitedRequest(otherUser, sessionId, messageId, timestamp, text );
            this.addChat(awaited);
            const result = await this.#socketHandler.GetMessageHeaders({ sessionId, toAlias: myAlias, fromAlias: otherAlias });
            if ("reason" in result) {
                logError(result.reason);
                return;
            }
            const firstResponse = _.orderBy(result, ["sendingRatchetNumber", "sendingChainNumber"], ["asc"])[0];
            if (firstResponse) await this.receiveRequestResponse(firstResponse);
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
        const result = await this.#x3dhUser.generateChatRequest(keyBundle, messageId, firstMessage, madeAt, profile);
        if (typeof result === "string") {
            logError(result);
            return failure(ErrorStrings.ProcessFailed, result);
        }
        const [chatRequest, { sessionId, timestamp, myAlias, otherAlias }, x3dhInfo] = result;
        const result2 = await this.#socketHandler.RegisterPendingSession({ sessionId, otherAlias, myAlias });
        if (result2?.reason) {
            logError(result2);
            return failure(ErrorStrings.ProcessFailed);
        }
        const result3 = await this.#socketHandler.SendChatRequest(chatRequest);
        if (result3?.reason) {
            logError(result3);
            return failure(ErrorStrings.ProcessFailed);
        }
        const result4 = await this.#socketHandler.UpdateUserData({ x3dhInfo, username: this.username });
        if (result4?.reason) {
            logError(result4);
            return failure(ErrorStrings.ProcessFailed);
        }
        this.addChat(new AwaitedRequest(otherUser, sessionId, messageId, timestamp, firstMessage));
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

    private async savePassword(username: string, passwordString: string, encryptionBaseVector: Buffer, clientIdentitySigningKey: Buffer, serverIdentityVerifyingKey: Buffer, databaseAuthKeyBuffer: Buffer) {
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
            const authData = await crypto.deriveEncrypt({ username, laterConfirmation, databaseAuthKeyBuffer }, authKeyBits, "Auth Data");
            const savedAuth = serialize({ serverKeyBits, authData, coreData }).toString("base64");
            window.localStorage.setItem("SavedAuth", savedAuth);
            return true;
        }
        else return false;
    }

    private async loadChats() {
        const chatsData = await this.#socketHandler.GetChats({ chatIds: this.#chatIds });
        if ("reason" in chatsData) return;
        const chats = await Promise.all(chatsData.map((chatData) => Chat.instantiate(this.#encryptionBaseVector, this.chatInterface, chatData)));
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
            this.rejectRequest(result.sessionId, request.headerId, request.yourOneTimeKeyIdentifier);
            return false;
        }
        const chatRequest = new ChatRequest(request, {
            acceptRequest: (request: ChatRequestHeader, respondingAt: number) => this.acceptRequest(request, respondingAt),
            rejectRequest: (sessionId: string, headerId: string, oneTimeKeyId: string) => this.rejectRequest(sessionId, headerId, oneTimeKeyId)
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

    private async acceptRequest(request: ChatRequestHeader, respondingAt: number) {
        const { headerId } = request;
        const { profile: myProfile } = this;
        const viewChatRequest = await this.#x3dhUser.viewChatRequest(request);
        let exportedChattingSession: UserEncryptedData;
        const response = await this.#x3dhUser.acceptChatRequest(request, respondingAt, myProfile, async (exported) => {
            exportedChattingSession = exported;
            return true;
        });
        if (typeof response === "string" || typeof viewChatRequest === "string") {
            logError(response);
            return false;
        }
        const { sessionId, profile, text, messageId, timestamp } = viewChatRequest;
        const { fromAlias, toAlias } = response;
        const registered = await this.#socketHandler.RegisterPendingSession({ sessionId, myAlias: fromAlias, otherAlias: toAlias });
        if (registered?.reason) {
            logError(registered);
            return false;
        }
        const sent = await this.#socketHandler.SendMessage(response);
        if (sent?.reason) {
            logError(sent);
            return false;
        }
        const chatId = getRandomString(15, "base64");
        const details = { chatId, contactDetails: profile, timeRatio: _.random(1, 999) };
        const chatDetails = await crypto.deriveEncrypt(details, this.#encryptionBaseVector, "ChatDetails");
        const chatData: ChatData = { chatId, chatDetails, exportedChattingSession };
        const chatsData = await  crypto.deriveEncrypt({ chatIds: [ ...this.#chatIds, chatId ] }, this.#encryptionBaseVector, "Chats Data");
        await this.#socketHandler.CreateChat(chatData);
        await this.#socketHandler.DeleteChatRequest({ headerId });
        await this.#socketHandler.UpdateUserData({ username: this.username, chatsData });
        const newChat = await Chat.instantiate(this.#encryptionBaseVector, this.chatInterface, chatData, { text, messageId, sentByMe: false, timestamp });
        this.removeChat(sessionId, "sessionId", true);
        this.addChat(newChat);
        return true;
    }

    private async rejectRequest(sessionId: string, headerId: string, oneTimeKeyId: string) {
        const result = await this.#socketHandler.DeleteChatRequest({ headerId });
        if (result.reason) {
            logError(result);
            return false;
        }
        this.#x3dhUser.disposeOneTimeKey(oneTimeKeyId);
        this.removeChat(sessionId, "sessionId");
        return true;
    }

    private async receiveRequestResponse(message: MessageHeader) {
        const { sessionId, headerId, toAlias } = message;
        const awaitedRequest = this.chatSessionIdsList.get(sessionId);
        if (!awaitedRequest || awaitedRequest.type !== "AwaitedRequest") {
            return false;
        }
        let exportedChattingSession: UserEncryptedData;
        const profileResponse = await this.#x3dhUser.receiveChatRequestResponse(message, async (exported) => {
            exportedChattingSession = exported;
            return true;
        });
        if (typeof profileResponse === "string") {
            logError(profileResponse);
            return false;
        }
        const { messageId, text, timestamp } = awaitedRequest.chatMessage.displayMessage;
        if (typeof profileResponse === "string") {
            logError(profileResponse);
            return false;
        }
        const { profile, respondedAt } = profileResponse;
        const chatId = getRandomString(15, "base64");
        const details = { chatId, contactDetails: profile, timeRatio: _.random(1, 999) };
        const chatDetails = await crypto.deriveEncrypt(details, this.#encryptionBaseVector, "ChatDetails");
        const chatData: ChatData = { chatId, chatDetails, exportedChattingSession };
        const chatsData = await  crypto.deriveEncrypt({ chatIds: [ ...this.#chatIds, chatId ] }, this.#encryptionBaseVector, "Chats Data");
        const { reason } = await this.#socketHandler.CreateChat(chatData);
        if (reason) {
            logError(reason);
            return false;
        }
        const x3dhInfo = await this.#x3dhUser.deleteWaitingRequest(sessionId);
        const { reason: r2 } = await this.#socketHandler.UpdateUserData({ chatsData, x3dhInfo, username: this.username });
        if (r2) {
            logError(r2);
        }
        await this.#socketHandler.MessageHeaderProcessed({ sessionId, headerId, toAlias });
        const newChat = await Chat.instantiate(this.#encryptionBaseVector, this.chatInterface, chatData, { messageId, text, timestamp, sentByMe: true, deliveredAt: respondedAt });
        this.removeChat(sessionId, "sessionId", true);
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

    private async receiptReceived(receipt: Receipt) {
        const { sessionId } = receipt;
        const chat = this.chatSessionIdsList.get(sessionId);
        if (chat?.type === "Chat") {
            await chat.processReceipt(receipt);
        }
    }

    private async chatRequestReceived(message: ChatRequestHeader) {
        return await this.loadRequest(message);
    }
}