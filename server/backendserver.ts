import _ from "lodash";
import { DateTime } from "luxon";
import { config } from "./node_modules/dotenv";
import { ServerOptions, createServer } from "node:https";
import fs, { promises as fsPromises } from "node:fs";
import cookieParser from "cookie-parser";
import express, { Request, Response, NextFunction, CookieOptions } from "express";
import cors, { CorsOptions } from "cors";
import * as ipaddr from "ipaddr.js";
import { Server as SocketServer, Socket } from "socket.io";
import { SessionCrypto } from "../shared/sessionCrypto";
import * as crypto from "../shared/cryptoOperator";
import { serialize, deserialize } from "../shared/cryptoOperator";
import { Failure, ErrorStrings, Username, PublishKeyBundlesRequest, RequestKeyBundleResponse, SocketClientSideEvents, ChatRequestHeader, UserEncryptedData, MessageHeader, StoredMessage, ChatData, SocketClientSideEventsKey, SocketServerSideEvents, SocketClientRequestParameters, SocketClientRequestReturn, SignUpRequest, SignUpChallenge, SignUpChallengeResponse, NewUserData, LogInRequest, LogInChallenge, LogInChallengeResponse, Receipt, MessageIdentifier, ChatIdentifier, SessionIdentifier, HeaderIdentifier, Backup, LogInSavedRequest, SavePasswordRequest, LogInResponse, LogInSavedResponse, PasswordDeriveInfo } from "../shared/commonTypes";
import { allSettledResults, failure, fromBase64, logError, randomFunctions, typedEntries } from "../shared/commonFunctions";
import { MongoHandlerCentral } from "./MongoHandler";
import * as esrp from "../shared/ellipticSRP";

declare module "http" {
    interface IncomingMessage {
        cookies: any;
        signedCookies: any;
    }
}

export type Notify = Readonly<{ type: "Message" | "Receipt", sessionId: string } | { type: "Request" }>;

type ResponseMap = Readonly<{
    [E in SocketClientSideEventsKey]: (arg: SocketClientRequestParameters[E]) => Promise<SocketClientRequestReturn[E] | Failure>
}>

class SocketHandler {
    private static socketHandlers: Map<string, SocketHandler>;
    private static onlineUsers: Map<string, { sessionReference: string, ipRep: string }>;

    private readonly responseMap: ResponseMap = {
        [SocketClientSideEvents.UsernameExists]: this.UsernameExists,
        [SocketClientSideEvents.PublishKeyBundles]: this.PublishKeyBundles,
        [SocketClientSideEvents.UpdateUserData]: this.UpdateUserData,
        [SocketClientSideEvents.RequestKeyBundle]: this.RequestKeyBundle,
        [SocketClientSideEvents.GetAllChats]: this.GetAllChats,
        [SocketClientSideEvents.GetAllRequests]: this.GetAllRequests,
        [SocketClientSideEvents.GetMessageHeaders]: this.GetMessageHeaders,
        [SocketClientSideEvents.GetMessagesByNumber]: this.GetMessagesByNumber,
        [SocketClientSideEvents.GetMessagesUptoTimestamp]: this.GetMessagesUptoTimestamp,
        [SocketClientSideEvents.GetMessagesUptoId]: this.GetMessagesUptoId,
        [SocketClientSideEvents.GetMessageById]: this.GetMessageById,
        [SocketClientSideEvents.StoreMessage]: this.StoreMessage,
        [SocketClientSideEvents.MessageHeaderProcessed]: this.MessageHeaderProcessed,
        [SocketClientSideEvents.CreateChat]: this.CreateChat,
        [SocketClientSideEvents.UpdateChat]: this.UpdateChat,
        [SocketClientSideEvents.RegisterPendingSession]: this.RegisterPendingSession,
        [SocketClientSideEvents.SendChatRequest]: this.SendChatRequest,
        [SocketClientSideEvents.SendMessage]: this.SendMessage,
        [SocketClientSideEvents.DeleteChatRequest]: this.DeleteChatRequest,
        [SocketClientSideEvents.StoreBackup]: this.StoreBackup,
        [SocketClientSideEvents.GetBackupById]: this.GetBackupById,
        [SocketClientSideEvents.BackupProcessed]: this.BackupProcessed,
        [SocketClientSideEvents.SendReceipt]: this.SendReceipt,
        [SocketClientSideEvents.GetAllReceipts]: this.GetAllReceipts,
        [SocketClientSideEvents.ClearAllReceipts]: this.ClearAllReceipts,
        [SocketClientSideEvents.RequestRoom]: this.RoomRequested
    };
    private readonly deleteSelf: () => void;
    #sessionCrypto: SessionCrypto;
    #socket: Socket;
    #mongoHandler: typeof MongoHandlerCentral.UserHandlerType;
    #openToRoomTemp: Username;
    #username: string;
    #disposeRooms: (() => void)[] = [];

    static getUsername(sessionReference: string) {
        const sessionHandler = this.socketHandlers.get(sessionReference);
        return sessionHandler ? sessionHandler.#username : null;
    }

    static getUserStatus(username: string, currentIp: string): "ActiveHere" | "ActiveElsewhere" | "Offline" {
        const { sessionReference, ipRep } = this.onlineUsers.get(username) || {};
        if (!sessionReference) return "Offline";
        return currentIp === ipRep ? "ActiveHere" : "ActiveElsewhere";
    }

    static async registerSocket(sessionReference: string, currentIp: string, authToken: string, authData: string, socket: Socket) {
        return this.socketHandlers.get(sessionReference)?.registerNewSocket(currentIp, authToken, authData, socket) || false;
    }

    static disposeSession(username: string) {
        this.socketHandlers.get(this.onlineUsers.get(username)?.sessionReference)?.dispose();
    }

    constructor(username: string, sessionReference: string, ipRep: string, mongoHandler: typeof MongoHandlerCentral.UserHandlerType, sessionCrypto: SessionCrypto) {
        this.#username = username;
        this.#mongoHandler = mongoHandler;
        this.#sessionCrypto = sessionCrypto;
        this.#mongoHandler.subscribe(this.notifyMessage.bind(this));
        this.deleteSelf = () => SocketHandler.socketHandlers.delete(sessionReference);
        SocketHandler.socketHandlers.set(sessionReference, this);
        SocketHandler.onlineUsers.set(username, { sessionReference, ipRep });
    }

    private deregisterSocket() {
        if (this.#socket) {
            console.log(`Disonnected: socket#${this.#socket.id}`);
            this.#disposeRooms.forEach((disposeRoom) => disposeRoom());
            this.#socket.removeAllListeners();
            this.#socket.disconnect();
            this.#socket = null;
        }
    }

    private async registerNewSocket(currentIp: string, authToken: string, authData: string, socket: Socket) {
        if (!this.#username) return false;
        if (SocketHandler.onlineUsers.get(this.#username)?.ipRep !== currentIp) return false;
        const { username, nonce } = await this.#sessionCrypto.decryptVerifyFromBase64(authToken, "Socket Auth") || {};
        if (username !== this.#username || nonce !== authData) return false;
        this.deregisterSocket();
        this.#socket = socket;
        for (let [event] of typedEntries(this.responseMap)) {
            const responseBy = this.responseMap[event].bind(this);
            socket.on(event, async (data: string, resolve) => await this.respond(event, data, responseBy, resolve));
        }
        socket.on("disconnect", this.deregisterSocket.bind(this));
        return true;
    }

    private async request(event: string, data: any, timeout = 0): Promise<any> {
        return await new Promise(async (resolve: (result: any) => void) => {
            this.#socket?.emit(event, await this.#sessionCrypto.signEncryptToBase64(data, event),
                async (response: string) => resolve(response ? await this.#sessionCrypto.decryptVerifyFromBase64(response, event) : {}));
            if (timeout > 0) {
                setTimeout(() => resolve({}), timeout);
            }
        }).catch((err) => console.log(`${err}\n${err.stack}`));
    }

    private async respond(event: SocketClientSideEventsKey, data: string, responseBy: (arg: SocketClientRequestParameters[typeof event]) => Promise<SocketClientRequestReturn[typeof event] | Failure>, resolve: (arg0: string) => void) {
        const encryptResolve = async (response: SocketClientRequestReturn[typeof event] | Failure) => {
            if (!this.#sessionCrypto) resolve(null);
            else resolve(await this.#sessionCrypto.signEncryptToBase64({ payload: response }, event));
        }
        try {
            const decryptedData = await this.#sessionCrypto.decryptVerifyFromBase64(data, event);
            if (!decryptedData) await encryptResolve(failure(ErrorStrings.DecryptFailure));
            else {
                const response = await responseBy(decryptedData);
                if (!response) await encryptResolve(failure(ErrorStrings.ProcessFailed));
                else {
                    encryptResolve(response);
                }
            }
        }
        catch (err) {
            logError(err)
            encryptResolve(failure(ErrorStrings.ProcessFailed, err));
        }
    }

    private async UsernameExists({ username }: Username): Promise<{ exists: boolean }> {
        return { exists: await MongoHandlerCentral.userExists(username) };
    }

    private async RegisterPendingSession(param: Readonly<{ sessionId: string, myAlias: string, otherAlias: string }>): Promise<Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.registerPendingSession(param.sessionId, param.myAlias, param.otherAlias))) return failure(ErrorStrings.ProcessFailed);
        return { reason: null };

    }

    private async UpdateUserData(userData: { x3dhInfo?: UserEncryptedData, chatsData?: UserEncryptedData } & Username): Promise<Failure> {
        if (!this.#username || this.#username !== userData.username) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.updateUserData(userData))) return failure(ErrorStrings.ProcessFailed);
        return { reason: null };
    }

    private async PublishKeyBundles(keyBundles: PublishKeyBundlesRequest): Promise<Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.publishKeyBundles(keyBundles))) return failure(ErrorStrings.ProcessFailed);
        return { reason: null };
    }

    private async RequestKeyBundle({ username }: Username): Promise<RequestKeyBundleResponse | Failure> {
        if (!this.#username || username === this.#username) return failure(ErrorStrings.InvalidRequest);
        const keyBundle = await MongoHandlerCentral.getKeyBundle(username);
        if (!keyBundle) return failure(ErrorStrings.ProcessFailed);
        return { keyBundle };
    }

    private async RoomRequested({ username }: Username): Promise<Failure> {
        if (!this.#username || this.#username === username) return failure(ErrorStrings.InvalidRequest);
        const otherSocketHandler = SocketHandler.socketHandlers.get(SocketHandler.onlineUsers.get(username)?.sessionReference);
        if (!otherSocketHandler) return failure(ErrorStrings.ProcessFailed);
        const response  = await otherSocketHandler.requestRoom(this.#username);
        if (!response?.reason) {
            const halfRoom = halfCreateRoom([this.#username, this.#socket, this.#sessionCrypto]);
            otherSocketHandler.establishRoom(this.#username, halfRoom).then((dispose) => {
                if (dispose) {
                    this.#disposeRooms.push(dispose);
                }
            });
        }
        return response;
    }

    private async requestRoom(username: string): Promise<Failure> {
        if (!this.#username || this.#username === username) return failure(ErrorStrings.InvalidRequest);
        const response: Failure = await this.request(SocketServerSideEvents.RoomRequested, { username });
        if (!response?.reason) {
            this.#openToRoomTemp = { username };
            setTimeout(() => { this.#openToRoomTemp = null; }, 5000);
        }
        return response;
    }

    private async establishRoom(username: string, halfRoom: (roomUser2: RoomUser) => Promise<() => void>): Promise<(() => void)> 
    {
        if (!this.#openToRoomTemp || this.#openToRoomTemp.username !== username) return null;
        return halfRoom([this.#username, this.#socket, this.#sessionCrypto]).then((dispose) => {
            if (dispose) {
                this.#disposeRooms.push(dispose);
            }
            return dispose;
        });
    }

    private async SendChatRequest(chatRequest: ChatRequestHeader): Promise<Failure> {
        if (!this.#username || this.#username === chatRequest.addressedTo) return failure(ErrorStrings.InvalidRequest);
        if (!(await MongoHandlerCentral.depositChatRequest(chatRequest))) return failure(ErrorStrings.ProcessFailed);
        return { reason: null };
    }

    private async SendMessage(message: MessageHeader): Promise<Failure> {
        if (!this.#username || this.#username === message.toAlias) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.depositMessage(message))) return failure(ErrorStrings.ProcessFailed);
        else return { reason: null };
    }

    private async GetAllChats(): Promise<ChatData[] | Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        return await this.#mongoHandler.getAllChats();
    }

    private async GetAllRequests(): Promise<ChatRequestHeader[] | Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        return (await this.#mongoHandler.getAllRequests(this.#username)) || failure(ErrorStrings.ProcessFailed);
    }

    private async GetMessageHeaders({ sessionId, toAlias, fromAlias }: SessionIdentifier & { fromAlias: string }): Promise<MessageHeader[] | Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        return (await this.#mongoHandler.getMessageHeaders(sessionId, toAlias, fromAlias)) || failure(ErrorStrings.ProcessFailed);
    }

    private async GetMessagesByNumber(param: ChatIdentifier & { limit: number, olderThanTimemark: number }): Promise<StoredMessage[] | Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        let { chatId, limit, olderThanTimemark } = param;
        return (await this.#mongoHandler.getMessagesByNumber(chatId, limit, olderThanTimemark)) || failure(ErrorStrings.ProcessFailed);
    }

    private async GetMessagesUptoTimestamp(param: ChatIdentifier & { newerThanTimemark: number, olderThanTimemark: number }): Promise<StoredMessage[] | Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        let { chatId, newerThanTimemark, olderThanTimemark } = param;
        return (await this.#mongoHandler.getMessagesUptoTimestamp(chatId, newerThanTimemark, olderThanTimemark)) || failure(ErrorStrings.ProcessFailed);
    }

    private async GetMessagesUptoId(param: MessageIdentifier & { olderThanTimemark: number }): Promise<StoredMessage[] | Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        let { chatId, hashedId, olderThanTimemark } = param;
        return (await this.#mongoHandler.getMessagesUptoId(chatId, hashedId, olderThanTimemark)) || failure(ErrorStrings.ProcessFailed);
    }

    private async GetMessageById({ chatId, hashedId }: MessageIdentifier): Promise<StoredMessage | Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        return (await this.#mongoHandler.getMessageById(chatId, hashedId)) || failure(ErrorStrings.ProcessFailed);
    }

    private async StoreMessage(message: StoredMessage): Promise<Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.storeMessage(message))) return failure(ErrorStrings.ProcessFailed);
        return { reason: null };
    }

    private async MessageHeaderProcessed({ sessionId, toAlias, headerId }: SessionIdentifier & HeaderIdentifier): Promise<Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.messageHeaderProcessed(toAlias, sessionId, headerId))) return failure(ErrorStrings.ProcessFailed);
        return { reason: null };
    }

    private async CreateChat(chat: ChatData): Promise<Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.createChat(chat))) return failure(ErrorStrings.ProcessFailed);
        return { reason: null };
    }

    private async UpdateChat(chat: Omit<ChatData, "chatDetails" | "exportedChattingSession"> & Partial<ChatData>): Promise<Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.updateChat(chat))) return failure(ErrorStrings.ProcessFailed);
        return { reason: null };
    }

    private async DeleteChatRequest({ headerId }: { headerId: string }): Promise<Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.deleteChatRequest(headerId))) return failure(ErrorStrings.ProcessFailed);
        return { reason: null };
    }

    private async StoreBackup(backup: Backup): Promise<Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.storeBackup(backup))) return failure(ErrorStrings.ProcessFailed);
        return { reason: null };
    }

    private async GetBackupById({ byAlias, sessionId, headerId }: HeaderIdentifier & { byAlias: string }): Promise<Backup | Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        return (await this.#mongoHandler.getBackupById(byAlias, sessionId, headerId)) || failure(ErrorStrings.ProcessFailed);
    }

    private async BackupProcessed({ byAlias, sessionId, headerId }: HeaderIdentifier & { byAlias: string }): Promise<Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.backupProcessed(byAlias, sessionId, headerId))) return failure(ErrorStrings.ProcessFailed);
        return { reason: null };
    }

    private async SendReceipt(receipt: Receipt): Promise<Failure> {
        if (!this.#username || this.#username === receipt.toAlias) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.depositReceipt(receipt))) return failure(ErrorStrings.ProcessFailed);
        return { reason: null };
    }

    private async GetAllReceipts({ toAlias, sessionId }: SessionIdentifier): Promise<Receipt[] | Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        return (await this.#mongoHandler.getAllReceipts(toAlias, sessionId)) || failure(ErrorStrings.ProcessFailed);
    }

    private async ClearAllReceipts({ toAlias, sessionId }: SessionIdentifier): Promise<Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.clearAllReceipts(toAlias, sessionId))) return failure(ErrorStrings.ProcessFailed);
        return { reason: null };
    }

    private async notifyMessage(notify: Notify) {
        if (notify.type === "Request") {
            await this.request(SocketServerSideEvents.ChatRequestReceived, []);
        }
        else if (notify.type === "Message") {
            await this.request(SocketServerSideEvents.MessageReceived, _.pick(notify, "sessionId"));
        }
        else {
            await this.request(SocketServerSideEvents.ReceiptReceived, _.pick(notify, "sessionId"));
        }
    }

    private dispose() {
        this.deregisterSocket();
        this.#mongoHandler.unsubscribe();
        SocketHandler.onlineUsers.delete(this.#username);
        this.deleteSelf();
        this.#sessionCrypto = null;
        this.#username = null;
        this.#mongoHandler = null;
    }
}

type EmitHandler = (data: string, respond: (recv: boolean) => void) => void;

type RoomUser = [string, Socket, SessionCrypto];

async function createRoom([username1, socket1, sessionCrypto1]: RoomUser, [username2, socket2, sessionCrypto2]: RoomUser, messageTimeoutMs = 20000): Promise<() => void> {

    function configureSocket(socketRecv: Socket, cryptoRecv: SessionCrypto, socketForw: Socket, cryptoForw: SessionCrypto, socketEvent: string) {
        const decrypt = (data: string) => cryptoRecv.decryptVerifyFromBase64(data, socketEvent);
        const encrypt = (data: any) => cryptoForw.signEncryptToBase64(data, socketEvent);
        const repackage = async (data: string) => await encrypt(await decrypt(data))
        const forward: EmitHandler =
            messageTimeoutMs > 0
                ? async (data, respond) => {
                    const timeout = setTimeout(() => respond(false), messageTimeoutMs);
                    socketForw.emit(socketEvent, await repackage(data), (response: boolean) => {
                        clearTimeout(timeout);
                        respond(response);
                    });
                }
                : async (data, respond) => socketForw.emit(socketEvent, await repackage(data), respond);
        socketRecv.on(socketEvent, forward);
        return forward;
    }

    function constructRoom() {
        const socket1Event = `${username1} -> ${username2}`;
        const socket2Event = `${username2} -> ${username1}`;
        const forward1 = configureSocket(socket1, sessionCrypto1, socket2, sessionCrypto2, socket1Event);
        const forward2 = configureSocket(socket2, sessionCrypto2, socket1, sessionCrypto1, socket2Event);
        const dispose = () => {
            socket1?.emit(socket2Event, "room-disconnected");
            socket2?.emit(socket1Event, "room-disconnected");
            socket1?.off(socket1Event, forward1);
            socket2?.off(socket2Event, forward2);
        }
        socket1.on("disconnect", dispose);
        socket2.on("disconnect", dispose);
        return dispose;
    }

    function awaitClientRoomReady(socket: Socket, otherUsername: string) {
        return new Promise<boolean>((resolve) => {
            const response = (withUser: string) => {
                if (withUser === otherUsername) {
                    socket.off(SocketServerSideEvents.ClientRoomReady, response);
                    resolve(true);
                }
            };
            socket.on(SocketServerSideEvents.ClientRoomReady, response);
            setTimeout(() => {
                socket.off(SocketServerSideEvents.ClientRoomReady, response);
                resolve(false);
            }, 1000);
        });
    }

    const established1 = awaitClientRoomReady(socket1, username2);
    const established2 = awaitClientRoomReady(socket2, username1);

    socket1.emit(SocketServerSideEvents.ServerRoomReady, username2);
    socket2.emit(SocketServerSideEvents.ServerRoomReady, username1);

    const [est1, est2] = await allSettledResults([established1, established2]);
    if (est1 && est2) {
        const dispose = constructRoom();
        socket1.emit(username2, "confirmed");
        socket2.emit(username1, "confirmed");
        return dispose;
    }
    else {
        return null;
    }
}

function halfCreateRoom(roomUser1: RoomUser, messageTimeoutMs = 20000) {
    return (roomUser2: RoomUser) => createRoom(roomUser1, roomUser2, messageTimeoutMs);
}

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
    sharedKeyBits: CryptoKey,
}>;

type LogInTemp = Temp & Readonly<{ clientReference: string, clientVerifyingKey: CryptoKey }>;

type RegisterChallengeTemp = ChallengeTemp & Omit<SignUpRequest, "clientEphemeralPublic">;

type LogInChallengeTemp = ChallengeTemp & Username & LogInTemp;

type LogInSavedChallengeTemp = Omit<ServerSavedDetails, "authKeyBits"> & LogInTemp;

class AuthHandler {
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

    async userLoginPermitted(username: string, ipRep: string): Promise<{ tries: number, allowsAt: number }> {
        const { tries, allowsAt } = await MongoHandlerCentral.getUserRetries(username, ipRep);
        return allowsAt && allowsAt > Date.now() ? { tries, allowsAt } : { tries: null, allowsAt: null };
    }

    async initiateSignUp(ipRep: string, challengeReference: string, request: SignUpRequest): Promise<SignUpChallenge | Failure> {
        const { username, clientReference, clientEphemeralPublic, clientIdentityVerifyingKey, verifierPoint } = request;
        if (await MongoHandlerCentral.userExists(username)) return failure(ErrorStrings.InvalidRequest);
        const { confirmClient, sharedKeyBits, serverConfirmationCode, verifierEntangled } = await esrp.serverSetupAuthChallenge(verifierPoint, clientEphemeralPublic, "now");
        this.#registerChallengeTemp.set(challengeReference, { ipRep, clientReference, username, clientIdentityVerifyingKey, serverConfirmationCode, confirmClient, verifierPoint, sharedKeyBits, setAt: Date.now() });
        const { #serverIdentityVerifyingKey: serverIdentityVerifyingKey } = this;
        return { verifierEntangled, serverIdentityVerifyingKey };
    }

    async concludeSignUp(ipRep: string, challengeReference: string, sessionReference: string, response: SignUpChallengeResponse): Promise<LogInResponse | Failure> {
        const { clientConfirmationCode, newUserDataSigned, databaseAuthKeyBuffer } = response;
        const registerChallenge = this.#registerChallengeTemp.get(challengeReference);
        if (!registerChallenge || registerChallenge.ipRep !== ipRep) return failure(ErrorStrings.InvalidReference);
        const { username, clientReference, clientIdentityVerifyingKey, serverConfirmationCode, confirmClient, sharedKeyBits, verifierPoint } = registerChallenge;
        try {
            if (!(await confirmClient(clientConfirmationCode))) return failure(ErrorStrings.IncorrectData);
            const clientVerifyingKey = await crypto.importKey(clientIdentityVerifyingKey, "ECDSA", "public", false);
            const newUserData: NewUserData = await crypto.deriveDecryptVerify(sharedKeyBits, newUserDataSigned, Buffer.alloc(32), "New User Data", clientVerifyingKey);
            if (!newUserData) return failure(ErrorStrings.IncorrectData);
            const databaseAuthKey = await crypto.importRaw(databaseAuthKeyBuffer);
            if (await MongoHandlerCentral.createNewUser({ username, clientIdentityVerifyingKey, verifierPoint, ...newUserData }, databaseAuthKey)) {
                const mongoHandler = await MongoHandlerCentral.instantiateUserHandler(username, databaseAuthKey);
                if (!mongoHandler) return failure(ErrorStrings.ProcessFailed);
                const sessionCrypto = new SessionCrypto(clientReference, sharedKeyBits, this.#serverIdentitySigningKey, clientVerifyingKey);
                new SocketHandler(username, sessionReference, ipRep, mongoHandler, sessionCrypto);
                console.log(`Saved user: ${username}`);
                return { serverConfirmationCode };
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
        const { verifierDerive, verifierPoint, databaseAuthKeyDerive, clientIdentityVerifyingKey } = (await MongoHandlerCentral.getLeanUser(username)) ?? {}; 
        if (!verifierDerive) return failure(ErrorStrings.IncorrectData);
        const clientVerifyingKey = await crypto.importKey(clientIdentityVerifyingKey, "ECDSA", "public", false);
        const { confirmClient, sharedKeyBits, serverConfirmationCode, verifierEntangled } = await esrp.serverSetupAuthChallenge(verifierPoint, clientEphemeralPublic, "now");
        this.#logInChallengeTemp.set(challengeReference, { ipRep, serverConfirmationCode, confirmClient, sharedKeyBits, username, clientReference, clientVerifyingKey, setAt: Date.now() });
        return { verifierDerive, verifierEntangled, databaseAuthKeyDerive };
    }

    async concludeLogIn(ipRep: string, challengeReference: string, sessionReference: string, response: LogInChallengeResponse): Promise<LogInResponse | Failure> {
        const { clientConfirmationCode, databaseAuthKeyBuffer } = response;
        const logInChallenge = this.#logInChallengeTemp.get(challengeReference);
        if (!logInChallenge || logInChallenge.ipRep !== ipRep) return failure(ErrorStrings.InvalidReference);
        const { confirmClient, serverConfirmationCode, sharedKeyBits, username, clientVerifyingKey, clientReference } = logInChallenge;
        const databaseAuthKey = await crypto.importRaw(databaseAuthKeyBuffer);
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
            const status = SocketHandler.getUserStatus(username, ipRep);
            if (status === "ActiveElsewhere") return failure(ErrorStrings.InvalidRequest, "Already Logged In Elsewhere");
            else if (status === "ActiveHere") SocketHandler.disposeSession(username);
            const mongoHandler = await MongoHandlerCentral.instantiateUserHandler(username, databaseAuthKey);
            if (!mongoHandler) return failure(ErrorStrings.ProcessFailed);
            const sessionCrypto = new SessionCrypto(clientReference, sharedKeyBits, this.#serverIdentitySigningKey, clientVerifyingKey);
            new SocketHandler(username, sessionReference, ipRep, mongoHandler, sessionCrypto);
            return { serverConfirmationCode };
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
        const { clientIdentityVerifyingKey } = (await MongoHandlerCentral.getLeanUser(username)) ?? {}; 
        const clientVerifyingKey = await crypto.importKey(clientIdentityVerifyingKey, "ECDSA", "public", false);
        this.#logInSavedTemp.set(username, { username, ipRep, clientReference, coreKeyBits, laterConfirmation, clientVerifyingKey, setAt: Date.now() });
        return { username, authKeyBits };
    }

    async concludeLogInSaved(ipRep: string, sessionReference: string, { username, clientConfirmationCode, databaseAuthKeyBuffer }: LogInChallengeResponse & Username): Promise<LogInSavedResponse | Failure> {
        const logInSaved = this.#logInSavedTemp.get(username)
        if (!logInSaved || logInSaved.ipRep !== ipRep) return failure(ErrorStrings.InvalidReference);
        const { laterConfirmation, coreKeyBits, clientVerifyingKey, clientReference } = logInSaved;
        const databaseAuthKey = await crypto.importRaw(databaseAuthKeyBuffer);
        const { clientConfirmationData, serverConfirmationCode, sharedSecret } = laterConfirmation;
        try {
            if (!(await esrp.processConfirmationData(sharedSecret, clientConfirmationCode, clientConfirmationData))) return failure(ErrorStrings.IncorrectData);
            const sharedKeyBits = await esrp.getSharedKeyBits(sharedSecret);
            const status = SocketHandler.getUserStatus(username, ipRep);
            if (status === "ActiveElsewhere") return failure(ErrorStrings.InvalidRequest, "Already Logged In Elsewhere");
            else if (status === "ActiveHere") SocketHandler.disposeSession(username);
            const mongoHandler = await MongoHandlerCentral.instantiateUserHandler(username, databaseAuthKey);
            if (mongoHandler) return failure(ErrorStrings.ProcessFailed);
            const sessionCrypto = new SessionCrypto(clientReference, sharedKeyBits, this.#serverIdentitySigningKey, clientVerifyingKey);
            new SocketHandler(username, sessionReference, ipRep, mongoHandler, sessionCrypto);
            return { serverConfirmationCode, coreKeyBits };
        }
        catch (err) {
            logError(err)
            return failure(ErrorStrings.ProcessFailed, err);
        }
    }

    async savePassword(username: string, ipRep: string, saveToken: string, request: SavePasswordRequest): Promise<{ verifierDerive: PasswordDeriveInfo, verifierEntangled: Buffer } | Failure> {
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

function parseIpRepresentation(address: string) {
    if (!ipaddr.isValid(address)) return null;
    const ipv4_or_ipv6 = ipaddr.parse(address);
    const ipv6 =
        "octets" in ipv4_or_ipv6
            ? ipv4_or_ipv6.toIPv4MappedAddress()
            : ipv4_or_ipv6;
    return Buffer.from(ipv6.toByteArray()).toString("base64");
}

export function parseIpReadable(ipRep: string) {
    const ipv6 = new ipaddr.IPv6(Array.from(Buffer.from(ipRep, "base64")));
    return ipv6.isIPv4MappedAddress()
        ? ipv6.toIPv4Address().toString()
        : ipv6.toRFC5952String();
}

async function writeJsHash() {
    const file = await fsPromises.readFile(`..\\client\\public\\main.js`, { flag: "r" });
    const hash = await crypto.digestToBase64("SHA-256", file);
    await fsPromises.writeFile(`..\\client\\public\\prvJsHash.txt`, hash);
}

async function watchForJsHashChange() {
    const watcher = fsPromises.watch(`..\\client\\public\\main.js`);
    for await (const { eventType } of watcher) {
        if (eventType === "change") {
            await writeJsHash();
        }
    }
}

async function main() {
    
    const PORT = 8080;
    const mongoUrl = "mongodb://localhost:27017/chatapp";
    const httpsOptions: ServerOptions = {
        key: fs.readFileSync(`..\\certificates\\key.pem`),
        cert: fs.readFileSync(`..\\certificates\\cert.pem`)
    }
    const corsOptions: CorsOptions = { origin: /.*/, methods: ["GET", "POST"], exposedHeaders: ["set-cookie"], allowedHeaders: ["content-type"], credentials: true };
    const { getRandomString, getRandomVector } = randomFunctions();

    try {
        config({ debug: true, path: "./config.env" });
    }
    catch (e) {
        logError(e);
        console.log("Could not load config.env");
    }

    await writeJsHash(); 
    watchForJsHashChange();
    MongoHandlerCentral.connect(mongoUrl);
    const { signingKey, verifyingKey, cookieSign } = await MongoHandlerCentral.setupIdentity();
    const authHandler = AuthHandler.initiate(signingKey, verifyingKey);
    const cookieParserMiddle = cookieParser(cookieSign);
    const cookieOptions: CookieOptions = { httpOnly: true, secure: true, sameSite: "strict", signed: true };
    const app = express().use(cors(corsOptions)).use(cookieParserMiddle).use(express.json());
    const httpsServer = createServer(httpsOptions, app);
    
    
    const io = new SocketServer(httpsServer, {
        cors: {
            origin: /.*/,
            methods: ["GET", "POST"],
            credentials: true
        }
    });

    app.get("/userLogInPermitted", async (req, res) => {
        const ipRep = parseIpRepresentation(req.socket.remoteAddress);
        const { payload } = req.body;
        if (!ipRep || payload !== "string") return res.status(400).end();
        const { username } = deserialize(fromBase64(payload));
        const result = await authHandler.userLoginPermitted(username, ipRep);
        return res.json({ payload: serialize(result).toString("base64") }).status(200).end();
    })
    
    app.get("/initiateSignUp", async (req, res) => {
        const ipRep = parseIpRepresentation(req.socket.remoteAddress);
        const { payload } = req.body;
        if (!ipRep || payload !== "string") return res.status(400).end();
        const request: SignUpRequest = deserialize(fromBase64(payload));
        const challengeReference = getRandomString(16, "base64");
        const result = await authHandler.initiateSignUp(ipRep, challengeReference, request);
        res.json({ payload: serialize(result).toString("base64") });
        if (!("reason" in result)) {
            res.cookie("signUpInit", { challengeReference }, { ...cookieOptions, maxAge: 5000 });
        }
        return res.status(200).end();
    });
    
    app.connect("/concludeSignUp", async (req, res) => {
        const ipRep = parseIpRepresentation(req.socket.remoteAddress);
        const { challengeReference } = req.signedCookies?.signUpInit || {};
        res.clearCookie("signUpInit");
        const { payload } = req.body;
        if (!ipRep || payload !== "string") return res.status(400).end();
        const request: SignUpChallengeResponse= deserialize(fromBase64(payload));
        const sessionReference = getRandomString(16, "base64");
        const result = await authHandler.concludeSignUp(ipRep, challengeReference, sessionReference, request);
        res.json({ payload: serialize(result).toString("base64") });
        if (!("reason" in result)) {
            res.cookie("authenticated", { sessionReference }, cookieOptions);
        }
        return res.status(200).end();
    });
    
    app.get("/initiateLogIn", async (req, res) => {
        const ipRep = parseIpRepresentation(req.socket.remoteAddress);
        const { payload } = req.body;
        if (!ipRep || payload !== "string") return res.status(400).end();
        const request: LogInRequest = deserialize(fromBase64(payload));
        const challengeReference = getRandomString(16, "base64");
        const result = await authHandler.initiateLogIn(ipRep, challengeReference, request);
        res.json({ payload: serialize(result).toString("base64") });
        if (!("reason" in result)) {
            res.cookie("logInInit", { challengeReference }, { ...cookieOptions, maxAge: 5000 });
        }
        return res.status(200).end();
    });
    
    app.connect("/concludeLogIn", async (req, res) => {
        const ipRep = parseIpRepresentation(req.socket.remoteAddress);
        const { challengeReference } = req.signedCookies?.logInInit || {};
        res.clearCookie("logInInit");
        const { payload } = req.body;
        if (!ipRep || payload !== "string") return res.status(400).end();
        const request: LogInChallengeResponse= deserialize(fromBase64(payload));
        const sessionReference = getRandomString(16, "base64");
        const result = await authHandler.concludeLogIn(ipRep, challengeReference, sessionReference, request);
        res.json({ payload: serialize(result).toString("base64") });
        if (!("reason" in result)) {
            res.cookie("authenticated", { sessionReference }, cookieOptions);
        }
        return res.status(200).end();
    });
    
    app.get("/initiateLogInSaved", async (req, res) => {
        const ipRep = parseIpRepresentation(req.socket.remoteAddress);
        const { saveToken } = req.signedCookies?.passwordSaved || {};
        const { payload } = req.body;
        if (!ipRep || payload !== "string") return res.status(400).end();
        const request: LogInSavedRequest = deserialize(fromBase64(payload));
        const challengeReference = getRandomString(16, "base64");
        const result = await authHandler.InitiateLogInSaved(ipRep, saveToken, request)
        res.json({ payload: serialize("reason" in result ? result : _.pick(result, "authKeyBits")).toString("base64") });
        if (!("reason" in result)) {
            const { username } = result;
            res.cookie("logInSavedInit", { username }, { ...cookieOptions, maxAge: 5000 });
        }
        return res.status(200).end();
    });
    
    app.connect("/concludeLogInSaved", async (req, res) => {
        const ipRep = parseIpRepresentation(req.socket.remoteAddress);
        const { username } = req.signedCookies?.logInSavedInit || {};
        res.clearCookie("logInSavedInit");
        const { payload } = req.body;
        if (!ipRep || payload !== "string") return res.status(400).end();
        const request: LogInChallengeResponse= deserialize(fromBase64(payload));
        const sessionReference = getRandomString(16, "base64");
        const result = await authHandler.concludeLogInSaved(ipRep, sessionReference, { ...request, username });
        res.json({ payload: serialize(result).toString("base64") });
        if (!("reason" in result)) {
            res.cookie("authenticated", { sessionReference }, cookieOptions);
        }
        return res.status(200).end();
    });
    
    app.post("/savePassword", async (req, res) => {
        const ipRep = parseIpRepresentation(req.socket.remoteAddress);
        const { sessionReference } = req.signedCookies?.authenticated || {};
        const { payload } = req.body || {};
        if (!ipRep || payload !== "string") return res.status(400).end();
        const request: SavePasswordRequest = crypto.deserialize(fromBase64(payload));
        const username = SocketHandler.getUsername(sessionReference);
        const saveToken = getRandomString(16, "base64");
        const result = await authHandler.savePassword(username, ipRep, saveToken, request);
        res.json({ payload: serialize(result).toString("base64") });
        if (!("reason" in result)) {
            res.cookie("passwordSaved", { saveToken }, { ...cookieOptions, maxAge: 10 * 24 * 60 * 60 * 1000, expires: DateTime.now().plus({ days: 10 }).toJSDate() });
        }
        return res.status(200).end();
    });
    
    app.get("/authNonce", async (req, res) => {
        const ipRep = parseIpRepresentation(req.socket.remoteAddress);
        const { sessionReference } = req.signedCookies?.authenticated || {};
        if (!ipRep || !sessionReference) return res.status(400).end();
        const nonce = getRandomVector(64).toString("base64");
        const payload = Buffer.concat([fromBase64(ipRep), fromBase64(sessionReference), fromBase64(nonce)]).toString("base64");
        res.json({ payload });
        res.cookie("authNonce", { nonce }, { ...cookieOptions, maxAge: 5000 });
        return res.status(200).end();
    });
    
    io.use((socket: Socket, next) => {
        cookieParserMiddle(socket.request as Request, ((socket.request as any).res || {}) as Response, next as NextFunction)
    });

    io.on("connection", async (socket) => {
        try {
            const ipRep = parseIpRepresentation(socket.request.socket.remoteAddress);
            const { authenticated: { sessionReference }, authNonce: { nonce } } = socket.request.signedCookies;
            const { authToken } = socket.handshake.auth ?? {};
            const authData = Buffer.concat([fromBase64(ipRep), fromBase64(sessionReference), fromBase64(nonce)]).toString("base64");
            console.log(`Socket connected from ip ${parseIpReadable(ipRep)} with sessionReference ${sessionReference}.`);
            if (!(await SocketHandler.registerSocket(sessionReference, ipRep, authToken, authData, socket))) {
                socket.disconnect(true);
            }
        }
        catch (err) {
            socket.disconnect(true);
        }
    });

    httpsServer.listen(PORT, () => console.log(`listening on *:${PORT}`));
}

main();