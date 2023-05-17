import _ from "lodash";
import { DateTime } from "luxon";
import { config } from "./node_modules/dotenv";
import { ServerOptions, createServer } from "node:https";
import fs, { promises as fsPromises } from "node:fs";
import session, { Session, CookieOptions as SessionCookieOptions, SessionOptions } from "express-session";
import cookieParser from "cookie-parser";
import ConnectMongoDBSession from "connect-mongodb-session";
import express, { Request, Response, NextFunction, CookieOptions } from "express";
import cors, { CorsOptions } from "cors";
import * as ipaddr from "ipaddr.js";
import { Server as SocketServer, Socket } from "socket.io";
import { Buffer } from "./node_modules/buffer";
import { SessionCrypto } from "../shared/sessionCrypto";
import * as crypto from "../shared/cryptoOperator";
import { serialize } from "../shared/cryptoOperator";
import { failure, Failure, ErrorStrings, Username, PublishKeyBundlesRequest, RequestKeyBundleResponse, SocketClientSideEvents, PasswordDeriveInfo, randomFunctions, SavedDetails, ChatRequestHeader, KeyBundle, UserEncryptedData, MessageHeader, StoredMessage, ChatData, SocketClientSideEventsKey, SocketServerSideEvents, SocketClientRequestParameters, SocketClientRequestReturn, typedEntries, RegisterNewUserRequest, RegisterNewUserChallenge, RegisterNewUserChallengeResponse, NewUserData, LogInRequest, LogInChallenge, UserData, LogInChallengeResponse } from "../shared/commonTypes";
import { MongoHandlerCentral, MongoUserHandler, bufferReplaceForMongo } from "./MongoHandler";
import * as esrp from "../shared/ellipticSRP";

try {
    config({ debug: true, path: "./config.env" });
}
catch (e) {
    logError(e);
    console.log("Could not load config.env");
}

const { getRandomVector, getRandomString } = randomFunctions();
const sleep = (timeInMillis: number) => new Promise((resolve, _) => { setTimeout(resolve, timeInMillis); });
const PORT = 8080;

declare module "http" {
    interface IncomingMessage {
        session: Session;
        cookies: any;
    }
}

type ResponseMap = Readonly<{
    [E in SocketClientSideEventsKey]: (arg: SocketClientRequestParameters[E]) => Promise<SocketClientRequestReturn[E] | Failure>
}>

type ChallengeTemp = Readonly<{ challengeReference: string, confirmCode: (confirmationCode: Buffer) => Promise<boolean>, sharedKeyBits: CryptoKey }>;

type RegisterChallengeTemp = ChallengeTemp & Omit<RegisterNewUserRequest, "clientEphemeralPublicHex">;

type LogInChallengeTemp = ChallengeTemp & Username & { userData: UserData, clientVerifyingKey: CryptoKey };

class SocketHandler {
    private readonly responseMap: ResponseMap = {
        [SocketClientSideEvents.UsernameExists]: this.UsernameExists,
        [SocketClientSideEvents.UserLoginPermitted]: this.UserLoginPermitted,
        [SocketClientSideEvents.RegisterNewUser]: this.RegisterNewUser,
        [SocketClientSideEvents.ConcludeRegisterNewUser]: this.ConcludeRegisterNewUser,
        [SocketClientSideEvents.LogIn]: this.LogIn,
        [SocketClientSideEvents.ConcludeLogIn]: this.ConcludeLogIn,
        [SocketClientSideEvents.SetSavedDetails]: this.SetSavedDetails,
        [SocketClientSideEvents.GetSavedDetails]: this.GetSavedDetails,
        [SocketClientSideEvents.PublishKeyBundles]: this.PublishKeyBundles,
        [SocketClientSideEvents.UpdateX3DHUser]: this.UpdateX3DHUser,
        [SocketClientSideEvents.RequestKeyBundle]: this.RequestKeyBundle,
        [SocketClientSideEvents.GetAllChats]: this.GetAllChats,
        [SocketClientSideEvents.GetAllRequests]: this.GetAllRequests,
        [SocketClientSideEvents.GetUnprocessedMessages]: this.GetUnprocessedMessages,
        [SocketClientSideEvents.GetMessagesByNumber]: this.GetMessagesByNumber,
        [SocketClientSideEvents.GetMessagesUptoTimestamp]: this.GetMessagesUptoTimestamp,
        [SocketClientSideEvents.GetMessagesUptoId]: this.GetMessagesUptoId,
        [SocketClientSideEvents.GetMessageById]: this.GetMessageById,
        [SocketClientSideEvents.StoreMessage]: this.StoreMessage,
        [SocketClientSideEvents.CreateChat]: this.CreateChat,
        [SocketClientSideEvents.UpdateChat]: this.UpdateChat,
        [SocketClientSideEvents.SendChatRequest]: this.SendChatRequest,
        [SocketClientSideEvents.SendMessage]: this.SendMessage,
        [SocketClientSideEvents.DeleteChatRequest]: this.DeleteChatRequest,
        [SocketClientSideEvents.LogOut]: this.LogOut,
        [SocketClientSideEvents.RequestRoom]: this.RoomRequested,
        [SocketClientSideEvents.TerminateCurrentSession]: this.TerminateCurrentSession
    };
    #saveToken: string;
    #session: Session;
    #sessionReference: string;
    #sessionCrypto: SessionCrypto;
    #socket: Socket;
    #socketId: string;
    #registerChallengeTemp: RegisterChallengeTemp;
    #logInChallengeTemp: LogInChallengeTemp;
    #newAuthReference: { authRef: string, uname: string, pInfo: PasswordDeriveInfo, hSaltAuth: Buffer, hSaltEncrypt: Buffer };
    #currentAuthReference: { authRef: string, originalData: Buffer, signature: Buffer, hSalt: Buffer };
    #username: string;
    #mongoHandler: MongoUserHandler;
    #accessedBundles = new Map<string, KeyBundle>();
    #disposeRooms: (() => void)[] = [];
    #ipRep: string;

    constructor(socket: Socket, session: Session, sessionReference: string, ipRep: string, sessionKeyBits: Buffer, sessionKeyBitsImported: CryptoKey, sessionSigningKey: CryptoKey, sessionVerifyingKey: CryptoKey, saveToken?: string, resuming = false) {
        this.#ipRep = ipRep;
        this.#saveToken = saveToken;
        this.#session = session;
        this.#sessionReference = sessionReference;
        this.#sessionCrypto = new SessionCrypto(sessionReference, sessionKeyBitsImported, sessionSigningKey, sessionVerifyingKey);
        this.registerNewSocket(socket);
        console.log(`Connected: socket#${socket.id} with session reference ${sessionReference}`);
        console.log(`Session ${session.id} begun.`);
    }

    setSaveToken(sessionReference: string, currentIp: string, saveToken: string) {
        if (sessionReference === this.#sessionReference && currentIp === this.#ipRep && (!this.#saveToken || !saveToken)) {
            if (!this.#saveToken && saveToken) {
                this.#saveToken = saveToken;
            }
            else if (this.#saveToken && !saveToken) {
                MongoHandlerCentral.getSavedDetails(saveToken).then(() => {
                    this.#saveToken = null;
                })
            }
            return true;
        }
        return false;
    }

    private deregisterSocket() {
        if (this.#socketId) {
            socketHandlers.delete(this.#socketId);
            onlineUsers.forEach((value, key, map) => {
                if (value === this.#socketId) {
                    map.delete(key);
                }
            })
            this.#socketId = null;
            this.#socket?.removeAllListeners();
            this.#socket?.disconnect();
            this.#socket = null;
        }
    }

    private registerNewSocket(socket: Socket) {
        if (!this.#sessionReference) {
            return;
        }
        this.deregisterSocket();
        this.#socket = socket;
        this.#socketId = socket.id;
        socketHandlers.set(socket.id, this);
        for (let [event] of typedEntries(this.responseMap)) {
            const responseBy = this.responseMap[event].bind(this);
            socket.on(event, async (data: string, resolve) => await this.respond(event, data, responseBy, resolve));
        }
        socket.on(SocketClientSideEvents.TerminateCurrentSession, (_, respond) => {
            this.TerminateCurrentSession();
            respond();
        });
        socket.on("disconnect", this.onSocketDisconnect.bind(this));
    }

    private onSocketDisconnect() {
        if (!this.#socketId) {
            return;
        }
        this.#disposeRooms.forEach((disposeRoom) => disposeRoom());
        this.deregisterSocket();
        const sessionId = this.#session.id;
        console.log(`Disonnected: socket#${this.#socketId}`);
    }

    private async request(event: string, data: any, timeout = 0): Promise<any> {
        return await new Promise(async (resolve: (result: any) => void) => {
            this.#socket.emit(event, await this.#sessionCrypto.signEncryptToBase64(data, event),
                async (response: string) => resolve(response ? await this.#sessionCrypto.decryptVerifyFromBase64(response, event) : {}));
            if (timeout > 0) {
                setTimeout(() => resolve({}), timeout);
            }
        }).catch((err) => console.log(`${err}\n${err.stack}`));
    }

    private async respond(event: SocketClientSideEventsKey, data: string, responseBy: (arg: SocketClientRequestParameters[typeof event]) => Promise<SocketClientRequestReturn[typeof event] | Failure>, resolve: (arg0: string) => void) {
        const encryptResolve = async (response: SocketClientRequestReturn[typeof event] | Failure) => {
            if (!this.#sessionCrypto) resolve(null);
            else resolve(await this.#sessionCrypto.signEncryptToBase64({ payload: response, fileHash: await jsHash }, event));
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

    private async UserLoginPermitted({ username }: Username): Promise<{ tries: number, allowsAt: number }> {
        const { tries, allowsAt } = await MongoHandlerCentral.getUserRetries(username);
        return allowsAt && allowsAt > Date.now() ? { tries, allowsAt } : { tries: null, allowsAt: null };
    }

    private async UsernameExists({ username }: Username): Promise<{ exists: boolean }> {
        return { exists: !!(await MongoHandlerCentral.getUser(username)) };
    }

    private awaitSwitchSessionCrypto(sharedKeyBits: CryptoKey, clientVerifyingKey: CryptoKey): Promise<boolean> {
        return new Promise<boolean>((resolve) => {
            const stop = () => {
                this.#socket.off("SwitchSessionCrypto", switchSessionCrypto);
                resolve(false);
                this.TerminateCurrentSession();
            };
            let timeout: NodeJS.Timeout = null;
            const switchSessionCrypto = async (ref: string, respond: (success: boolean) => void) => {
                if (ref === this.#sessionReference) {
                    this.#sessionCrypto = new SessionCrypto(this.#sessionReference, sharedKeyBits, (await identityKeys).signingKey, clientVerifyingKey);
                    clearTimeout(timeout);
                    respond(true);
                    resolve(true);
                }
                else {
                    respond(false);
                    stop();
                }
            };
            timeout = setTimeout(stop, 2000);
            this.#socket.once("SwitchSessionCrypto", switchSessionCrypto);
        });
    }

    private async RegisterNewUser(request: RegisterNewUserRequest): Promise<RegisterNewUserChallenge | Failure> {
        if (this.#username) return failure(ErrorStrings.InvalidRequest);
        const { username, verifierSalt, clientEphemeralPublicHex, clientIdentityVerifyingKey, verifierPointHex } = request;
        if ((await this.UsernameExists({ username })).exists) return failure(ErrorStrings.IncorrectData);
        const { confirmCode, sharedKeyBits, serverConfirmationCode, verifierEntangledHex } = await esrp.serverSetupAuthChallenge(verifierPointHex, clientEphemeralPublicHex);
        const challengeReference = getRandomString().slice(0, 10);
        this.#registerChallengeTemp = { challengeReference, username, clientIdentityVerifyingKey, confirmCode, verifierSalt, verifierPointHex, sharedKeyBits };
        this.#logInChallengeTemp = null;
        setTimeout(() => { this.#registerChallengeTemp = null; }, 5000);
        const serverIdentityVerifyingKey = Buffer.from((await identityKeys).verifyingKey, "base64");
        return { challengeReference, verifierEntangledHex, serverConfirmationCode, serverIdentityVerifyingKey };
    }

    private async ConcludeRegisterNewUser(response: RegisterNewUserChallengeResponse): Promise<Failure> {
        if (this.#username) return failure(ErrorStrings.InvalidRequest);
        const { challengeReference, clientConfirmationCode, newUserDataSigned } = response;
        if (!this.#registerChallengeTemp || this.#registerChallengeTemp.challengeReference !== challengeReference) return failure(ErrorStrings.InvalidReference);
        const { username, clientIdentityVerifyingKey, confirmCode, verifierSalt, sharedKeyBits, verifierPointHex } = this.#registerChallengeTemp;
        try {
            if (!(await confirmCode(clientConfirmationCode))) return failure(ErrorStrings.IncorrectData);
            const clientVerifyingKey = await crypto.importKey(clientIdentityVerifyingKey, "ECDSA", "public", false);
            const newUserData: NewUserData = await crypto.deriveDecryptVerify(sharedKeyBits, newUserDataSigned, Buffer.alloc(32), "New User Data", clientVerifyingKey);
            if (!newUserData) return failure(ErrorStrings.IncorrectData);
            if (await MongoHandlerCentral.createNewUser({ username, clientIdentityVerifyingKey, verifierPointHex, verifierSalt, ...newUserData })) {
                console.log(`Saved user: ${username}`);
                this.awaitSwitchSessionCrypto(sharedKeyBits, clientVerifyingKey).then(async (success) => {
                    if (success) {
                        this.#username = username;
                        this.#mongoHandler = await MongoUserHandler.createHandler(username, this.notifyMessage.bind(this));
                    }
                });
                return { reason: null };
            }
            return failure(ErrorStrings.ProcessFailed);
        }
        catch (err) {
            logError(err)
            return failure(ErrorStrings.ProcessFailed, err);
        }
    }

    private async LogIn(request: LogInRequest): Promise<LogInChallenge | Failure> {
        if (this.#username) return failure(ErrorStrings.InvalidRequest);
        const { username, clientEphemeralPublicHex } = request;
        const { tries, allowsAt } = await MongoHandlerCentral.getUserRetries(username);
        if (allowsAt && allowsAt > Date.now()) {
            return failure(ErrorStrings.TooManyWrongTries, { tries, allowsAt });
        }
        const { clientIdentitySigningKey, clientIdentityVerifyingKey, verifierSalt, verifierPointHex, encryptionBase, profileData, x3dhInfo, serverIdentityVerifyingKey } = (await MongoHandlerCentral.getLeanUser(username)) ?? {}; 
        if (!verifierSalt) return failure(ErrorStrings.IncorrectData);
        const clientVerifyingKey = await crypto.importKey(clientIdentityVerifyingKey, "ECDSA", "public", false);
        const { confirmCode, sharedKeyBits, serverConfirmationCode, verifierEntangledHex } = await esrp.serverSetupAuthChallenge(verifierPointHex, clientEphemeralPublicHex);
        const challengeReference = getRandomString().slice(0, 10);
        const userData = { clientIdentitySigningKey, encryptionBase, profileData, serverIdentityVerifyingKey, x3dhInfo };
        this.#logInChallengeTemp = { challengeReference, confirmCode, sharedKeyBits, username, clientVerifyingKey, userData };
        this.#registerChallengeTemp = null;
        setTimeout(() => { this.#logInChallengeTemp = null; }, 5000);
        return { challengeReference, serverConfirmationCode, verifierSalt, verifierEntangledHex };
    }

    private async ConcludeLogIn(response: LogInChallengeResponse): Promise<UserData | Failure> {
        if (this.#username) return failure(ErrorStrings.InvalidRequest);
        const { challengeReference, clientConfirmationCode } = response;
        if (!this.#logInChallengeTemp || this.#logInChallengeTemp.challengeReference !== challengeReference) return failure(ErrorStrings.InvalidReference);
        const { confirmCode, sharedKeyBits, username, clientVerifyingKey, userData } = this.#logInChallengeTemp;
        try {
            if (!(await confirmCode(clientConfirmationCode))) {
                let { tries } = await MongoHandlerCentral.getUserRetries(username);
                tries ??= 0;
                tries++;
                if (tries >= 5) {
                    const forbidInterval = 1000 * (30 + 15 * (tries - 5));
                    const allowsAt = Date.now() + forbidInterval;
                    await MongoHandlerCentral.updateUserRetries(username, allowsAt, tries);
                    setTimeout(async () => {
                        await MongoHandlerCentral.updateUserRetries(username, null);
                    }, forbidInterval);
                    return failure(ErrorStrings.TooManyWrongTries, { tries, allowsAt });
                }
                await MongoHandlerCentral.updateUserRetries(username, null, tries);
                return failure(ErrorStrings.IncorrectPassword, { tries });   
            }
            this.awaitSwitchSessionCrypto(sharedKeyBits, clientVerifyingKey).then(async (success) => {
                if (success) {
                    this.#username = username;
                    this.#mongoHandler = await MongoUserHandler.createHandler(username, this.notifyMessage.bind(this));
                    console.log(`User ${username} logged in.`);
                }
            });
            return userData;
        }
        catch (err) {
            logError(err)
            return failure(ErrorStrings.ProcessFailed, err);
        }
    }

    private async UpdateX3DHUser({ username, x3dhInfo }: { x3dhInfo: UserEncryptedData } & Username): Promise<Failure> {
        if (!this.#username || this.#username !== username) return failure(ErrorStrings.InvalidRequest);
        const user = await MongoHandlerCentral.getUser(username);
        user.x3dhInfo = bufferReplaceForMongo(x3dhInfo);
        try {
            const savedUser = await user.save();
            return savedUser !== user ? failure(ErrorStrings.ProcessFailed) : { reason: null };
        }
        catch (err) {
            logError(err);
            return failure(ErrorStrings.ProcessFailed, err);
        }
    }

    private async SetSavedDetails(request: Omit<SavedDetails, "ipRep" | "ipRead">): Promise<Failure> {
        if (request.saveToken !== this.#saveToken) return failure(ErrorStrings.IncorrectData);
        const ipRep = this.#ipRep;
        const ipRead = parseIpReadable(ipRep);
        const success = await MongoHandlerCentral.setSavedDetails({ ...request, ipRep, ipRead });
        return success ? { reason: null } : failure(ErrorStrings.ProcessFailed);
    }

    private async GetSavedDetails({ saveToken }: { saveToken: string }): Promise<SavedDetails | Failure> {
        if (saveToken !== this.#saveToken) return failure(ErrorStrings.IncorrectData);
        this.#saveToken = null;
        const savedDetails = await MongoHandlerCentral.getSavedDetails(saveToken);
        if (!savedDetails || savedDetails.ipRep !== this.#ipRep) return failure(savedDetails ? ErrorStrings.ProcessFailed : ErrorStrings.InvalidRequest)
        return savedDetails;
    }

    private validateKeyBundleOwner(keyBundles: PublishKeyBundlesRequest, username: string): boolean {
        let { defaultKeyBundle, oneTimeKeyBundles } = keyBundles;
        return [defaultKeyBundle.owner, ...oneTimeKeyBundles.map((kb) => kb.owner)].every((owner) => owner === username);
    }

    private async PublishKeyBundles(keyBundles: PublishKeyBundlesRequest): Promise<Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        if (!this.validateKeyBundleOwner(keyBundles, this.#username)) {
            return failure(ErrorStrings.IncorrectData);
        }
        const user = await MongoHandlerCentral.getUser(this.#username);
        if (!user) {
            return failure(ErrorStrings.ProcessFailed);
        }
        let { defaultKeyBundle, oneTimeKeyBundles } = keyBundles;
        user.keyBundles.defaultKeyBundle = bufferReplaceForMongo(defaultKeyBundle);
        oneTimeKeyBundles = Array.from(oneTimeKeyBundles.map((kb: any) => bufferReplaceForMongo(kb)));
        const leanUser = await MongoHandlerCentral.getLeanUser(this.#username);
        const oldOneTimes = Array.from(leanUser.keyBundles.oneTimeKeyBundles ?? []).map((okb: any) => okb.identifier);
        const dontAdd = [...(leanUser.accessedKeyBundles ?? []), ...oldOneTimes];
        for (const oneTime of oneTimeKeyBundles) {
            if (!dontAdd.includes(oneTime.identifier)) {
                user.keyBundles.oneTimeKeyBundles.push(oneTime);
            }
        }
        if (!leanUser.accessedKeyBundles) {
            user.accessedKeyBundles = [];
        }
        try {
            if (user !== await user.save()) return failure(ErrorStrings.ProcessFailed);
            return { reason: null };
        }
        catch (err) {
            logError(err);
            return failure(ErrorStrings.ProcessFailed, err);
        }
    }

    private async RequestKeyBundle({ username }: Username): Promise<RequestKeyBundleResponse | Failure> {
        if (!this.#username || username === this.#username) return failure(ErrorStrings.InvalidRequest);
        const accessedKeyBundle = this.#accessedBundles.get(username);
        if (!!accessedKeyBundle) {
            return { keyBundle: accessedKeyBundle };
        }
        const otherUser = await MongoHandlerCentral.getUser(username);
        if (!otherUser) return failure(ErrorStrings.IncorrectData);
        let keyBundle;
        let saveRequired = false;
        const { oneTimeKeyBundles, defaultKeyBundle } = otherUser?.keyBundles;
        if ((oneTimeKeyBundles ?? []).length > 0) {
            keyBundle = getPOJO(oneTimeKeyBundles.pop());
            saveRequired = true;
        }
        else if (defaultKeyBundle) {
            keyBundle = getPOJO(defaultKeyBundle);
        }
        if (!keyBundle) return failure(ErrorStrings.ProcessFailed);
        if (saveRequired) {
            otherUser.accessedKeyBundles.push(keyBundle.identifier);
        }
        try {
            if (saveRequired && otherUser !== await otherUser.save()) return failure(ErrorStrings.ProcessFailed);
            return { keyBundle };
        }
        catch (err) {
            logError(err);
            return failure(ErrorStrings.ProcessFailed, err);
        }
    }

    private async RoomRequested({ username }: Username): Promise<Failure> {
        if (!this.#username || this.#username === username) return failure(ErrorStrings.InvalidRequest);
        const otherSocketHandler = socketHandlers.get(onlineUsers.get(username));
        if (!otherSocketHandler) return failure(ErrorStrings.ProcessFailed);
        const halfRoom = halfCreateRoom([this.#username, this.#socket, this.#sessionCrypto]);
        const dispose = await otherSocketHandler.requestRoom(this.#username, halfRoom);
        if ("reason" in dispose) {
            return dispose;
        }
        this.#disposeRooms.push(dispose);
        return { reason: null };
    }

    private async requestRoom(username: string, halfRoom: (roomUser2: RoomUser) => Promise<() => void>): Promise<(() => void) | Failure> {
        if (!this.#username || this.#username === username) return failure(ErrorStrings.InvalidRequest);
        const response: Failure = await this.request(SocketServerSideEvents.RoomRequested, { username });
        if ("reason" in response) {
            return response;
        }
        const dispose = await halfRoom([this.#username, this.#socket, this.#sessionCrypto]);
        if (dispose) {
            this.#disposeRooms.push(dispose);
            return dispose;
        }
        else {
            return null;
        }
    }

    private async SendChatRequest(chatRequest: ChatRequestHeader): Promise<Failure> {
        if (!this.#username || this.#username === chatRequest.addressedTo) return failure(ErrorStrings.InvalidRequest);
        if (!(await MongoHandlerCentral.depositChatRequest(chatRequest))) return failure(ErrorStrings.ProcessFailed);
        return { reason: null };
    }

    private async SendMessage(message: MessageHeader): Promise<Failure> {
        if (!this.#username || this.#username === message.addressedTo) return failure(ErrorStrings.InvalidRequest);
        if (!(await MongoHandlerCentral.depositMessage(message))) return failure(ErrorStrings.ProcessFailed);
        return { reason: null };
    }

    private async GetAllChats(): Promise<ChatData[] | Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        return await this.#mongoHandler.getAllChats();
    }

    private async GetAllRequests(): Promise<ChatRequestHeader[] | Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        return await this.#mongoHandler.getAllRequests();
    }

    private async GetUnprocessedMessages(param: { sessionId: string }): Promise<MessageHeader[] | Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        return await this.#mongoHandler.getUnprocessedMessages(param.sessionId);
    }

    private async GetMessagesByNumber(param: { sessionId: string, limit: number, olderThan?: number }): Promise<StoredMessage[] | Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        let { sessionId, limit, olderThan } = param;
        olderThan ||= Date.now();
        return await this.#mongoHandler.getMessagesByNumber(sessionId, limit, olderThan);
    }

    private async GetMessagesUptoTimestamp(param: { sessionId: string, newerThan: number, olderThan?: number }): Promise<StoredMessage[] | Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        let { sessionId, newerThan, olderThan } = param;
        olderThan ||= Date.now();
        return await this.#mongoHandler.getMessagesUptoTimestamp(sessionId, newerThan, olderThan);
    }

    private async GetMessagesUptoId(param: { sessionId: string, messageId: string, olderThan?: number }): Promise<StoredMessage[] | Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        let { sessionId, messageId, olderThan } = param;
        olderThan ||= Date.now();
        return await this.#mongoHandler.getMessagesUptoId(sessionId, messageId, olderThan);
    }

    private async GetMessageById(param: { sessionId: string, messageId: string }): Promise<StoredMessage | Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        let { sessionId, messageId } = param;
        return await this.#mongoHandler.getMessageById(sessionId, messageId);
    }

    private async StoreMessage(message: StoredMessage): Promise<Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.storeMessage(message))) return failure(ErrorStrings.ProcessFailed);
        return { reason: null };
    }

    private async CreateChat(chat: ChatData) {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.createChat(chat))) return failure(ErrorStrings.ProcessFailed);
        return { reason: null };
    }

    private async UpdateChat(chat: ChatData) {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.updateChat(chat))) return failure(ErrorStrings.ProcessFailed);
        return { reason: null };
    }

    private async DeleteChatRequest(param: { sessionId: string }) {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        const success = await this.#mongoHandler.deleteChatRequest(param.sessionId);
        return success ? { reason: null } : failure(ErrorStrings.ProcessFailed);
    }

    private async notifyMessage(message: MessageHeader | ChatRequestHeader) {
        if (message.addressedTo !== this.#username) return;
        if ("messageBody" in message) {
            await this.request(SocketServerSideEvents.MessageReceived, message);
        }
        else if ("initialMessage" in message) {
            await this.request(SocketServerSideEvents.ChatRequestReceived, message);
        }
    }

    private async LogOut({ username }: Username): Promise<Failure> {
        if (this.#username !== username) return failure(ErrorStrings.InvalidRequest);
        this.dispose();
    }

    private async TerminateCurrentSession(): Promise<Failure> {
        this.#session?.destroy((err) => {
            console.log(`Session ${this.#session.id} destroyed.`);
            this.dispose();
        });
        return { reason: null }
    }

    private dispose() {
        console.log(`Disposing connection: session reference ${this.#sessionReference}`);
        this.deregisterSocket();
        MongoHandlerCentral.deregisterUserHandler(this.#username);
        this.#session = null;
        this.#sessionReference = null;
        this.#sessionCrypto = null;
        this.#newAuthReference = null;
        this.#currentAuthReference = null;
        this.#username = null;
    }
}

type EmitHandler = (data: string, respond: (recv: boolean) => void) => void;

type RoomUser = [string, Socket, SessionCrypto];

async function createRoom([username1, socket1, sessionCrypto1]: RoomUser, [username2, socket2, sessionCrypto2]: RoomUser, messageTimeoutMs = 20000): Promise<() => void> {

    function configureSocket(socketRecv: Socket, socketForw: Socket, sessionCrypto: SessionCrypto, socketEvent: string) {
        const forward: EmitHandler =
            messageTimeoutMs > 0
                ? (data, respond) => {
                    const timeout = setTimeout(() => respond(false), messageTimeoutMs);
                    socketForw.emit(socketEvent, serialize(sessionCrypto.decryptVerifyFromBase64(data, socketEvent)).toString("base64"), (response: boolean) => {
                        clearTimeout(timeout);
                        respond(response);
                    });
                }
                : (data, respond) => socketForw.emit(socketEvent, data, respond);
        socketRecv.on(socketEvent, forward);
        return forward;
    }

    function constructRoom() {
        const socket1Event = `${username1} -> ${username2}`;
        const socket2Event = `${username2} -> ${username1}`;
        const forward1 = configureSocket(socket1, socket2, sessionCrypto1, socket1Event);
        const forward2 = configureSocket(socket2, socket1, sessionCrypto2, socket2Event);
        return () => {
            socket1?.emit(socket2Event, "disconnected");
            socket2?.emit(socket1Event, "disconnected");
            socket1?.off(socket1Event, forward1);
            socket2?.off(socket2Event, forward2);
        }
    }

    function awaitEstablished(socket: Socket, otherUsername: string) {
        return new Promise<boolean>((resolve) => {
            const response = (withUser: string) => {
                if (withUser === otherUsername) {
                    socket.off(SocketServerSideEvents.RoomEstablished, response);
                    resolve(true);
                }
            };
            socket.on(SocketServerSideEvents.RoomEstablished, response);
            setTimeout(() => {
                socket.off(SocketServerSideEvents.RoomEstablished, response);
                resolve(false);
            }, 20000);
        });
    }

    const established1 = await awaitEstablished(socket1, username1);
    const established2 = await awaitEstablished(socket2, username1);
    return Promise.all([established1, established2]).then(([est1, est2]) => {
        if (est1 && est2) {
            const room = constructRoom();
            socket1.emit(username2, "confirmed");
            socket2.emit(username1, "confirmed");
            return room;
        }
        else {
            return null;
        }
    });
}

function halfCreateRoom(roomUser1: RoomUser, messageTimeoutMs = 20000) {
    return (roomUser2: RoomUser) => createRoom(roomUser1, roomUser2, messageTimeoutMs);
}

function getPOJO(mongObj: any): any {
    if (!mongObj) {
        return null;
    }
    if (!isDoc(mongObj)) {
        return mongObj;
    }
    if (typeof mongObj === "object") {
        mongObj = "_doc" in mongObj ? mongObj._doc : mongObj;
        if (Object.getPrototypeOf(mongObj).constructor.name === "Buffer" || ArrayBuffer.isView(mongObj)) {
            return Buffer.from(mongObj);
        }
        if (mongObj instanceof Array) {
            return mongObj.map(o => getPOJO(o));
        }
        type Keyed = { [key: string]: any };
        const newObj: Keyed = {};
        for (const [key, value] of Object.entries(mongObj)) {
            if (!key.startsWith("$") && !key.startsWith("_")) {
                if (value === null) {
                    newObj[key] = null;
                }
                else if (value === undefined) {
                    newObj[key] = undefined;
                }
                else if (Object.getPrototypeOf(value).constructor.name === "Buffer" || ArrayBuffer.isView(value)) {
                    newObj[key] = Buffer.from(value as Buffer);
                }
                else if (isDoc(value)) {
                    newObj[key] = getPOJO(value);
                }
                else {
                    newObj[key] = value;
                }
            }
        }
        mongObj = newObj;
    }
    return mongObj;
}

function isDoc(docObj: any): boolean {
    if (!docObj) {
        return false;
    }
    if (typeof docObj === "object") {
        if ("_doc" in docObj) {
            return true;
        }
        if (Object.getPrototypeOf(docObj).constructor.name === "Buffer" || ArrayBuffer.isView(docObj)) {
            return false;
        }
        if (docObj instanceof Array) {
            return docObj.some(v => isDoc(v));
        }
        return Object.entries(docObj).some(([_, v]) => isDoc(v));
    }
    return false;
}

function logError(err: any): void {
    const message = err.message;
    const stack = err.stack;
    if (message || stack) {
        console.log(`${message}${stack}`);
    }
    else {
        console.log(`${err}`);
    }
}

function fromBase64(data: string) {
    return Buffer.from(data, "base64");
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

function parseIpReadable(ipRep: string) {
    const ipv6 = new ipaddr.IPv6(Array.from(Buffer.from(ipRep, "base64")));
    return ipv6.isIPv4MappedAddress()
        ? ipv6.toIPv4Address().toString()
        : ipv6.toRFC5952String();
}

let abortController: AbortController = new AbortController();
async function hashCalculator() {
    try {
        const buffer = await fsPromises.readFile(`..\\client\\public\\main.js`, { flag: "r", signal: abortController.signal });
        const hash = await crypto.digest("SHA-256", buffer);
        return hash;
    }
    catch (err) {
        logError(err);
        return null;
    }
};

let jsHash = hashCalculator();
async function watchForFileHashChange() {
    const watcher = fsPromises.watch(`..\\client\\public\\main.js`);
    for await (const { eventType } of watcher) {
        if (eventType === "change") {
            const prevController = abortController;
            abortController = new AbortController();
            jsHash = hashCalculator();
            prevController.abort();
        }
    }
}
watchForFileHashChange();

const mongoUrl = "mongodb://localhost:27017/chatapp";
MongoHandlerCentral.connect(mongoUrl);
const MongoDBStore = ConnectMongoDBSession(session);
const store = new MongoDBStore({ uri: mongoUrl, collection: "user_sessions" });
const httpsOptions: ServerOptions = {
    key: fs.readFileSync(`..\\certificates\\key.pem`),
    cert: fs.readFileSync(`..\\certificates\\cert.pem`)
}
const cookie: SessionCookieOptions = { httpOnly: true, sameSite: "strict", secure: false }
const sessionOptions: SessionOptions = {
    secret: getRandomString(),
    cookie,
    genid(req) {
        return `${getRandomString()}-${req.socket.remoteAddress}`;
    },
    name: "chatapp.session.id",
    resave: true,
    store,
    unset: "destroy",
    saveUninitialized: true
};
const corsOptions: CorsOptions = { origin: /.*/, methods: ["GET", "POST"], exposedHeaders: ["set-cookie"], allowedHeaders: ["content-type"], credentials: true };
const sessionMiddleware = session(sessionOptions);
const cookieParserMiddle = cookieParser();
const app = express().use(cors(corsOptions)).use(sessionMiddleware).use(cookieParserMiddle).use(express.json());
const httpsServer = createServer(httpsOptions, app);
const socketHandlers = new Map<string, SocketHandler>();
const onlineUsers = new Map<string, string>();
const registeredKeys = new Map<string, { ipRep: string, sessionId: string, sessionKeyBits: Buffer, signingKey: CryptoKey, clientVerifyingKey: CryptoKey, timeout: NodeJS.Timeout }>();

async function getIdentityKeys() {
    const { privateKey: signingKey, publicKey } = await MongoHandlerCentral.setupIdentity();
    const verifyingKey = (await crypto.exportKey(publicKey)).toString("base64");
    return { signingKey, verifyingKey };
}

const identityKeys = getIdentityKeys();

const io = new SocketServer(httpsServer, {
    cors: {
        origin: /.*/,
        methods: ["GET", "POST"],
        credentials: true
    }
});

app.post("/setSaveToken", (req, res) => {
    const { saveToken, socketId, sessionReference } = req.body || {};
    const { socket: { remoteAddress } } = req;
    const currentIp = parseIpRepresentation(remoteAddress);
    if (!currentIp) {
        res.status(400).end();
        return;
    }
    if (saveToken === "0") {
        if (socketHandlers.get(socketId)?.setSaveToken(sessionReference, currentIp, null)) {
            res.clearCookie("saveToken").status(200).end();
        }
        else {
            res.status(403).end();
        }
        return;
    }
    if (socketHandlers.get(socketId)?.setSaveToken(sessionReference, currentIp, saveToken)) {
        const cookieOptions: CookieOptions = { httpOnly: true, secure: true, maxAge: 10 * 24 * 60 * 60 * 1000, sameSite: "strict", expires: DateTime.now().plus({ days: 10 }).toJSDate() };
        res.cookie("saveToken", { saveToken }, cookieOptions).status(200).end();
    }
    else {
        res.status(403).end();
    }
});

app.get("/verifyingKey", async (req, res) => {
    const { verifyingKey } = await identityKeys;
    res.json({ verifyingKey }).status(200).end();
});

app.post("/registerKeys", async (req, res) => {
    const { sessionReference, publicDHKey, publicVerifyingKey } = req.body;
    const { socket: { remoteAddress }, session } = req;
    session.save();
    const ipRep = parseIpRepresentation(remoteAddress);
    if (!ipRep) {
        res.status(400).end();
        return;
    }
    const sessionId = session.id;
    console.log(`Keys registered from ip ${parseIpReadable(ipRep)} with sessionReference ${sessionReference} and sessionID ${sessionId}`);
    const { signingKey, verifyingKey } = await identityKeys;
    const { privateKey, publicKey } = await crypto.generateKeyPair("ECDH");
    const clientVerifyingKey = await crypto.importKey(fromBase64(publicVerifyingKey), "ECDSA", "public", true);
    const clientPublicKey = await crypto.importKey(fromBase64(publicDHKey), "ECDH", "public", true);
    const sessionKeyBits = await crypto.deriveSymmetricBits(privateKey, clientPublicKey, 512);
    const serverPublicKey = (await crypto.exportKey(publicKey)).toString("base64");
    const timeout = setTimeout(() => registeredKeys.delete(sessionReference), 10_000);
    registeredKeys.set(sessionReference, { ipRep, sessionId, sessionKeyBits, signingKey, clientVerifyingKey, timeout });
    res.json({ serverPublicKey, verifyingKey, sessionId }).status(200).end();
});

store.on("error", (err) => logError(err));
httpsServer.listen(PORT, () => console.log(`listening on *:${PORT}`));
io.use((socket: Socket, next) => {
    sessionMiddleware(socket.request as Request, ((socket.request as any).res || {}) as Response, next as NextFunction)
});
io.use((socket: Socket, next) => {
    cookieParserMiddle(socket.request as Request, ((socket.request as any).res || {}) as Response, next as NextFunction)
});
io.on("connection", async (socket) => {
    const fileHashLocal = await jsHash;
    const { session, cookies: { saveToken: saveTokenCookie }, socket: { remoteAddress } } = socket.request;
    const currentIp = parseIpRepresentation(remoteAddress);
    const { saveToken } = saveTokenCookie ?? {};
    let { sessionReference, sessionSigned, fileHash } = socket.handshake.auth ?? {};
    const rejectConnection = async () => {
        console.log(`Rejecting sessionReference ${sessionReference}`);
        socket.emit(SocketServerSideEvents.CompleteHandshake, "", fileHashLocal, () => { });
        await sleep(5000);
        socket.disconnect(true);
    }
    if (!currentIp || !sessionReference || !sessionSigned || fileHash !== fileHashLocal) {
        await rejectConnection();
        return;
    }
    console.log(`Socket connected from ip ${parseIpReadable(currentIp)} with sessionReference ${sessionReference} and session.id ${session.id} and sessionID ${(socket.request as any).sessionID}`);
    if (!registeredKeys.has(sessionReference)) {
        await rejectConnection();
        return;
    }
    const { ipRep, sessionId, sessionKeyBits, clientVerifyingKey, signingKey, timeout } = registeredKeys.get(sessionReference);
    clearTimeout(timeout);
    registeredKeys.delete(sessionReference);
    if (ipRep !== currentIp || sessionId !== session.id || !(await crypto.verify(fromBase64(sessionReference), fromBase64(sessionSigned), clientVerifyingKey))) {
        await rejectConnection();
        return;
    }
    const success = await new Promise((resolve) => {
        socket.emit(SocketServerSideEvents.CompleteHandshake, sessionReference, fileHashLocal, resolve);
        setTimeout(() => resolve(false), 30000);
    })
    if (!success) {
        socket.disconnect(true);
        return;
    }
    const sessionKeyBitsImported = await crypto.importRaw(sessionKeyBits);
    new SocketHandler(socket, session, sessionReference, ipRep, sessionKeyBits, sessionKeyBitsImported, signingKey, clientVerifyingKey, saveToken);
});