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
import { failure, Failure, ErrorStrings, Username, AuthSetupKey, AuthInfo, RegisterNewUserRequest, InitiateAuthenticationResponse, SignInResponse, PublishKeyBundlesRequest, RequestKeyBundleResponse, SocketClientSideEvents, PasswordDeriveInfo, UserAuthInfo, randomFunctions, SavedDetails, AuthSetupKeyData, NewUserData, ConcludeAuthenticationRequest, AuthChangeData, ChatRequestHeader, KeyBundle, UserEncryptedData, MessageHeader, StoredMessage, ChatData, SocketClientSideEventsKey, SocketServerSideEvents, SocketClientRequestParameters, SocketClientRequestReturn, typedEntries } from "../shared/commonTypes";
import { MongoHandlerCentral, MongoUserHandler, bufferReplaceForMongo } from "./MongoHandler";

try {
  config({ debug: true, path:"./config.env" });
}
catch(e) {
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

class SocketHandler {
  private readonly responseMap: ResponseMap = {
    [SocketClientSideEvents.UsernameExists]: this.usernameExists,
    [SocketClientSideEvents.UserLoginPermitted]: this.userLoginPermitted, 
    [SocketClientSideEvents.RequestAuthSetupKey]: this.generateAuthSetupKey, 
    [SocketClientSideEvents.RegisterNewUser]: this.registerNewUser, 
    [SocketClientSideEvents.InitiateAuthentication]: this.initiateAuthentication, 
    [SocketClientSideEvents.ConcludeAuthentication]: this.concludeAuthentication,
    [SocketClientSideEvents.SetSavedDetails]: this.setSavedDetails,
    [SocketClientSideEvents.GetSavedDetails]: this.getSavedDetails,
    [SocketClientSideEvents.PublishKeyBundles]: this.publishKeyBundles,
    [SocketClientSideEvents.UpdateX3DHUser]: this.updateX3DHUser,
    [SocketClientSideEvents.RequestKeyBundle]: this.requestKeyBundle,
    [SocketClientSideEvents.GetAllChats]: this.getAllChats,
    [SocketClientSideEvents.GetAllRequests]: this.getAllRequests,
    [SocketClientSideEvents.GetUnprocessedMessages]: this.getUnprocessedMessages,
    [SocketClientSideEvents.GetMessagesByNumber]: this.getMessagesByNumber,
    [SocketClientSideEvents.GetMessagesUptoTimestamp]: this.getMessagesUptoTimestamp,
    [SocketClientSideEvents.GetMessagesUptoId]: this.getMessagesUptoId,
    [SocketClientSideEvents.GetMessageById]: this.getMessageById,
    [SocketClientSideEvents.StoreMessage]: this.storeMessage,
    [SocketClientSideEvents.CreateChat]: this.createChat,
    [SocketClientSideEvents.UpdateChat]: this.updateChat,
    [SocketClientSideEvents.SendChatRequest]: this.sendChatRequest,
    [SocketClientSideEvents.SendMessage]: this.sendMessage,
    [SocketClientSideEvents.DeleteChatRequest]: this.deleteChatRequest,
    [SocketClientSideEvents.LogOut]: this.logOut,
    [SocketClientSideEvents.RequestRoom]: this.roomRequested,
    [SocketClientSideEvents.TerminateCurrentSession]: this.terminateCurrentSession
  };
  #saveToken: string;
  #session: Session;
  #sessionReference: string;
  #sessionCrypto: SessionCrypto;
  #socket: Socket;
  #socketId: string;
  #newAuthReference: { authRef: string, uname: string, pInfo: PasswordDeriveInfo, hSaltAuth: Buffer, hSaltEncrypt: Buffer };
  #currentAuthReference: { authRef: string, originalData: Buffer, signedData: Buffer, hSalt: Buffer };
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
        }})
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
      this.terminateCurrentSession();
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
      async (response: string) => resolve(response ? await this.#sessionCrypto.decryptVerifyFromBase64(response, event): {}));
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
    catch(err) {
      logError(err)
      encryptResolve(failure(ErrorStrings.ProcessFailed, err));
    }
  }

  private async userLoginPermitted({ username }: Username): Promise<{ tries: number, allowsAt: number }> {
    const { tries, allowsAt } = await MongoHandlerCentral.getUserRetries(username);
    return allowsAt && allowsAt > Date.now() ? { tries, allowsAt } : { tries: null, allowsAt: null };
  }

  private async usernameExists({ username }: Username): Promise<{ exists: boolean }> {
    return { exists: !!(await MongoHandlerCentral.getUser(username)) };
  }

  private async generateAuthSetupKey({ username }: Username, newUser = true): Promise<AuthSetupKey | Failure> {
    const { exists } = await this.usernameExists({ username });
    if ((newUser && exists) || this.#username) {
      return failure(ErrorStrings.InvalidRequest);
    }
    const newAuthReference = getRandomString();
    const hSaltAuth = getRandomVector(32);
    const hSaltEncrypt = getRandomVector(32);
    const pSalt = getRandomVector(64);
    const iterSeed = _.random(1, 999);
    const pInfo: PasswordDeriveInfo = { pSalt, iterSeed };
    const keyData: AuthSetupKeyData = { newAuthReference, pInfo, hSaltAuth, hSaltEncrypt };
    const [userKeyBits, userPInfo] = await crypto.deriveMasterKeyBits(username);
    const hSalt = getRandomVector(32);
    const dInfo = { hSalt, ...userPInfo };
    const authKeyData = await crypto.deriveSignEncrypt(userKeyBits, keyData, hSalt, "AuthKeyData");
    this.#newAuthReference = { authRef: newAuthReference, uname: username, pInfo, hSaltEncrypt, hSaltAuth };
    setTimeout(() => { this.#newAuthReference = null; }, 120000);
    return { authKeyData, dInfo };
  }

  private async processAuth(request: RegisterNewUserRequest): Promise<UserAuthInfo & NewUserData | Failure>;
  private async processAuth(request: ConcludeAuthenticationRequest): Promise<UserAuthInfo & Username | Failure>;
  private async processAuth(request: RegisterNewUserRequest | ConcludeAuthenticationRequest): Promise<UserAuthInfo & (NewUserData | Username) | Failure> {
    if (!this.#newAuthReference) return failure(ErrorStrings.InvalidRequest);
    const { authRef, uname, pInfo, hSaltAuth, hSaltEncrypt } = this.#newAuthReference;
    this.#newAuthReference = null;
    if (authRef !== request.newAuthReference) return failure(ErrorStrings.IncorrectData);
    const authBits = "newAuthBits" in request ? request.newAuthBits : request.currentAuthBits;
    const { ciphertext, signature } = "newUserData" in request ? request.newUserData : request.authChangeData;
    const purpose = "newUserData" in request ? "NewUser" : "AuthChange";
    const verifyingKey = await crypto.deriveMACKey(authBits, hSaltAuth, `${purpose}Verify`, 512);
    const result: NewUserData | AuthChangeData = await crypto.deriveDecryptVerify(authBits, ciphertext, hSaltEncrypt, purpose, signature, verifyingKey);
    if (result.username !== uname) return failure(ErrorStrings.IncorrectData);
    if ("currentAuthReference" in request) {
      const verified = await this.verifyCurrentAuth(request.currentAuthReference, authBits);
      if ("reason" in verified) return verified;
      if (!verified.passwordCorrect) return failure(ErrorStrings.IncorrectPassword, result.username);
    }
    const newAuthBits = "newAuthBits" in request ? request.newAuthBits : (result as AuthChangeData).newAuthBits;
    const hSalt = getRandomVector(32);
    const originalData = getRandomVector(100);
    const dInfo = { hSalt, ...pInfo };
    const verifyKey = await crypto.deriveMACKey(newAuthBits, hSalt, "AuthSign", 512);
    const signedData = await crypto.sign(originalData, verifyKey);
    const { username, serverProof, encryptionBase } = result;
    const authInfo: UserAuthInfo = { dInfo, originalData, signedData, serverProof, encryptionBase };
    if ("x3dhInfo" in result) {
      const { userDetails, x3dhInfo, keyBundles } = result;
      return { username, userDetails, x3dhInfo, keyBundles, ...authInfo };
    }
    return { ...authInfo, username };
  }

  private async verifyCurrentAuth(currentAuthReference: string, currentAuthBits: Buffer): Promise<{ passwordCorrect: boolean } | Failure> {
    if (!this.#currentAuthReference) return failure(ErrorStrings.InvalidRequest);
    const { authRef, originalData, signedData, hSalt } = this.#currentAuthReference;
    this.#currentAuthReference = null;
    if (authRef !== currentAuthReference) return failure(ErrorStrings.IncorrectData);
    const verifyKey = await crypto.deriveMACKey(currentAuthBits, hSalt, "AuthSign", 512);
    const passwordCorrect = await crypto.verify(signedData, originalData, verifyKey);
    return { passwordCorrect };
  }

  private async registerNewUser(request: RegisterNewUserRequest): Promise<Failure> {
    const newAuthCreated = await this.processAuth(request);
    if ("reason" in newAuthCreated) return newAuthCreated;
    const { username, userDetails, x3dhInfo, keyBundles, ...authInfo } = newAuthCreated;
    if (!this.validateKeyBundleOwner(keyBundles, username)) {
      return failure(ErrorStrings.IncorrectData);
    }
    try {
      if (await MongoHandlerCentral.createNewUser({ username, userDetails, authInfo, x3dhInfo, keyBundles })) {
        console.log(`Saved user: ${username}`);
        this.#username = username;
        this.#mongoHandler = await MongoUserHandler.createHandler(username, this.notifyMessage.bind(this));
        return { reason: null };
      }
      return failure(ErrorStrings.ProcessFailed);
    }
    catch(err) {
      logError(err)
      return failure(ErrorStrings.ProcessFailed, err);
    }
  }

  private async initiateAuthentication({ username }: Username): Promise<InitiateAuthenticationResponse | Failure> {
    if (this.#username) return failure(ErrorStrings.InvalidRequest);
    const { tries, allowsAt } = await MongoHandlerCentral.getUserRetries(username);
    if (allowsAt && allowsAt > Date.now()) {
      return failure(ErrorStrings.TooManyWrongTries, { tries, allowsAt });
    }
    let { authInfo : { encryptionBase, originalData, signedData, serverProof, dInfo: { hSalt, ...pInfo } } } = (await MongoHandlerCentral.getLeanUser(username)) ?? {};
    if (!originalData) return failure(ErrorStrings.IncorrectData);
    const currentAuthReference = getRandomString();
    this.#currentAuthReference = { authRef: currentAuthReference, originalData, signedData, hSalt };
    const authInfo: AuthInfo = { encryptionBase, serverProof, pInfo };
    const newAuthSetup = await this.generateAuthSetupKey({ username }, false);
    if ("reason" in newAuthSetup) return newAuthSetup
    setTimeout(() => { this.#currentAuthReference = null; }, 120000);
    return { currentAuthReference, authInfo, newAuthSetup };
  }

  private async concludeAuthentication(request: ConcludeAuthenticationRequest): Promise<SignInResponse | Failure> {
    const processAuthResult = await this.processAuth(request);
    if ("reason" in processAuthResult) {
      if (processAuthResult.reason === ErrorStrings.IncorrectPassword) {
        const username: string = processAuthResult.details;
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
      return processAuthResult;
    }
    const { username, ...userAuthInfo } = processAuthResult;        
    await MongoHandlerCentral.updateUserRetries(username, null, 0);
    const user = await MongoHandlerCentral.getUser(username);
    if (!user) return failure(ErrorStrings.ProcessFailed);
    const { userDetails, x3dhInfo }: SignInResponse = await MongoHandlerCentral.getLeanUser(username);
    user.authInfo = bufferReplaceForMongo(userAuthInfo);
    try {
      const savedUser = await user.save();
      if (savedUser === user) {
        this.#username = username;
        this.#mongoHandler = await MongoUserHandler.createHandler(username, this.notifyMessage.bind(this));
        onlineUsers.set(username, this.#socketId);
        return { userDetails, x3dhInfo };
      }
      return failure(ErrorStrings.ProcessFailed);
    }
    catch(err) {
      logError(err);
      return failure(ErrorStrings.ProcessFailed, err);
    }
  }

  private async updateX3DHUser({ username, x3dhInfo }: { x3dhInfo: UserEncryptedData } & Username): Promise<Failure> {
    if (!this.#username || this.#username !== username) return failure(ErrorStrings.InvalidRequest);
    const user = await MongoHandlerCentral.getUser(username);
    user.x3dhInfo = bufferReplaceForMongo(x3dhInfo);
    try {
      const savedUser = await user.save();
      return savedUser !== user ? failure(ErrorStrings.ProcessFailed) : { reason: null };
    }
    catch(err) {
      logError(err);
      return failure(ErrorStrings.ProcessFailed, err);
    }
  }

  private async setSavedDetails(request: Omit<SavedDetails, "ipRep" | "ipRead">) : Promise<Failure> {
    if (request.saveToken !== this.#saveToken) return failure(ErrorStrings.IncorrectData);
    const ipRep = this.#ipRep;
    const ipRead = parseIpReadable(ipRep);
    const success = await MongoHandlerCentral.setSavedDetails({ ...request, ipRep, ipRead });
    return success ? { reason: null } : failure(ErrorStrings.ProcessFailed);
  }

  private async getSavedDetails({ saveToken }: { saveToken: string }): Promise<SavedDetails | Failure> {
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

  private async publishKeyBundles(keyBundles: PublishKeyBundlesRequest): Promise<Failure>  {
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
    catch(err) {
      logError(err);
      return failure(ErrorStrings.ProcessFailed, err);
    }
  }
  
  private async requestKeyBundle({ username }: Username): Promise<RequestKeyBundleResponse | Failure> {
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
    catch(err) {
      logError(err);
      return failure(ErrorStrings.ProcessFailed, err);
    }
  }

  private async roomRequested({ username }: Username): Promise<Failure> {
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

  private async sendChatRequest(chatRequest: ChatRequestHeader): Promise<Failure> {
    if (!this.#username || this.#username === chatRequest.addressedTo) return failure(ErrorStrings.InvalidRequest);
    if (!(await MongoHandlerCentral.depositChatRequest(chatRequest))) return failure(ErrorStrings.ProcessFailed);
    return { reason: null };
  }

  private async sendMessage(message: MessageHeader): Promise<Failure> {
    if (!this.#username || this.#username === message.addressedTo) return failure(ErrorStrings.InvalidRequest);
    if (!(await MongoHandlerCentral.depositMessage(message))) return failure(ErrorStrings.ProcessFailed);
    return { reason: null };
  }

  private async getAllChats(): Promise<ChatData[]| Failure> {
    if (!this.#username) return failure(ErrorStrings.InvalidRequest);
    return await this.#mongoHandler.getAllChats();
  }

  private async getAllRequests(): Promise<ChatRequestHeader[] | Failure> {
    if (!this.#username) return failure(ErrorStrings.InvalidRequest);
    return await this.#mongoHandler.getAllRequests();
  }

  private async getUnprocessedMessages(param: { sessionId: string }): Promise<MessageHeader[] | Failure> {
    if (!this.#username) return failure(ErrorStrings.InvalidRequest);
    return await this.#mongoHandler.getUnprocessedMessages(param.sessionId);
  }

  private async getMessagesByNumber(param: { sessionId: string, limit: number, olderThan?: number }): Promise<StoredMessage[] | Failure> {
    if (!this.#username) return failure(ErrorStrings.InvalidRequest);
    let { sessionId, limit, olderThan } = param;
    olderThan ||= Date.now();
    return await this.#mongoHandler.getMessagesByNumber(sessionId, limit, olderThan);
  }

  private async getMessagesUptoTimestamp(param: { sessionId: string, newerThan: number, olderThan?: number }): Promise<StoredMessage[] | Failure> {
    if (!this.#username) return failure(ErrorStrings.InvalidRequest);
    let { sessionId, newerThan, olderThan } = param;
    olderThan ||= Date.now();
    return await this.#mongoHandler.getMessagesUptoTimestamp(sessionId, newerThan, olderThan);
  }

  private async getMessagesUptoId(param: { sessionId: string, messageId: string, olderThan?: number }): Promise<StoredMessage[] | Failure> {
    if (!this.#username) return failure(ErrorStrings.InvalidRequest);
    let { sessionId, messageId, olderThan } = param;
    olderThan ||= Date.now();
    return await this.#mongoHandler.getMessagesUptoId(sessionId, messageId, olderThan);
  }

  private async getMessageById(param: { sessionId: string, messageId: string }): Promise<StoredMessage | Failure> {
    if (!this.#username) return failure(ErrorStrings.InvalidRequest);
    let { sessionId, messageId } = param;
    return await this.#mongoHandler.getMessageById(sessionId, messageId);
  }

  private async storeMessage(message: StoredMessage): Promise<Failure> {
    if (!this.#username) return failure(ErrorStrings.InvalidRequest);
    if (!(await this.#mongoHandler.storeMessage(message))) return failure(ErrorStrings.ProcessFailed);
    return { reason: null };
  }

  private async createChat(chat: ChatData) {
    if (!this.#username) return failure(ErrorStrings.InvalidRequest);
    if (!(await this.#mongoHandler.createChat(chat))) return failure(ErrorStrings.ProcessFailed);
    return { reason: null };
  }

  private async updateChat(chat: ChatData) {
    if (!this.#username) return failure(ErrorStrings.InvalidRequest);
    if (!(await this.#mongoHandler.updateChat(chat))) return failure(ErrorStrings.ProcessFailed);
    return { reason: null };
  }

  private async deleteChatRequest(param: { sessionId: string }) {
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

  private async logOut({ username }: Username): Promise<Failure> {
    if (this.#username !== username) return failure(ErrorStrings.InvalidRequest);
    this.dispose();
  }

  private async terminateCurrentSession(): Promise<Failure> {
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
        } };
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
    return Object.entries(docObj).some(([_,v]) => isDoc(v));
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
  catch(err) {
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
const httpsOptions : ServerOptions = {
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
const registeredKeys = new Map<string, { ipRep:string, sessionId: string, sessionKeyBits: Buffer, signingKey: CryptoKey, clientVerifyingKey: CryptoKey, timeout: NodeJS.Timeout }>();

async function regenerateSigningKeys() {
  async function generateKeys(): Promise<[string, CryptoKey, string]> {
    const { privateKey, publicKey } = await crypto.generateKeyPair("ECDSA");
    const exportedPublicKey = (await crypto.exportKey(publicKey)).toString("base64");
    const version = getRandomString().slice(0, 8);
    return [version, privateKey, exportedPublicKey];
  }

  let [version, signingKey, verifyingKey] = await generateKeys();
  setInterval(async () => [version, signingKey, verifyingKey] = await generateKeys(), 1_800_000);
  return () => ({ version, signingKey, verifyingKey });
}

const getCurrentKeys = regenerateSigningKeys();

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
    const cookieOptions : CookieOptions = { httpOnly: true, secure: true, maxAge: 10*24*60*60*1000, sameSite: "strict", expires: DateTime.now().plus({ days: 10 }).toJSDate() };
    res.cookie("saveToken", { saveToken }, cookieOptions).status(200).end();
  }
  else {
    res.status(403).end();
  }
});

app.get("/currentVerifyingKey", async (req, res) => {
  const { version, verifyingKey } = (await getCurrentKeys)();
  res.json({ version, verifyingKey }).status(200).end();
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
  const { signingKey, verifyingKey } = (await getCurrentKeys)();
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
  sessionMiddleware(socket.request as Request, ((socket.request as any).res || {}) as Response, next as NextFunction) });
io.use((socket: Socket, next) => { 
  cookieParserMiddle(socket.request as Request, ((socket.request as any).res || {}) as Response, next as NextFunction) });
io.on("connection", async (socket) => {
  const fileHashLocal = await jsHash;
  const { session, cookies: { saveToken: saveTokenCookie }, socket: { remoteAddress } } = socket.request;
  const currentIp = parseIpRepresentation(remoteAddress);
  const { saveToken } = saveTokenCookie ?? {};
  let { sessionReference, sessionSigned, fileHash } = socket.handshake.auth ?? {};
  const rejectConnection = async () => {
    console.log(`Rejecting sessionReference ${sessionReference}`);
    socket.emit(SocketServerSideEvents.CompleteHandshake, "", fileHashLocal, () => {});
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
  if (ipRep !== currentIp || sessionId !== session.id || !(await crypto.verify(fromBase64(sessionSigned), fromBase64(sessionReference), clientVerifyingKey))) {
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