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
import { Server as SocketServer, Socket } from "socket.io";
import { Buffer } from "./node_modules/buffer";
import { SessionCrypto } from "../shared/sessionCrypto";
import * as crypto from "../shared/cryptoOperator";
import { serialize, deserialize } from "../shared/cryptoOperator";
import { failure, Failure, ErrorStrings, Username, AuthSetupKey, AuthInfo, RegisterNewUserRequest, InitiateAuthenticationResponse, SignInResponse, PublishKeyBundlesRequest, RequestKeyBundleResponse, SocketEvents, PasswordDeriveInfo, UserAuthInfo, randomFunctions, SavedDetails, AuthSetupKeyData, NewUserData, ConcludeAuthenticationRequest, AuthChangeData, MessageRequestHeader, KeyBundle, EstablishData, UserEncryptedData, MessageHeader, MessageEvent, StoredMessage } from "../shared/commonTypes";
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

class SocketHandler {
  private readonly responseMap: Map<SocketEvents, any> = new Map([
    [SocketEvents.UsernameExists, this.usernameExists] as [SocketEvents, any], 
    [SocketEvents.UserLoginPermitted, this.userLoginPermitted], 
    [SocketEvents.RequestAuthSetupKey, this.generateAuthSetupKey], 
    [SocketEvents.RegisterNewUser, this.registerNewUser], 
    [SocketEvents.InitiateAuthentication, this.initiateAuthentication], 
    [SocketEvents.ConcludeAuthentication, this.concludeAuthentication],
    [SocketEvents.SetSavedDetails, this.setSavedDetails],
    [SocketEvents.GetSavedDetails, this.getSavedDetails],
    [SocketEvents.PublishKeyBundles, this.publishKeyBundles],
    [SocketEvents.RequestKeyBundle, this.requestKeyBundle],
    [SocketEvents.GetAllChats, this.getAllChats],
    [SocketEvents.GetAllRequests, this.getAllRequests],
    [SocketEvents.GetUnprocessedMessages, this.getUnprocessedMessages],
    [SocketEvents.GetMessagesByNumber, this.getMessagesByNumber],
    [SocketEvents.GetMessagesUptoTimestamp, this.getMessagesUptoTimestamp],
    [SocketEvents.GetMessagesUptoId, this.getMessagesUptoId],
    [SocketEvents.GetMessageById, this.getMessageById],
    [SocketEvents.StoreMessage, this.storeMessage],
    [SocketEvents.CreateChat, this.createChat],
    [SocketEvents.UpdateChat, this.updateChat],
    [SocketEvents.SendMessageRequest, this.sendMessageRequest],
    [SocketEvents.SendMessage, this.sendMessage],
    [SocketEvents.SendMessageEvent, this.sendMessageEvent],
    [SocketEvents.DeleteMessageRequest, this.deleteMessageRequest],
    [SocketEvents.LogOut, this.logOut],
    [SocketEvents.RequestRoom, this.roomRequested]
  ]);
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
  #rooms: Room[] = [];
  #url: string;

  constructor(socket: Socket, session: Session, sessionReference: string, sessionKeyBits: Buffer, sessionSigningKey: CryptoKey, sessionVerifyingKey: CryptoKey, url: string, saveToken?: string, resuming = false) {
    this.#url = url;
    this.#saveToken = saveToken;
    this.#session = session;
    this.#sessionReference = sessionReference;
    this.#sessionCrypto = new SessionCrypto(sessionReference, sessionKeyBits, sessionSigningKey, sessionVerifyingKey);
    this.registerNewSocket(socket);
    if (!resuming) {
      this.registerRunningSession(session.id, sessionReference, sessionKeyBits, sessionSigningKey, sessionVerifyingKey);
    }
    else {
      MongoHandlerCentral.getSession(session.id).then((running) => {
        const { accessedBundles } = running;
        if (accessedBundles) {
          this.#accessedBundles = accessedBundles;
        }
      })
    }
    console.log(`Connected: socket#${socket.id} with session reference ${sessionReference}`);
    console.log(`Session ${session.id} begun.`);
  }

  setSaveToken(sessionReference: string, saveToken: string) {
    const _saveToken = this.#saveToken;
    const _sessionRef = this.#sessionReference;
    if (sessionReference === this.#sessionReference && (!this.#saveToken || !saveToken)) {
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
      this.#socket?.disconnect(true);
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
    for (const [event, response] of this.responseMap.entries()) {
      socket.on(event, async (data: string, respond) => await this.respond(event, data, response.bind(this), respond));
    }
    socket.on(SocketEvents.TerminateCurrentSession, (_, respond) => {
      this.terminateCurrentSession();
      respond();
    });
    socket.on("disconnect", this.onSocketDisconnect.bind(this));
  }

  private async registerRunningSession(sessionId: string, sessionReference: string, sessionKeyBits: Buffer, sessionSigningKey: CryptoKey, sessionVerifyingKey: CryptoKey) {
    if ("sessionReference" in ((await MongoHandlerCentral.getSession(sessionId)) ?? {})) {
      return;
    }
    const sessionSigningKeyEx = await crypto.exportKey(sessionSigningKey);
    const sessionVerifyingKeyEx = await crypto.exportKey(sessionVerifyingKey);
    await MongoHandlerCentral.addSession({ sessionId, sessionReference, sessionKeyBits, sessionSigningKeyEx, sessionVerifyingKeyEx });
  }

  private onSocketDisconnect() {
    if (!this.#socketId) {
      return;
    }
    this.#rooms.forEach((room) => room.dispose());
    this.deregisterSocket();
    const sessionId = this.#session.id;
    console.log(`Disonnected: socket#${this.#socketId}`);
    console.log(`Session ${sessionId} interrupted.`);
    interruptedSessions.set(sessionId, this.waitInterrupted.bind(this));
    setTimeout(() => {
      interruptedSessions.delete(sessionId);
      this.terminateCurrentSession();
    }, 10*60*1000);
  }

  private async waitInterrupted(newSocket: Socket, sessionReference: string) {
    if (sessionReference !== this.#sessionReference) {
      return false;
    }
    interruptedSessions.delete(this.#session.id);
    socketHandlers.set(newSocket.id, this);
    if (this.#username) {
      onlineUsers.set(this.#username, newSocket.id);
    }
    this.registerNewSocket(newSocket);
    newSocket.emit(SocketEvents.CompleteHandshake, "1", null, null, () => {});
    console.log(`Session ${this.#session.id} reconnected.`);
    return true;
  }

  private async request(event: string, data: any, timeout = 0): Promise<any> {
    return await new Promise(async (resolve: (result: any) => void) => {
      this.#socket.emit(event, Buffer.from(await this.#sessionCrypto.signEncrypt(data, event)).toString("base64"), 
      async (response: string) => resolve(response ? await this.#sessionCrypto.decryptVerify(Buffer.from(response, "base64"), event): {}));
      if (timeout > 0) {
        setTimeout(() => resolve({}), timeout);
      }
    }).catch((err) => console.log(`${err}\n${err.stack}`));
  }

  private async respond(event: string, data: string, responseBy: (arg0: any) => any, respondAt: (arg0: string) => void) {
    const respond = async (response: any) => {
      respondAt(Buffer.from(await this.#sessionCrypto.signEncrypt(response, event)).toString("base64"));
    }
    try {
      const decryptedData = await this.#sessionCrypto.decryptVerify(Buffer.from(data, "base64"), event);
      if (!decryptedData) await respond(failure(ErrorStrings.DecryptFailure));
      else if (decryptedData.url !== this.#url || decryptedData.fileHash !== await jsHash ) {
        await respond(failure(ErrorStrings.InvalidRequest, "Url or File Hash do not match."));
        this.terminateCurrentSession();
      }
      else {
        const response = await responseBy(decryptedData);
        if (!response) await respond(failure(ErrorStrings.ProcessFailed));
        else {
          respond(response);
        }
      }
    }
    catch(err) {
      logError(err)
      respond(failure(ErrorStrings.ProcessFailed, err));
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
    const authKeyData = await crypto.deriveSignEncrypt(userKeyBits, serialize(keyData), hSalt, "AuthKeyData");
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
    const result: NewUserData | AuthChangeData = deserialize(await crypto.deriveDecryptVerify(authBits, ciphertext, hSaltEncrypt, purpose, signature, verifyingKey));
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
        return { userDetails, x3dhInfo };
      }
      return failure(ErrorStrings.ProcessFailed);
    }
    catch(err) {
      logError(err);
      return failure(ErrorStrings.ProcessFailed, err);
    }
  }

  private async setSavedDetails(request: SavedDetails) : Promise<Failure> {
    if (request.saveToken !== this.#saveToken) return failure(ErrorStrings.IncorrectData);
    const success = await MongoHandlerCentral.setSavedDetails(request);
    return success ? { reason: null } : failure(ErrorStrings.ProcessFailed);
  }

  private async getSavedDetails({ saveToken }: { saveToken: string }) {
    if (saveToken !== this.#saveToken) return failure(ErrorStrings.IncorrectData);
    this.#saveToken = null;
    return (await MongoHandlerCentral.getSavedDetails(saveToken)) ?? failure(ErrorStrings.ProcessFailed);
  }

  private validateKeyBundleOwner(keyBundles: PublishKeyBundlesRequest, username: string) {
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
      if (saveRequired) {
        this.#accessedBundles.set(username, keyBundle);
        await MongoHandlerCentral.addAccessedBundle(this.#session.id, username, keyBundle);
      }
      return { keyBundle };
    }
    catch(err) {
      logError(err);
      return failure(ErrorStrings.ProcessFailed, err);
    }
  }

  private async roomRequested({ username, ...rest }: Username & EstablishData) {
    if (!this.#username || this.#username === username) return failure(ErrorStrings.InvalidRequest);
    const otherSocketHandler = socketHandlers.get(onlineUsers.get(username));
    if (!otherSocketHandler) return failure(ErrorStrings.ProcessFailed);
    const createRoom = (otherSocket: Socket) => Room.createRoom(this.#username, this.#socket, username, otherSocket);
    const response = await otherSocketHandler.requestRoom({ username: this.#username, createRoom, ...rest });
    if ("reason" in response) {
      return response;
    }
    const { potentialRoom, establish } = response;
    potentialRoom.then((room) => this.#rooms.push(room));
    return establish;
  }

  private async requestRoom({ username, createRoom, ...rest }: Username & EstablishData & { createRoom: (socket: Socket) => Promise<Room> }): Promise<{ potentialRoom: Promise<Room>, establish: EstablishData} | Failure> {
    if (!this.#username || this.#username === username) return failure(ErrorStrings.InvalidRequest);
    const potentialRoom = createRoom(this.#socket);
    potentialRoom.then((room) => this.#rooms.push(room));
    const response: Failure | EstablishData = await this.request(SocketEvents.RequestRoom, { username, ...rest });
    if ("reason" in response) {
      return response;
    }
    return { potentialRoom, establish: response };
  }

  private async sendMessageRequest(messageRequest: MessageRequestHeader) {
    if (!this.#username || this.#username === messageRequest.addressedTo) return failure(ErrorStrings.InvalidRequest);
    if (!(await MongoHandlerCentral.depositMessageRequest(messageRequest))) return failure(ErrorStrings.ProcessFailed);
    return { reason: null };
  }

  private async sendMessage(message: MessageHeader) {
    if (!this.#username || this.#username === message.addressedTo) return failure(ErrorStrings.InvalidRequest);
    if (!(await MongoHandlerCentral.depositMessage(message))) return failure(ErrorStrings.ProcessFailed);
    return { reason: null };
  }

  private async sendMessageEvent(event: MessageEvent) {
    if (!this.#username || this.#username === event.addressedTo) return failure(ErrorStrings.InvalidRequest);
    if (!(await MongoHandlerCentral.logMessageEvent(event))) return failure(ErrorStrings.ProcessFailed);
    return { reason: null };
  }

  private async getAllChats() {
    if (!this.#username) return failure(ErrorStrings.InvalidRequest);
    return await this.#mongoHandler.getAllChats();
  }

  private async getAllRequests() {
    if (!this.#username) return failure(ErrorStrings.InvalidRequest);
    return await this.#mongoHandler.getAllRequests();
  }

  private async getUnprocessedMessages(param: { sessionId: string }) {
    if (!this.#username) return failure(ErrorStrings.InvalidRequest);
    return await this.#mongoHandler.getUnprocessedMessages(param.sessionId);
  }

  private async getMessagesByNumber(param: { sessionId: string, limit: number, olderThan?: number }) {
    if (!this.#username) return failure(ErrorStrings.InvalidRequest);
    let { sessionId, limit, olderThan } = param;
    olderThan ||= Date.now();
    return await this.#mongoHandler.getMessagesByNumber(sessionId, limit, olderThan);
  }

  private async getMessagesUptoTimestamp(param: { sessionId: string, newerThan: number, olderThan?: number }) {
    if (!this.#username) return failure(ErrorStrings.InvalidRequest);
    let { sessionId, newerThan, olderThan } = param;
    olderThan ||= Date.now();
    return await this.#mongoHandler.getMessagesUptoTimestamp(sessionId, newerThan, olderThan);
  }

  private async getMessagesUptoId(param: { sessionId: string, messageId: string, olderThan?: number }) {
    if (!this.#username) return failure(ErrorStrings.InvalidRequest);
    let { sessionId, messageId, olderThan } = param;
    olderThan ||= Date.now();
    return await this.#mongoHandler.getMessagesUptoId(sessionId, messageId, olderThan);
  }

  private async getMessageById(param: { sessionId: string, messageId: string }) {
    if (!this.#username) return failure(ErrorStrings.InvalidRequest);
    let { sessionId, messageId } = param;
    return await this.#mongoHandler.getMessageById(sessionId, messageId);
  }

  private async storeMessage(message: StoredMessage) {
    if (!this.#username) return failure(ErrorStrings.InvalidRequest);
    if (!(await this.#mongoHandler.storeMessage(message))) return failure(ErrorStrings.ProcessFailed);
    return { reason: null };
  }

  private async createChat(chat: { sessionId: string, lastActivity: number, chatDetails: UserEncryptedData, chattingSession: UserEncryptedData }) {
    if (!this.#username) return failure(ErrorStrings.InvalidRequest);
    if (!(await this.#mongoHandler.createChat(chat))) return failure(ErrorStrings.ProcessFailed);
    return { reason: null };
  }

  private async updateChat(chat: { sessionId: string, lastActivity: number, chatDetails: UserEncryptedData, chattingSession: UserEncryptedData }) {
    if (!this.#username) return failure(ErrorStrings.InvalidRequest);
    if (!(await this.#mongoHandler.updateChat(chat))) return failure(ErrorStrings.ProcessFailed);
    return { reason: null };
  }

  private async deleteMessageRequest(param: { sessionId: string }) {
    if (!this.#username) return failure(ErrorStrings.InvalidRequest);
    const success = await this.#mongoHandler.deleteMessageRequest(param.sessionId);
    return success ? { reason: null } : failure(ErrorStrings.ProcessFailed); 
  }

  private async notifyMessage(message: MessageHeader | MessageRequestHeader | MessageEvent) {
    if (message.addressedTo !== this.#username) return;
    if ("messageBody" in message) {
      await this.request(SocketEvents.MessageReceived, message);
    }
    else if ("initialMessage" in message) {
      await this.request(SocketEvents.MessageRequestReceived, message);
    }
    else if ("event" in message) {
      await this.request(SocketEvents.MessageEventLogged, message);
    }
  }

  private async logOut({ username }: Username): Promise<Failure> {
    if (this.#username !== username) return failure(ErrorStrings.InvalidRequest);
    this.dispose();
  }

  private terminateCurrentSession() {
    this.#session?.destroy((err) => {
      console.log(`Session ${this.#session.id} destroyed.`);
      this.dispose();
    });
  }

  private dispose() {
    console.log(`Disposing connection: session reference ${this.#sessionReference}`);
    this.deregisterSocket();
    MongoHandlerCentral.deleteSession(this.#session.id);
    MongoHandlerCentral.deregisterUserHandler(this.#username);
    this.#session = null;
    this.#sessionReference = null;
    this.#sessionCrypto = null;
    this.#newAuthReference = null;
    this.#currentAuthReference = null;
    this.#username = null;
  }
}

class Room {
  readonly #user1: string;
  readonly #user2: string;
  readonly #socket1: Socket;
  readonly #socket2: Socket;
  private readonly emit1: (data: string, respond: (recv: boolean) => void) => void;
  private readonly emit2: (data: string, respond: (recv: boolean) => void) => void;

  private constructor(user1: string, socket1: Socket, user2: string, socket2: Socket, timeoutMs: number) {
    this.#user1 = user1;
    this.#user2 = user2;
    this.#socket1 = socket1;
    this.#socket2 = socket2;
    if (timeoutMs > 0) {
      this.emit1 = (data, respond) => this.#socket1.emit(this.#user2, data, respond);
      this.emit2 = (data, respond) => this.#socket2.emit(this.#user1, data, respond);
    }
    else {
      this.emit1 = (data, respond) => {
        const timeout = setTimeout(() => respond(false), timeoutMs);
        this.#socket1.emit(this.#user2, data, (response: boolean) => {
          clearTimeout(timeout);
          respond(response);
        });
      };
      this.emit2 = (data, respond) => {
        const timeout = setTimeout(() => respond(false), timeoutMs);
        this.#socket2.emit(this.#user1, data, (response: boolean) => {
          clearTimeout(timeout);
          respond(response);
        });
      };
    }
    this.#socket1.on(this.#user2, this.emit1);
    this.#socket2.on(this.#user1, this.emit2);
  }

  dispose() {
    this.#socket1?.emit(this.#user2, "disconnected");
    this.#socket2?.emit(this.#user1, "disconnected");
    this.#socket1?.off(this.#user2, this.emit1);
    this.#socket2?.off(this.#user1, this.emit2);
  }

  static async createRoom(user1: string, socket1: Socket, user2: string, socket2: Socket, timeoutMs = 0): Promise<Room> {
    const established1 = new Promise<boolean>((resolve) => {
      const response = (withUser: string) => { 
        if (withUser === user2) {
          socket1.off(SocketEvents.RoomEstablished, response);
          resolve(true);
        } };
      socket1.on(SocketEvents.RoomEstablished, response);
      setTimeout(() => {
        socket1.off(SocketEvents.RoomEstablished, response);
        resolve(false);
      }, 20000);
    });
    const established2 = new Promise<boolean>((resolve) => {
      const response = (withUser: string) => { 
        if (withUser === user1) {
          socket2.off(SocketEvents.RoomEstablished, response);
          resolve(true);
        } };
      socket2.on(SocketEvents.RoomEstablished, response);
      setTimeout(() => {
        socket2.off(SocketEvents.RoomEstablished, response);
        resolve(false);
      }, 20000);
    });
    return Promise.all([established1, established2]).then(([est1, est2]) => {
      if (est1 && est2) {
        const room = new Room(user1, socket1, user2, socket2, timeoutMs);
        socket1.emit(user2, "confirmed");
        socket2.emit(user1, "confirmed");
        return room;
      }
      else {
        return null;
      }
    });
  }
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
const mongoUrl = "mongodb://localhost:27017/chatapp";
MongoHandlerCentral.connect(mongoUrl);
const MongoDBStore = ConnectMongoDBSession(session);
const store = new MongoDBStore({ uri: mongoUrl, collection: "user_sessions" });
const httpsOptions : ServerOptions = {
  key: fs.readFileSync(`..\\certificates\\key.pem`),
  cert: fs.readFileSync(`..\\certificates\\cert.pem`)
}
const cookie: SessionCookieOptions = { httpOnly: true, sameSite: "strict", secure: false }
const sessionOptions: SessionOptions = { secret: getRandomString(), cookie, genid(req) {
  return `${getRandomString()}-${req.ip}`; }, name: "chatapp.session.id", resave: false, store, unset: "destroy", saveUninitialized: false };
const corsOptions: CorsOptions = { origin: /.*/, methods: ["GET", "POST"], exposedHeaders: ["set-cookie"], allowedHeaders: ["content-type"], credentials: true };
const sessionMiddleware = session(sessionOptions);
const cookieParserMiddle = cookieParser();
const app = express().use(cors(corsOptions)).use(sessionMiddleware).use(cookieParserMiddle).use(express.json());
const httpsServer = createServer(httpsOptions, app);
const socketHandlers = new Map<string, SocketHandler>();
const interruptedSessions = new Map<string, (socket: Socket, sessionReference: string) => boolean>();
const onlineUsers = new Map<string, string>();
let abortController: AbortController = new AbortController();
const hashCalculator = async () => {
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
(async () => {
  const watcher = fsPromises.watch(`..\\client\\public\\main.js`);
  for await (const { eventType } of watcher) {
    if (eventType === "change") {
      const prevController = abortController;
      abortController = new AbortController();
      jsHash = hashCalculator();
      prevController.abort();
    }
  }
})();

const io = new SocketServer(httpsServer, {
  cors: {
    origin: /.*/,
    methods: ["GET", "POST"],
    credentials: true
  }
});

app.post("/setSaveToken", (req, res) => {
  const { saveToken, socketId, sessionReference } = req.body;
  if (saveToken === "0") {
    if (socketHandlers.get(socketId)?.setSaveToken(sessionReference, null)) {
      res.clearCookie("saveToken").status(200).end();
    }
    else {
      res.status(403).end();
    }
    return;
  }

  if (socketHandlers.get(socketId)?.setSaveToken(sessionReference, saveToken)) {
    const cookieOptions : CookieOptions = { httpOnly: true, secure: true, maxAge: 10*24*60*60*1000, sameSite: "strict", expires: DateTime.now().plus({ days: 10 }).toJSDate() };
    res.cookie("saveToken", { saveToken }, cookieOptions).status(200).end();
  }
  else {
    res.status(403).end();
  }
});

store.on("error", (err) => logError(err));
httpsServer.listen(PORT, () => console.log(`listening on *:${PORT}`));
io.use((socket: Socket, next) => { sessionMiddleware(socket.request as Request, {} as Response, next as NextFunction) });
io.use((socket: Socket, next) => { cookieParserMiddle(socket.request as Request, {} as Response, next as NextFunction) });
io.on("connection", async (socket) => {
  const fileHashLocal = await jsHash;
  const { session, cookies: { saveToken: saveTokenCookie } } = socket.request;
  const { saveToken } = saveTokenCookie ?? {};
  let { sessionReference, clientPublicKey, clientVerifyingKey, fileHash, url } = socket.handshake.auth ?? {};
  if (!sessionReference || !clientPublicKey || !clientVerifyingKey || fileHash !== fileHashLocal) {
    socket.emit(SocketEvents.CompleteHandshake, "", null, null, () => {});
    await sleep(5000);
    socket.disconnect(true);
    return;
  }
  if (interruptedSessions.has(session.id)) {
    if (interruptedSessions.get(session.id)(socket, sessionReference)) {
      return;
    }
  }
  const crashedSession = await MongoHandlerCentral.getSession(session.id);
  if (crashedSession) {
    const { sessionKeyBits, sessionSigningKeyEx, sessionVerifyingKeyEx } = crashedSession;
    const sessionSigningKey = await crypto.importKey(sessionSigningKeyEx, "ECDSA", "private", true);
    const sessionVerifyingKey = await crypto.importKey(sessionVerifyingKeyEx, "ECDSA", "public", true);
    console.log(`Resuming crashed session #${session.id}.`);
    new SocketHandler(socket, session, sessionReference, sessionKeyBits, sessionSigningKey, sessionVerifyingKey, url, saveToken, true);
    socket.emit(SocketEvents.CompleteHandshake, "1", null, null, () => {});
    return;
  }
  clientPublicKey = await crypto.importKey(Buffer.from(clientPublicKey, "base64"), "ECDH", "public", true);
  clientVerifyingKey = await crypto.importKey(Buffer.from(clientVerifyingKey, "base64"), "ECDSA", "public", true);
  console.log(`Socket#${socket.id} connecting with session reference: ${sessionReference}.`);
  const { privateKey, publicKey } = await crypto.generateKeyPair("ECDH");
  const { privateKey: signingKey, publicKey: verifyingKey } = await crypto.generateKeyPair("ECDSA");
  const sessionKeyBits = await crypto.deriveSymmetricBits(privateKey, clientPublicKey, 512);
  const serverPublicKey = (await crypto.exportKey(publicKey)).toString("base64");
  const serverVerifyingKey = (await crypto.exportKey(verifyingKey)).toString("base64");
  const success = await new Promise((resolve) => {
    socket.emit(SocketEvents.CompleteHandshake, sessionReference, serverPublicKey, serverVerifyingKey, resolve);
    setTimeout(() => resolve(false), 30000);
  })
  if (!success) {
    socket.disconnect(true);
    return;
  }
  new SocketHandler(socket, session, sessionReference, sessionKeyBits, signingKey, clientVerifyingKey, url, saveToken);
});