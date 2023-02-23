import _ from "lodash";
import { DateTime } from "luxon";
import { config } from "./node_modules/dotenv";
import { ServerOptions, createServer } from "node:https";
import fs from "node:fs";
import session, { Session, CookieOptions as SessionCookieOptions, SessionOptions } from "express-session";
import cookieParser from "cookie-parser";
import ConnectMongoDBSession from "connect-mongodb-session";
import express, { Request, Response, NextFunction, CookieOptions } from "express";
import cors, { CorsOptions } from "cors";
import { Server as SocketServer, Socket } from "socket.io";
import { Buffer } from "./node_modules/buffer";
import { SessionCrypto } from "../shared/sessionCrypto";
import * as crypto from "../shared/cryptoOperator";
import { failure, Failure, CommonStrings, Username, AuthSetupKey, AuthInfo, RegisterNewUserRequest, InitiateAuthenticationResponse, SignInResponse, PublishKeyBundlesRequest, RequestKeyBundleResponse, SocketEvents, PasswordDeriveInfo, UserAuthInfo, randomFunctions, SavedDetails, AuthSetupKeyData, NewUserData, ConcludeAuthenticationRequest, AuthChangeData } from "../shared/commonTypes";
import BufferSerializer from "./custom_modules/buffer-serializer";
import { MongoHandler, bufferReplaceForMongo } from "./MongoHandler";

const serializer = new BufferSerializer();
const serialize: (thing: any) => Buffer = serializer.toBuffer.bind(serializer);
const deserialize: (buff: Buffer) => any = serializer.fromBuffer.bind(serializer);

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
  readonly mongoHandler: MongoHandler;
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
    [SocketEvents.LogOut, this.logOut],
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

  constructor(socket: Socket, session: Session, mongoHandler: MongoHandler, sessionReference: string, sessionKeyBits: Buffer, sessionSigningKey: CryptoKey, sessionVerifyingKey: CryptoKey, saveToken?: string, resuming = false) {
    this.#saveToken = saveToken;
    this.#session = session;
    this.mongoHandler = mongoHandler;
    this.#sessionReference = sessionReference;
    this.#sessionCrypto = new SessionCrypto(sessionReference, sessionKeyBits, sessionSigningKey, sessionVerifyingKey);
    this.registerNewSocket(socket);
    if (!resuming) {
      this.registerRunningSession(session.id, sessionReference, sessionKeyBits, sessionSigningKey, sessionVerifyingKey);
    }
    console.log(`Connected: socket#${socket.id} with session reference ${sessionReference}`);
    console.log(`Session ${session.id} begun.`);
  }

  setSaveToken(sessionReference: string, saveToken: string) {
    if (!this.#saveToken && sessionReference === this.#sessionReference) {
      this.#saveToken = saveToken;
      return true;
    }
    return false;
  }

  private deregisterSocket() {
    if (this.#socketId) {
      sockets.delete(this.#socketId);
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
    sockets.set(socket.id, this);
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
    if ("sessionReference" in ((await mongoHandler.getSession(sessionId)) ?? {})) {
      return;
    }
    const sessionSigningKeyEx = await crypto.exportKey(sessionSigningKey);
    const sessionVerifyingKeyEx = await crypto.exportKey(sessionVerifyingKey);
    await mongoHandler.addSession({ sessionId, sessionReference, sessionKeyBits, sessionSigningKeyEx, sessionVerifyingKeyEx });
  }

  private onSocketDisconnect() {
    if (!this.#socketId) {
      return;
    }
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
    sockets.set(newSocket.id, this);
    if (this.#username) {
      onlineUsers.set(this.#username, newSocket.id);
    }
    this.registerNewSocket(newSocket);
    newSocket.emit(SocketEvents.CompleteHandshake, "1", null, null, (success: boolean) => {});
    console.log(`Session ${this.#session.id} reconnected.`);
    return true;
  }

  private async request(event: string, data: any, timeout = 0): Promise<any> {
    return new Promise(async (resolve: (result: any) => void) => {
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
      if (!decryptedData) await respond(failure(CommonStrings.DecryptFailure));
      else {
        const response = await responseBy(decryptedData);
        if (!response) await respond(failure(CommonStrings.ProcessFailed));
        else {
          respond(response);
        }
      }
    }
    catch(err) {
      logError(err)
      respond(failure(CommonStrings.ProcessFailed, err));
    }
  }

  private async userLoginPermitted({ username }: Username): Promise<{ tries: number, allowsAt: number }> {
    const { tries, allowsAt } = await mongoHandler.getUserRetries(username);
    return allowsAt && allowsAt > Date.now() ? { tries, allowsAt } : { tries: null, allowsAt: null };
  }

  private async usernameExists({ username }: Username): Promise<{ exists: boolean }> {
    return { exists: !!(await mongoHandler.getUser(username)) };
  }

  private async generateAuthSetupKey({ username }: Username, newUser = true): Promise<AuthSetupKey | Failure> {
    const { exists } = await this.usernameExists({ username });
    if ((newUser && exists) || this.#username) {
      return failure(CommonStrings.InvalidRequest);
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
    if (!this.#newAuthReference) return failure(CommonStrings.InvalidRequest);
    const { authRef, uname, pInfo, hSaltAuth, hSaltEncrypt } = this.#newAuthReference;
    this.#newAuthReference = null;
    if (authRef !== request.newAuthReference) return failure(CommonStrings.IncorrectData);
    const authBits = "newAuthBits" in request ? request.newAuthBits : request.currentAuthBits;
    const { ciphertext, signature } = "newUserData" in request ? request.newUserData : request.authChangeData;
    const purpose = "newUserData" in request ? "NewUser" : "AuthChange";
    const verifyingKey = await crypto.deriveMACKey(authBits, hSaltAuth, `${purpose}Verify`, 512);
    const result: NewUserData | AuthChangeData = deserialize(await crypto.deriveDecryptVerify(authBits, ciphertext, hSaltEncrypt, purpose, signature, verifyingKey));
    if (result.username !== uname) return failure(CommonStrings.IncorrectData);
    if ("currentAuthReference" in request) {
      const verified = await this.verifyCurrentAuth(request.currentAuthReference, authBits);
      if ("reason" in verified) return verified;
      if (!verified.passwordCorrect) return failure(CommonStrings.IncorrectPassword, result.username);
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
      const { displayName, x3dhInfo, keyBundles } = result;
      return { username, displayName, x3dhInfo, keyBundles, ...authInfo };
    }
    return { ...authInfo, username };
  }

  private async verifyCurrentAuth(currentAuthReference: string, currentAuthBits: Buffer): Promise<{ passwordCorrect: boolean } | Failure> {
    if (!this.#currentAuthReference) return failure(CommonStrings.InvalidRequest);
    const { authRef, originalData, signedData, hSalt } = this.#currentAuthReference;
    this.#currentAuthReference = null;
    if (authRef !== currentAuthReference) return failure(CommonStrings.IncorrectData);
    const verifyKey = await crypto.deriveMACKey(currentAuthBits, hSalt, "AuthSign", 512);
    const passwordCorrect = await crypto.verify(signedData, originalData, verifyKey);
    return { passwordCorrect };
  }

  private async registerNewUser(request: RegisterNewUserRequest): Promise<Failure> {
    const newAuthCreated = await this.processAuth(request);
    if ("reason" in newAuthCreated) return newAuthCreated;
    const { username, displayName, x3dhInfo: x3dh, keyBundles: kb, ...userAuthInfo } = newAuthCreated;
    if (!this.validateKeyBundleOwner(kb, username)) {
      return failure(CommonStrings.IncorrectData);
    }
    const authInfo = bufferReplaceForMongo(userAuthInfo);
    const x3dhInfo = bufferReplaceForMongo(x3dh);
    const keyBundles = bufferReplaceForMongo(kb);
    const newUser = new mongoHandler.User({ username, displayName, authInfo, x3dhInfo, keyBundles });
    try {
      const savedUser = await newUser.save();
      if (savedUser === newUser) {
        console.log(`Saved user: ${username}`);
        this.#username = username;
        return { reason: null };
      }
      return failure(CommonStrings.ProcessFailed);
    }
    catch(err) {
      logError(err)
      return failure(CommonStrings.ProcessFailed, err);
    }
  }

  private async initiateAuthentication({ username }: Username): Promise<InitiateAuthenticationResponse | Failure> {
    if (this.#username) return failure(CommonStrings.InvalidRequest);
    const { tries, allowsAt } = await mongoHandler.getUserRetries(username);
    if (allowsAt && allowsAt > Date.now()) {
      return failure(CommonStrings.TooManyWrongTries, { tries, allowsAt });
    }
    let { authInfo : { encryptionBase, originalData, signedData, serverProof, dInfo: { hSalt, ...pInfo } } } = (await mongoHandler.getLeanUser(username)) ?? {};
    if (!originalData) return failure(CommonStrings.IncorrectData);
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
      if (processAuthResult.reason === CommonStrings.IncorrectPassword) {
        const username: string = processAuthResult.details;
        let { tries } = await mongoHandler.getUserRetries(username);
        tries ??= 0;
        tries++;
        if (tries >= 5) {
          const forbidInterval = 1000 * (30 + 15 * (tries - 5));
          const allowsAt = Date.now() + forbidInterval;
          await mongoHandler.updateUserRetries(username, allowsAt, tries);
          setTimeout(async () => {
            await mongoHandler.updateUserRetries(username, null);
          }, forbidInterval);
          return failure(CommonStrings.TooManyWrongTries, { tries, allowsAt });
        }
        await mongoHandler.updateUserRetries(username, null, tries);
        return failure(CommonStrings.IncorrectPassword, { tries });
      }
      return processAuthResult;
    }
    const { username, ...userAuthInfo } = processAuthResult;        
    await mongoHandler.updateUserRetries(username, null, 0);
    const user = await mongoHandler.getUser(username);
    if (!user) return failure(CommonStrings.ProcessFailed);
    const { displayName, x3dhInfo }: SignInResponse = await mongoHandler.getLeanUser(username);
    user.authInfo = bufferReplaceForMongo(userAuthInfo);
    try {
      const savedUser = await user.save();
      if (savedUser === user) {
        this.#username = username;
        return { displayName, x3dhInfo };
      }
      return failure(CommonStrings.ProcessFailed);
    }
    catch(err) {
      logError(err);
      return failure(CommonStrings.ProcessFailed, err);
    }
  }

  private async setSavedDetails(request: SavedDetails) : Promise<Failure> {
    if (request.saveToken !== this.#saveToken) return failure(CommonStrings.IncorrectData);
    const success = await mongoHandler.setSavedDetails(request);
    return success ? { reason: null } : failure(CommonStrings.ProcessFailed);
  }

  private async getSavedDetails({ saveToken }: { saveToken: string }) {
    if (saveToken !== this.#saveToken) return failure(CommonStrings.IncorrectData);
    this.#saveToken = null;
    return await mongoHandler.getSavedDetails(saveToken) ?? { };
  }

  private validateKeyBundleOwner(keyBundles: PublishKeyBundlesRequest, username: string) {
    let { defaultKeyBundle, oneTimeKeyBundles } = keyBundles;
    return [defaultKeyBundle.owner, ...oneTimeKeyBundles.map((kb) => kb.owner)].every((kb: any) => kb.owner === username)
  }

  private async publishKeyBundles(keyBundles: PublishKeyBundlesRequest): Promise<Failure>  {
    if (!this.#username) return failure(CommonStrings.InvalidRequest);
    if (!this.validateKeyBundleOwner(keyBundles, this.#username)) {
      return failure(CommonStrings.IncorrectData);
    }
    const user = await mongoHandler.getUser(this.#username);
    if (!user) {
      return failure(CommonStrings.ProcessFailed);
    }
    let { defaultKeyBundle, oneTimeKeyBundles } = keyBundles;
    user.keyBundles.defaultKeyBundle = bufferReplaceForMongo(defaultKeyBundle);
    oneTimeKeyBundles = Array.from(oneTimeKeyBundles.map((kb: any) => bufferReplaceForMongo(kb)));
    const leanUser = await mongoHandler.getLeanUser(this.#username);
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
      if (user !== await user.save()) return failure(CommonStrings.ProcessFailed);
      return { reason: null };
    }
    catch(err) {
      logError(err);
      return failure(CommonStrings.ProcessFailed, err);
    }
  }
  
  private async requestKeyBundle({ username }: Username): Promise<RequestKeyBundleResponse | Failure> {
    if (!this.#username || username === this.#username) return failure(CommonStrings.InvalidRequest);
    const otherUser = await mongoHandler.getUser(username);
    if (!otherUser) return failure(CommonStrings.IncorrectData);
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
    if (!keyBundle) return failure(CommonStrings.ProcessFailed);
    if (saveRequired) {
      otherUser.accessedKeyBundles.push(keyBundle.identifier);
    }
    try {
      if (saveRequired && otherUser !== await otherUser.save()) return failure(CommonStrings.ProcessFailed);
      return { keyBundle };
    }
    catch(err) {
      logError(err);
      return failure(CommonStrings.ProcessFailed, err);
    }
  }

  private async logOut({ username }: Username): Promise<Failure> {
    if (this.#username !== username) return failure(CommonStrings.InvalidRequest);
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
    mongoHandler.deleteSession(this.#session.id);
    this.#session = null;
    this.#sessionReference = null;
    this.#sessionCrypto = null;
    this.#newAuthReference = null;
    this.#currentAuthReference = null;
    this.#username = null;
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
const mongoHandler = new MongoHandler(mongoUrl);
const sockets = new Map<string, SocketHandler>();
const interruptedSessions = new Map<string, (socket: Socket, sessionReference: string) => boolean>();
const onlineUsers = new Map<string, string>();
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
    res.clearCookie("saveToken").status(200).end();
    return;
  }
  if (sockets.get(socketId)?.setSaveToken(sessionReference, saveToken)) {
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
  const { session, cookies: { saveToken: saveTokenCookie } } = socket.request;
  const { saveToken } = saveTokenCookie ?? {};
  let { sessionReference, clientPublicKey, clientVerifyingKey } = socket.handshake.auth ?? {};
  if (!sessionReference || !clientPublicKey || !clientVerifyingKey) {
    socket.emit(SocketEvents.CompleteHandshake, "", null, null, (success: boolean) => {});
    await sleep(5000);
    socket.disconnect(true);
    return;
  }
  const crashedSession = await mongoHandler.getSession(session.id);
  if (crashedSession) {
    const { sessionKeyBits, sessionSigningKeyEx, sessionVerifyingKeyEx } = crashedSession;
    const sessionSigningKey = await crypto.importKey(sessionSigningKeyEx, "ECDSA", "private", true);
    const sessionVerifyingKey = await crypto.importKey(sessionVerifyingKeyEx, "ECDSA", "public", true);
    console.log(`Resuming crashed session #${session.id}.`);
    new SocketHandler(socket, session, mongoHandler, sessionReference, sessionKeyBits, sessionSigningKey, sessionVerifyingKey, saveToken, true);
    return;
  }
  if (interruptedSessions.has(session.id)) {
    if (interruptedSessions.get(session.id)(socket, sessionReference)) {
      return;
    }
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
  new SocketHandler(socket, session, mongoHandler, sessionReference, sessionKeyBits, signingKey, clientVerifyingKey, saveToken);
});