import _ from "lodash";
import { match } from "ts-pattern";
import axios, { Axios } from "axios";
import { io, Socket } from "socket.io-client";
import { Buffer } from "./node_modules/buffer";
import { stringify } from "safe-stable-stringify";
import { SessionCrypto } from "../../shared/sessionCrypto";
import { ChattingSession, ViewMessageRequest, ViewPendingRequest, X3DHUser } from "./e2e-encryption";
import * as crypto from "../../shared/cryptoOperator";
import { serialize, deserialize } from "../../shared/cryptoOperator";
import { ErrorStrings, Failure, Username, AuthSetupKey, UserEncryptedData, RegisterNewUserRequest, InitiateAuthenticationResponse, ConcludeAuthenticationRequest, SignInResponse, PublishKeyBundlesRequest, RequestKeyBundleResponse, SocketEvents, randomFunctions, failure, SavedDetails, PasswordEncryptedData, AuthSetupKeyData, NewUserData, AuthChangeData, EstablishData, MessageHeader, MessageRequestHeader, StoredMessage, MessageEvent, ChatData, PlainMessage, MessageBody, DisplayMessage, Contact, Profile } from "../../shared/commonTypes";

const { getRandomVector, getRandomString } = randomFunctions();
axios.defaults.withCredentials = true;

export enum Status {
  Disconnected, 
  Connecting,
  Reconnecting,
  FailedToConnect,
  Connected,
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

export type AwaitedRequest = Readonly<{
  sessionId: string,
  otherUser: string,
  lastActivity: number,
  message: DisplayMessage
}>;

type ChatEvent = {
    readonly event: "typing" | "stopped-typing" | "delivered" | "seen";
    readonly timestamp?: number;
    readonly messageId?: string;
}

type ClientChatInterface = Readonly<{
  SendMessage: (data: MessageHeader, timeout?: number) => Promise<Failure>,
  SendMessageEvent: (data: Omit<MessageEvent, "sessionId">, timeout?: number) => Promise<Failure>,
  GetUnprocessedMessages: (timeout?: number) => Promise<MessageHeader[] | Failure>,
  GetMessagesByNumber: (data: { limit: number, olderThan?: number }, timeout?: number) => Promise<StoredMessage[] | Failure>,
  GetMessagesUptoTimestamp: (data: { newerThan: number, olderThan?: number }, timeout?: number) => Promise<StoredMessage[] | Failure>,
  GetMessagesUptoId: (data: { messageId: string, olderThan?: number }, timeout?: number) => Promise<StoredMessage[] | Failure>,
  GetMessageById: (data: { messageId: string }, timeout?: number) => Promise<StoredMessage | Failure>,
  StoreMessage: (data: Omit<StoredMessage, "sessionId">, timeout?: number) => Promise<Failure>,
  UpdateMessage: (data: Omit<MessageEvent, "addressedTo" | "sessionId">, timeout?: number) => Promise<Failure>,
  UpdateChat: (data: Omit<ChatData, "sessionId">, timeout?: number) => Promise<Failure>
}>;

type ClientChatRequestInterface = Readonly<{
  rejectRequest: (otherUser: string, sessionId: string, oneTimeKeyId: string) => Promise<boolean>,
  respondToRequest: (request: MessageRequestHeader, respondingAt: number) => Promise<boolean>
}>

export class Client {
  private readonly responseMap: Map<SocketEvents, any> = new Map([
    [SocketEvents.RequestRoom, this.roomRequested] as [SocketEvents, any],
    [SocketEvents.MessageReceived, this.messageReceived],
    [SocketEvents.MessageRequestReceived, this.messageRequestReceived],
    [SocketEvents.MessageEventLogged, this.messageEventLogged]
  ]);
  private readonly url: string;
  private readonly axInstance: Axios;
  private notifyStatusChange: (status: Status) => void;
  private notifyChange: () => void;
  private connecting = false;
  private retryingConnect = false;
  private reportDone: (arg0: any) => void = undefined;
  #socket: Socket;
  #displayName: string;
  #profilePicture: string;
  #username: string;
  #x3dhUser: X3DHUser;
  #sessionReference: string;
  #sessionCrypto: SessionCrypto;
  #encryptionBaseVector: CryptoKey;
  #fileHash: Promise<string>;
  private readonly chatsByUsername = new Map<string, Chat>();
  private readonly chatRequestsByUsername = new Map<string, ChatRequest>();
  private readonly awaitedRequestsByUsername = new Map<string, AwaitedRequest>();
  private readonly chatsBySessionId = new Map<string, Chat>();
  private readonly chatRequestsBySessionId = new Map<string, ChatRequest>();
  private readonly awaitedRequestsBySessionId = new Map<string, AwaitedRequest>();
  private readonly chatList: string[] = [];
  private readonly chatSessionIdsList = new Map<string, "Chat" | "ChatRequest" | "AwaitedRequest">();
  private readonly chatUsernamesList = new Map<string, "Chat" | "ChatRequest" | "AwaitedRequest">();

  private readonly chatInterface: (sessionId: string) => ClientChatInterface = (sessionId) => ({
    SendMessage: (data: MessageHeader, timeout = 0) => {
      return this.request(SocketEvents.SendMessage, data, timeout);
    },
    SendMessageEvent: (data: Omit<MessageEvent, "sessionId">, timeout = 0) => {
      return this.request(SocketEvents.SendMessageEvent, data, timeout);
    },
    GetUnprocessedMessages: (timeout = 0) => {
      return this.request(SocketEvents.GetUnprocessedMessages, { sessionId }, timeout);
    },
    GetMessagesByNumber: (data: { limit: number, olderThan?: number }, timeout = 0) => {
      return this.request(SocketEvents.GetMessagesByNumber, { sessionId, ...data }, timeout);
    },
    GetMessagesUptoTimestamp: (data: { newerThan: number, olderThan?: number }, timeout = 0) => {
      return this.request(SocketEvents.GetMessagesUptoTimestamp, { sessionId, ...data }, timeout);
    },
    GetMessagesUptoId: (data: { messageId: string, olderThan?: number }, timeout = 0) => {
      return this.request(SocketEvents.GetMessagesUptoId, { sessionId, ...data }, timeout);
    },
    GetMessageById: (data: { messageId: string }, timeout = 0) => {
      return this.request(SocketEvents.GetMessageById, { sessionId, ...data }, timeout);
    },
    StoreMessage: (data: Omit<StoredMessage, "sessionId">, timeout = 0) => {
      return this.request(SocketEvents.StoreMessage, { sessionId, ...data }, timeout);
    },
    UpdateMessage: (data: Omit<MessageEvent, "addressedTo" | "sessionId">, timeout = 0) => {
      return this.request(SocketEvents.UpdateMessage, { sessionId, ...data }, timeout);
    },
    UpdateChat: (data: Omit<ChatData, "sessionId">, timeout = 0) =>  {
      return this.request(SocketEvents.UpdateChat, { sessionId, ...data }, timeout);
    }
  })
 
  private addChat(chat: Chat) {
    this.chatsByUsername.set(chat.otherUser, chat);
    this.chatsBySessionId.set(chat.sessionId, chat);
    this.chatSessionIdsList.set(chat.sessionId, "Chat");
    this.chatUsernamesList.set(chat.otherUser, "Chat");
    this.chatList.push(chat.otherUser);
    if (this.notifyChange) {
      chat.subscribe("client", this.notifyChange);
    }
    this.notifyChange?.();
  }
 
  private addChatRequest(chat: ChatRequest) {
    this.chatRequestsByUsername.set(chat.otherUser, chat);
    this.chatRequestsBySessionId.set(chat.sessionId, chat);
    this.chatSessionIdsList.set(chat.sessionId, "ChatRequest");
    this.chatUsernamesList.set(chat.otherUser, "ChatRequest");
    this.chatList.push(chat.otherUser);
    this.notifyChange?.();
  }
 
  private addAwaitedRequest(chat: AwaitedRequest) {
    this.awaitedRequestsByUsername.set(chat.otherUser, chat);
    this.awaitedRequestsBySessionId.set(chat.sessionId, chat);
    this.chatSessionIdsList.set(chat.sessionId, "AwaitedRequest");
    this.chatUsernamesList.set(chat.otherUser, "AwaitedRequest");
    this.chatList.push(chat.otherUser);
    this.notifyChange?.();
  }
 
  private removeChat(key: string, keyType: "username" | "sessionId") {
    const chat = keyType === "username" ? this.chatsByUsername.get(key) : this.chatsBySessionId.get(key);
    this.chatsByUsername.delete(chat.otherUser);
    this.chatsBySessionId.delete(chat.sessionId);
    this.chatSessionIdsList.delete(chat.sessionId);
    this.chatUsernamesList.delete(chat.otherUser);
    _.remove(this.chatList, ([user, _]) => user === chat.otherUser);
    chat.dispose();
    this.notifyChange?.();
  }
 
  private removeChatRequest(key: string, keyType: "username" | "sessionId") {
    const chat = keyType === "username" ? this.chatRequestsByUsername.get(key) : this.chatRequestsBySessionId.get(key);
    this.chatRequestsByUsername.delete(chat.otherUser);
    this.chatRequestsBySessionId.delete(chat.sessionId);
    this.chatSessionIdsList.delete(chat.sessionId);
    this.chatUsernamesList.delete(chat.otherUser);
    _.remove(this.chatList, ([user, _]) => user === chat.otherUser);
    this.notifyChange?.();
  }
 
  private removeAwaitedRequest(key: string, keyType: "username" | "sessionId") {
    const chat = keyType === "username" ? this.awaitedRequestsByUsername.get(key) : this.awaitedRequestsBySessionId.get(key);
    this.awaitedRequestsByUsername.delete(chat.otherUser);
    this.awaitedRequestsBySessionId.delete(chat.sessionId);
    this.chatSessionIdsList.delete(chat.sessionId);
    this.chatUsernamesList.delete(chat.otherUser);
    _.remove(this.chatList, ([user, _]) => user === chat.otherUser);
    this.notifyChange?.();
  }

  public getChatByUser(otherUser: string): Chat | ChatRequest | AwaitedRequest {
    const type = this.chatUsernamesList.get(otherUser);
    if (type === "Chat") {
      return this.chatsByUsername.get(otherUser);
    }
    else if (type === "ChatRequest") {
      return this.chatRequestsByUsername.get(otherUser);
    }
    else if (type === "AwaitedRequest"){
      return this.awaitedRequestsByUsername.get(otherUser);
    }
    else {
      return null;
    }
  }

  public getChatDetailsByUser(otherUser: string): { type: "Chat" | "ChatRequest" | "AwaitedRequest", displayName?: string, contactName?: string, profilePicture?: string, lastActivity: number } {
    const type = this.chatUsernamesList.get(otherUser);
    if (typeof type !== "string") {
      return null;
    }
    const chat = this.getChatByUser(otherUser);
    const { lastActivity } = chat;
    if ("contactDetails" in chat) {
      const { contactDetails: { displayName, profilePicture, contactName } } = chat;
      return { type, displayName, contactName, profilePicture, lastActivity };
    }
    else {
      return { type, displayName: otherUser, lastActivity };
    }
  }

  public get chatsList() {
    return Array.from(this.chatList);
  }

  public get username(): string {
    return this.#username;
  }

  public get displayName(): string {
    return this.#displayName;
  }

  public get profilePicture(): string {
    return this.#profilePicture;
  }

  public get isConnected(): boolean {
    return this.#socket?.connected ?? false;
  }

  public get isSignedIn(): boolean {
    return !!this.#username;
  }

  constructor(url: string) {
    this.url = url;
    this.axInstance = axios.create({ baseURL: `${this.url}/`, maxRedirects:0 });
    this.#fileHash = this.calculateFileHash();
  }

  subscribeStatusChange(notifyCallback?: (status: Status) => void) {
    if (notifyCallback) this.notifyStatusChange = notifyCallback;
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
      console.log(`Attempting to establish secure session.`);
      this.notifyStatusChange?.(Status.Connecting);
      this.connecting = true;
      const { privateKey, publicKey } = await crypto.generateKeyPair("ECDH");
      const { privateKey: signingKey, publicKey: verifyingKey } = await crypto.generateKeyPair("ECDSA");
      const sessionReference = this.#sessionReference ?? getRandomString();
      const clientPublicKey = (await crypto.exportKey(publicKey)).toString("base64");
      const clientVerifyingKey = (await crypto.exportKey(verifyingKey)).toString("base64");
      const fileHash = await this.#fileHash;
      const auth = { sessionReference, clientPublicKey, clientVerifyingKey, fileHash, url: this.url };
      this.#socket = io(this.url, { auth, withCredentials: true });
      this.#socket.on("disconnect", this.retryConnect.bind(this));
      let nevermind = false;
      const completeHandshake = async (publicKey: string, verifyingKey: string, resolve: (success: boolean) => void, respond: (success: boolean) => void) => {
        try {
          if (nevermind) {
            console.log("Nevermind");
            respond(false);
            resolve(false);
            return;
          }
          console.log(`ServerPublicKey: ${publicKey}`);
          const serverPublicKey = await crypto.importKey(Buffer.from(publicKey, "base64"), "ECDH", "public", true);
          const serverVerifyingKey = await crypto.importKey(Buffer.from(verifyingKey, "base64"), "ECDSA", "public", true);
          const sessionKeyBits = await crypto.deriveSymmetricBits(privateKey, serverPublicKey, 512);
          this.#sessionReference = sessionReference;
          this.#sessionCrypto = new SessionCrypto(sessionReference, sessionKeyBits, signingKey, serverVerifyingKey);
          console.log(`Connected with session reference: ${sessionReference}`);
          if (this.#username) {
            this.notifyStatusChange?.(Status.SignedOut);
            this.#displayName = null;
            this.#username = null;
            this.#x3dhUser = null;
          }
          respond(true);
          resolve(true);
        }
        catch(err) {
          logError(err);
          respond(false);
          resolve(false);
        }
      }
      const success: boolean = await new Promise((resolve) => {
        this.#socket.once(SocketEvents.CompleteHandshake, (ref, publicKey, verifyingKey, respond) => {
          try {
            if (ref !== sessionReference) {
              const reconnected = this.#sessionReference && ref === "1";
              respond(reconnected);
              resolve(reconnected);
              return;
            }
            completeHandshake(publicKey, verifyingKey, resolve, respond); 
          }
          catch(err) {
            logError(err);
            respond(false);
            resolve(false);
          }
        });
        window.setTimeout(() => resolve(false), 20000);
        this.#socket.connect();
      });
      nevermind = true;
      this.connecting = false;
      console.log(success && this.isConnected ? "Secure session established." : "Failed to establish secure session.");
      this.notifyStatusChange?.(this.isConnected ? Status.Connected : Status.FailedToConnect);
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
    if (this.retryingConnect) return;
    this.#socket?.offAny?.();
    this.#socket?.disconnect?.();
    this.#socket = null;
    this.notifyStatusChange?.(Status.Disconnected);
    this.notifyStatusChange?.(Status.SignedOut);
    if (reason === "io client disconnect") return;
    this.retryingConnect = true;
    while(!this.isConnected) {
      const wait = new Promise((resolve, _) => { 
        this.reportDone = resolve;
        window.setTimeout(() => resolve(null), 10000); });
      if (!this.connecting) {
        console.log("Retrying connect");
        this.notifyStatusChange?.(Status.Reconnecting);
        this.establishSession();
      }
      await wait;
      this.reportDone = undefined;
    }
    this.retryingConnect = false;
  }

  async checkUsernameExists(username: string) {
    const { exists }: { exists: boolean } = await this.request(SocketEvents.UsernameExists, { username });
    return exists;
  }

  async userLogInPermitted(username: string): Promise<{ tries: number, allowsAt: number }> {
    return await this.request(SocketEvents.UserLoginPermitted, { username });
  }

  async registerNewUser(username: string, password: string, displayName: string, profilePicture: string, savePassword: boolean): Promise<Failure> {
    if (!this.isConnected) return failure(ErrorStrings.NoConnectivity);
    this.notifyStatusChange?.(Status.CreatingNewUser);
    try {
      displayName ??= username;
      const encryptionBaseVector = getRandomVector(64);
      const encryptionBase = await this.encrypt(username, password, encryptionBaseVector, "Encryption Base");
      const serverProof = await this.encrypt(username, password, serialize({ username }), "Server Proof");
      this.#encryptionBaseVector = await crypto.importRaw(encryptionBaseVector);
      const x3dhUser = await X3DHUser.new(username, this.#encryptionBaseVector);
      if (!x3dhUser) {
        this.notifyStatusChange?.(Status.FailedCreateNewUser);
        return failure(ErrorStrings.ProcessFailed);
      }
      const keyBundles = await x3dhUser.publishKeyBundles();
      const x3dhInfo = await x3dhUser.exportUser();
      const userDetails = await crypto.encryptData({ profilePicture, displayName }, this.#encryptionBaseVector, "User Details");
      const newUserData: NewUserData = { username, userDetails, serverProof, encryptionBase, x3dhInfo, keyBundles };
      if (!x3dhInfo) {
        this.notifyStatusChange?.(Status.FailedCreateNewUser);
        return failure(ErrorStrings.ProcessFailed);
      }
      const response = await this.RequestAuthSetupKey({ username });
      if ("reason" in response) {
        this.notifyStatusChange?.(Status.FailedCreateNewUser);
        return response;
      }
      const keyData = await this.processAuthSetupKey(username, response);
      const newUserRequest = await this.createNewUserAuth(username, password, keyData, newUserData);
      let { reason } = await this.RegisterNewUser(newUserRequest);
      if (reason) {
        this.notifyStatusChange?.(Status.FailedCreateNewUser);
        return { reason };
      }
      this.#username = username;
      this.#displayName = displayName;
      this.#profilePicture = profilePicture;
      this.#x3dhUser = x3dhUser;
      await this.savePassword(savePassword, username, password);
      this.notifyStatusChange?.(Status.CreatedNewUser);
      this.notifyStatusChange(Status.SignedIn);
      return { reason: null };
    }
    catch(err) {
      logError(err);
      this.notifyStatusChange?.(Status.FailedCreateNewUser);
      return failure(ErrorStrings.ProcessFailed);
    }
  }

  async userLogIn(): Promise<Failure>
  async userLogIn(username: string, password: string, savePassword: boolean): Promise<Failure>;
  async userLogIn(username?: string, password?: string, savePassword?: boolean): Promise<Failure> {
    if (!this.isConnected) return failure(ErrorStrings.NoConnectivity);
    this.notifyStatusChange?.(Status.SigningIn);
    try {
      if (!username) {
        const savedDetails = JSON.parse(window.localStorage.getItem("SavedDetails"));
        if (!savedDetails) {
          await this.clearCookie();
          this.notifyStatusChange?.(Status.FailedSignIn);
          return failure(ErrorStrings.InvalidRequest);
        }
        const { saveToken, cookieSavedDetails  } = savedDetails;
        window.localStorage.removeItem("SavedDetails");
        if (!saveToken) {
          await this.clearCookie();
          this.notifyStatusChange?.(Status.FailedSignIn);
          return failure(ErrorStrings.InvalidRequest);
        }
        const details = await this.GetSavedDetails({ saveToken });
        await this.clearCookie();
        if ("reason" in details) {
          this.notifyStatusChange?.(Status.FailedSignIn);
          return details;
        }
        [username, password] = await this.extractSavedDetails(cookieSavedDetails, details);
        if (!username) {
          this.notifyStatusChange?.(Status.FailedSignIn);
          return failure(ErrorStrings.ProcessFailed);
        }
        savePassword = true;
      }
      const response = await this.InitiateAuthentication({ username });
      if ("reason" in response) {
        this.notifyStatusChange?.(Status.FailedSignIn);
        return response;
      }
      const keyData = await this.processAuthSetupKey(username, response.newAuthSetup);
      const result = await this.createNewAuth(username, password, keyData, response);
      if (!result) {
        this.notifyStatusChange?.(Status.FailedSignIn);
        return failure(ErrorStrings.ProcessFailed);
      }
      const [concludeRequest, encryptionBaseVector] = result;
      this.#encryptionBaseVector = await crypto.importRaw(encryptionBaseVector);
      const concludeResponse = await this.ConcludeAuthentication(concludeRequest);
      if ("reason" in concludeResponse) {
        this.notifyStatusChange?.(Status.FailedSignIn);
        return concludeResponse;
      }
      if (deserialize(await this.decrypt(username, password, response.authInfo.serverProof, "Server Proof")).username !== username) {
        this.notifyStatusChange?.(Status.FailedSignIn);
        return failure(ErrorStrings.ProcessFailed);
      }
      const { userDetails, x3dhInfo } = concludeResponse;
      await this.savePassword(savePassword, username, password);
      const x3dhUser = await X3DHUser.importUser(x3dhInfo, this.#encryptionBaseVector);
      if (!x3dhUser) {
        this.notifyStatusChange?.(Status.FailedSignIn);
        return failure(ErrorStrings.ProcessFailed);
      }
      const { displayName, profilePicture } = await crypto.decryptData(userDetails, this.#encryptionBaseVector, "User Details");
      this.#username = username;
      this.#displayName = displayName;
      this.#profilePicture = profilePicture;
      this.#x3dhUser = x3dhUser;
      for (const { sessionId, timestamp, otherUser, firstMessage } of this.#x3dhUser.pendingMessageRequests) {
        this.addAwaitedRequest({ sessionId, otherUser, lastActivity: timestamp, message: { messageId: "0-0", content: firstMessage, timestamp, sentByMe: true, delivery: { delivered: false, seen: false } } });
      }
      this.notifyStatusChange(Status.SignedIn);
      this.loadChats();
      this.loadRequests();
      return { reason: null };
    }
    catch(err) {
      logError(err);
      this.notifyStatusChange?.(Status.FailedSignIn);
      return failure(ErrorStrings.ProcessFailed);
    }
  }

  async sendMessageRequest(otherUser: string, firstMessage: string, madeAt: number): Promise<Failure> {
    if (!this.isConnected) return failure(ErrorStrings.NoConnectivity);
    if (!(await this.checkUsernameExists(otherUser))) return failure(ErrorStrings.InvalidRequest);
    const keyBundleResponse = await this.RequestKeyBundle({ username: otherUser });
    if ("reason" in keyBundleResponse) {
      logError(keyBundleResponse);
      return keyBundleResponse;
    }
    const { keyBundle } = keyBundleResponse;
    const { displayName, profilePicture } = this;
    const pendingRequest = await this.#x3dhUser.generateMessageRequest(keyBundle, firstMessage, madeAt, { displayName, profilePicture }, async (messageRequest) => {
      const result = await this.SendMessageRequest(messageRequest);
      if (result.reason) {
        logError(result);
        return false;
      }
      return true;
    });
    if (typeof pendingRequest === "string") {
      logError(pendingRequest);
      return failure(ErrorStrings.ProcessFailed, pendingRequest);
    }
    const { sessionId, timestamp } = pendingRequest;
    this.addAwaitedRequest({ sessionId, otherUser, lastActivity: timestamp, message: { messageId: "0-0", content: firstMessage, timestamp, sentByMe: true, delivery: { delivered: false, seen: false } } });
    return { reason: null };
  }

  async userLogOut(): Promise<Failure> {
    if (!this.#username && !this.isConnected) return;
    this.notifyStatusChange?.(Status.SigningOut);
    const username = this.#username;
    this.#username = null;
    this.#displayName = null;
    this.#x3dhUser = null;
    this.#encryptionBaseVector = null;
    await this.request(SocketEvents.LogOut, { username });
    this.notifyStatusChange?.(Status.SignedOut);
    await this.retryConnect("");
  }

  async terminateCurrentSession(end = true) {
    await new Promise((resolve, _) => this.#socket.emit(SocketEvents.TerminateCurrentSession, "", resolve));
    console.log(`Terminating session: reference #${this.#sessionReference}`);
    this.#displayName = null;
    this.#username = null;
    this.#x3dhUser = null;
    this.#sessionReference = null;
    this.#sessionCrypto = null;
    if (!end) {
      await this.retryConnect("");
    }
  }

  private async encrypt(username: string, password: string, data: Buffer, purpose: string): Promise<PasswordEncryptedData> {
    const [masterKeyBits, pInfo] = await crypto.deriveMasterKeyBits(`${username}#${password}`);
    const hSalt = getRandomVector(48);
    const encrypted = await crypto.deriveSignEncrypt(masterKeyBits, data, hSalt, purpose);
    return { ...encrypted, ...pInfo, hSalt };
  }

  private async decrypt(username: string, password: string, data: PasswordEncryptedData, purpose: string) {
    const { ciphertext, hSalt, ...pInfo } = data;
    const masterKeyBits = await crypto.deriveMasterKeyBits(`${username}#${password}`, pInfo);
    return await crypto.deriveDecryptVerify(masterKeyBits, ciphertext, hSalt, purpose);
  }

  private async processAuthSetupKey(username: string, authSetupKey: AuthSetupKey): Promise<AuthSetupKeyData> {
    const { authKeyData: { ciphertext }, dInfo: { hSalt, ...pInfo } } = authSetupKey;
    const userKeyBits = await crypto.deriveMasterKeyBits(username, pInfo);
    return deserialize(await crypto.deriveDecryptVerify(userKeyBits, ciphertext, hSalt, "AuthKeyData"));
  }

  private async createNewUserAuth(username: string, password: string, keyData: AuthSetupKeyData, userData: NewUserData): Promise<RegisterNewUserRequest> {
    const { newAuthReference, hSaltAuth, hSaltEncrypt, pInfo } = keyData;
    const newAuthBits = await crypto.deriveMasterKeyBits(`${username}#${password}`, pInfo);
    const signingKey = await crypto.deriveMACKey(newAuthBits, hSaltAuth, "NewUserVerify", 512);
    const newUserData = await crypto.deriveSignEncrypt(newAuthBits, serialize(userData), hSaltEncrypt, "NewUser", signingKey);
    return { newAuthReference, newUserData, newAuthBits };
  }

  private async createNewAuth(username: string, password: string, keyData: AuthSetupKeyData, response: InitiateAuthenticationResponse): Promise<[ConcludeAuthenticationRequest, Buffer]> {
    const { currentAuthReference, authInfo: { pInfo: currentPInfo, encryptionBase: oldBase } } = response;
    const { newAuthReference, hSaltAuth, hSaltEncrypt, pInfo } = keyData;
    const encryptionBaseVector = await this.decrypt(username, password, oldBase, "Encryption Base");
    const serverProof = await this.encrypt(username, password, serialize({ username }), "Server Proof");
    const encryptionBase = await this.encrypt(username, password, encryptionBaseVector, "Encryption Base");
    const currentAuthBits = await crypto.deriveMasterKeyBits(`${username}#${password}`, currentPInfo);
    const newAuthBits = await crypto.deriveMasterKeyBits(`${username}#${password}`, pInfo);
    const authChange: AuthChangeData = { username, newAuthBits, encryptionBase, serverProof };
    const signingKey = await crypto.deriveMACKey(currentAuthBits, hSaltAuth, "AuthChangeVerify", 512);
    const authChangeData = await crypto.deriveSignEncrypt(currentAuthBits, serialize(authChange), hSaltEncrypt, "AuthChange", signingKey);
    const request: ConcludeAuthenticationRequest = { currentAuthReference, newAuthReference, currentAuthBits, authChangeData };
    return [request, encryptionBaseVector];
  }

  private async createSavedDetails(username: string, password: string) {
    const saveToken = getRandomString();
    const keyBits = getRandomVector(32);
    const hSalt = getRandomVector(48);
    const { ciphertext } = await crypto.deriveSignEncrypt(keyBits, serialize({ username, password }), hSalt, "Cookie Saved Details");
    const cookieSavedDetails = ciphertext.toString("base64");
    const savedDetails: SavedDetails = { saveToken, keyBits, hSalt, url: this.url };
    return { cookieSavedDetails, savedDetails };
  }

  private async extractSavedDetails(cookieSavedDetails: string, savedDetails: SavedDetails): Promise<[string, string]> {
    const { hSalt, keyBits } = savedDetails;
    const ciphertext = Buffer.from(cookieSavedDetails, "base64");
    const { username, password } = deserialize(await crypto.deriveDecryptVerify(keyBits, ciphertext, hSalt, "Cookie Saved Details"));
    return [username, password];
  }

  private async savePassword(savePassword: boolean, username: string, password: string) {
    if (savePassword) {
      const { cookieSavedDetails, savedDetails } = await this.createSavedDetails(username, password);
      const { saveToken } = savedDetails;
      const socketId = this.#socket.id;
      const sessionReference = this.#sessionReference;
      const response = await this.axInstance.post("/setSaveToken", { saveToken, socketId, sessionReference });
      if (response.status === 200) {
        const { reason } = await this.SetSavedDetails(savedDetails);
        if (!reason ) {
          window.localStorage.setItem("SavedDetails", stringify({ saveToken, cookieSavedDetails }));
        }
        else {
          await this.clearCookie();
        }
      }
    }
  }

  private async clearCookie() {
    const socketId = this.#socket.id;
    const sessionReference = this.#sessionReference;
    const response = await this.axInstance.post("/setSaveToken", { saveToken: "0", socketId, sessionReference });
    return response.status === 200;
  }

  private async loadChats() {
    const chatsData = await this.GetAllChats();
    if ("reason" in chatsData) return;
    const chats = await Promise.all(chatsData.map((chatData) => Chat.instantiate(this.#username, this.#encryptionBaseVector, this.chatInterface(chatData.sessionId), chatData)));
    for (const chat of chats) {
      this.addChat(chat);
    }
    await Promise.all(chats.map((chat) => this.requestRoom(chat)));
  }

  private async loadRequest(request: MessageRequestHeader) {
    const result = await this.#x3dhUser.viewMessageRequest(request);
    if (typeof result === "string") {
      logError(result);
      return false;
    }
    if (this.chatRequestsByUsername.has(result.profile.username)) {
      logError("Duplicate request.");
      this.rejectRequest(request.sessionId, request.yourOneTimeKeyIdentifier);
      return false;
    }
    const chatRequest = new ChatRequest(request, {
      respondToRequest: (request: MessageRequestHeader, respondingAt: number) => this.respondToRequest(request, respondingAt),
      rejectRequest: (sessionId: string, oneTimeKeyId: string) => this.rejectRequest(sessionId, oneTimeKeyId)
    }, result);
    this.addChatRequest(chatRequest);
    return true;
  }

  private async loadRequests() {
    const requests = await this.GetAllRequests();
    if ("reason" in requests) {
      logError(requests);
      return false;
    }
    const successes = await allSettledResults(requests.map((r) => this.loadRequest(r)));
    return successes.every((s) => s);
  }

  private async respondToRequest(request: MessageRequestHeader, respondingAt: number) {
    const { sessionId } = request;
    const { displayName, profilePicture } = this;
    const viewMessageRequest = await this.#x3dhUser.viewMessageRequest(request);
    const exportedChattingSession = await this.#x3dhUser.acceptMessageRequest(request, respondingAt, { displayName, profilePicture }, async (response) => {
      const sent = await this.SendMessage(response);
      if (sent.reason) {
        logError(sent);
        return false;
      }
      return true;
    });
    if (typeof exportedChattingSession === "string" || typeof viewMessageRequest === "string") {
      logError(exportedChattingSession);
      return false;
    }
    const { profile, firstMessage, timestamp } = viewMessageRequest;
    const lastActivity = respondingAt;
    const chatDetails = await crypto.encryptData(profile, this.#encryptionBaseVector, "ContactDetails");
    const chatData = { chatDetails, exportedChattingSession, lastActivity, sessionId };
    await this.CreateChat(chatData);
    const newChat = await Chat.instantiate(this.#username, this.#encryptionBaseVector, this.chatInterface(sessionId), chatData, { content: firstMessage, timestamp });
    this.addChat(newChat);
    return true;
  }

  private async rejectRequest(sessionId: string, oneTimeKeyId: string) {
    const result = await this.DeleteMessageRequest({ sessionId });
    if (result.reason) {
      logError(result);
      return false;
    }
    this.#x3dhUser.disposeOneTimeKey(oneTimeKeyId);
    this.removeChatRequest(sessionId, "sessionId");
    return true;
  }

  private async receiveRequestResponse(message: MessageHeader) {
    const { sessionId } = message;
    const awaitedRequest = this.awaitedRequestsBySessionId.get(sessionId);
    if (!awaitedRequest) {
      return false;
    }
    const result = await this.#x3dhUser.receiveMessageRequestResponse(message);
    if (typeof result === "string") {
      logError(result);
      return false;
    }
    const [{ profile, respondedAt }, exportedChattingSession] = result;
    const { message: { content, timestamp } } = awaitedRequest;
    const chatDetails = await crypto.encryptData(profile, this.#encryptionBaseVector, "ContactDetails");
    const chatData = { chatDetails, exportedChattingSession, lastActivity: respondedAt, sessionId };
    await this.CreateChat(chatData);
    const newChat = await Chat.instantiate(this.#username, this.#encryptionBaseVector, this.chatInterface(sessionId), chatData, { content, timestamp, delivery: respondedAt });
    this.addChat(newChat);
    this.removeAwaitedRequest(sessionId, "sessionId");
    await this.requestRoom(newChat);
    return true;
  }

  private SetSavedDetails(data: SavedDetails, timeout = 0): Promise<Failure> { 
    return this.request(SocketEvents.SetSavedDetails, data, timeout);
  }

  private GetSavedDetails(data: { saveToken: string }, timeout = 0): Promise<SavedDetails | Failure> { 
    return this.request(SocketEvents.GetSavedDetails, data, timeout);
  }

  private RequestAuthSetupKey(data: Username, timeout = 0): Promise<AuthSetupKey | Failure> { 
    return this.request(SocketEvents.RequestAuthSetupKey, data, timeout);
  }
  
  private RegisterNewUser(data: RegisterNewUserRequest, timeout = 0): Promise<Failure> { 
    return this.request(SocketEvents.RegisterNewUser, data, timeout);
  }
  
  private InitiateAuthentication(data: Username, timeout = 0): Promise<InitiateAuthenticationResponse | Failure> { 
    return this.request(SocketEvents.InitiateAuthentication, data, timeout);
  }
  
  private ConcludeAuthentication(data: ConcludeAuthenticationRequest, timeout = 0): Promise<SignInResponse | Failure> { 
    return this.request(SocketEvents.ConcludeAuthentication, data, timeout);
  }
  
  private PublishKeyBundles(data: PublishKeyBundlesRequest, timeout = 0): Promise<Failure> { 
    return this.request(SocketEvents.PublishKeyBundles, data, timeout);
  }
  
  private RequestKeyBundle(data: Username, timeout = 0): Promise<RequestKeyBundleResponse | Failure> { 
    return this.request(SocketEvents.RequestKeyBundle, data, timeout);
  }

  private SendMessageRequest(data: MessageRequestHeader, timeout = 0): Promise<Failure> {
    return this.request(SocketEvents.SendMessageRequest, data, timeout);
  }

  private GetAllChats(timeout = 0): Promise<ChatData[] | Failure> {
    return this.request(SocketEvents.GetAllChats, {}, timeout);
  }

  private GetAllRequests(timeout = 0): Promise<MessageRequestHeader[] | Failure> {
    return this.request(SocketEvents.GetAllRequests, {}, timeout);
  }

  private SendMessage(data: MessageHeader, timeout = 0): Promise<Failure> {
    return this.request(SocketEvents.SendMessage, data, timeout);
  }
 
  private CreateChat(data: ChatData, timeout = 0): Promise<Failure> {
    return this.request(SocketEvents.CreateChat, data, timeout);
  }

  private DeleteMessageRequest(data: { sessionId: string }, timeout = 0): Promise<Failure> {
    return this.request(SocketEvents.DeleteMessageRequest, data, timeout);
  }
  
  private RequestRoom(data: Username & EstablishData, timeout = 0): Promise<EstablishData | Failure> { 
    return this.request(SocketEvents.RequestRoom, data, timeout);
  }

  private async request(event: SocketEvents, data: any, timeout = 0): Promise<any | Failure> {
    if (!this.isConnected) {
      return {};
    }
    return new Promise(async (resolve: (result: any) => void) => {
      data = { ...data, fileHash: await this.#fileHash, url: this.url };
      this.#socket.emit(event, (await this.#sessionCrypto.signEncrypt(data, event)).toString("base64"), 
      async (response: string) => resolve(response ? await this.#sessionCrypto.decryptVerify(Buffer.from(response, "base64"), event) : {}));
      if (timeout > 0) {
        window.setTimeout(() => resolve({}), timeout);
      }
    })
  }

  private async respond(event: string, data: string, responseBy: (arg0: any) => any, respondAt: (arg0: string) => void) {
    const respond = async (response: any) => {
      respondAt(Buffer.from(await this.#sessionCrypto.signEncrypt(response, event)).toString("base64"));
    }
    try {
      const decryptedData = await this.#sessionCrypto.decryptVerify(Buffer.from(data, "base64"), event);
      if (!decryptedData) await respond(failure(ErrorStrings.DecryptFailure));
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

  private async roomRequested({ username, sessionReference, publicKey, verifyingKey }: Username & EstablishData) {
    if (username === this.#username) return failure(ErrorStrings.InvalidRequest);
    const chat = this.chatsByUsername.get(username);
    if (!chat) return failure(ErrorStrings.InvalidRequest);
    const { privateKey, publicKey: myPublicKey } = await crypto.generateKeyPair("ECDH");
    const { privateKey: signingKey, publicKey: myVerifyingKey } = await crypto.generateKeyPair("ECDSA");
    const otherPublicKey = await crypto.importKey(publicKey, "ECDH", "public", true);
    const otherVerifyingKey = await crypto.importKey(verifyingKey, "ECDSA", "public", true);
    const sessionKeyBits = await crypto.deriveSymmetricBits(privateKey, otherPublicKey, 512);
    chat.establishRoom(new SessionCrypto(sessionReference, sessionKeyBits, signingKey, otherVerifyingKey), this.#socket);
    return { sessionReference, publicKey: await crypto.exportKey(myPublicKey), verifyingKey: await crypto.exportKey(myVerifyingKey) };
  }

  private async requestRoom(chat: Chat) {
    const sessionReference = getRandomString();
    const { privateKey, publicKey: myPublicKey } = await crypto.generateKeyPair("ECDH");
    const { privateKey: signingKey, publicKey: myVerifyingKey } = await crypto.generateKeyPair("ECDSA");
    const data = { username: chat.otherUser, sessionReference, publicKey: await crypto.exportKey(myPublicKey), verifyingKey: await crypto.exportKey(myVerifyingKey) };
    const response = await this.RequestRoom(data);
    if ("reason" in response) {
      return response;
    }
    const { sessionReference: ref, publicKey, verifyingKey } = response;
    if (ref !== sessionReference) {
      return failure(ErrorStrings.InvalidReference);
    }
    const otherPublicKey = await crypto.importKey(publicKey, "ECDH", "public", true);
    const otherVerifyingKey = await crypto.importKey(verifyingKey, "ECDSA", "public", true);
    const sessionKeyBits = await crypto.deriveSymmetricBits(privateKey, otherPublicKey, 512);
    const confirmed = await chat.establishRoom(new SessionCrypto(sessionReference, sessionKeyBits, signingKey, otherVerifyingKey), this.#socket);
    if (!confirmed) return failure(ErrorStrings.ProcessFailed);
    return { reason: null };
  }

  private async messageReceived(message: MessageHeader) {
    const { sessionId } = message;
    return await match(this.chatSessionIdsList.get(sessionId))
      .with("Chat", () => this.chatsBySessionId.get(sessionId)?.messageReceived(message))
      .with("AwaitedRequest", () => this.receiveRequestResponse(message))
      .otherwise(async () => false);
  }

  private async messageRequestReceived(message: MessageRequestHeader) {
    return await this.loadRequest(message);
  }

  private async messageEventLogged(messageEvent: MessageEvent) {
    const { sessionId, messageId, event, timestamp } = messageEvent;
    const chat = this.chatsBySessionId.get(sessionId);
    if (!chat) {
      logError("No chat found corresponding to event.")
      return false;
    }
    return await chat.sendEvent(event, messageId, timestamp);
  }
}

export class Chat {
  private disposed = false;
  private readonly loadingBatch = 10;
  private loadedUpto = Date.now();
  private lastActivityTimestamp: number;
  private typing: boolean;
  private typingTimeout: number;
  private readonly notifyChange = new Map<string, () => void>();
  private readonly messagesList: DisplayMessage[] = [];
  private readonly clientInterface: ClientChatInterface;
  private chatDetails: UserEncryptedData;
  readonly sessionId: string;
  readonly me: string;
  readonly otherUser: string;
  readonly contactDetails: Omit<Contact, "username">;
  readonly #chattingSession: ChattingSession;
  readonly #encryptionBaseVector: CryptoKey;
  #sessionCrypto: SessionCrypto;
  #socket: Socket;

  get hasRoom() { return !!this.#sessionCrypto; }

  get lastActivity() { return this.lastActivityTimestamp; }

  get messages() { return Array.from(this.messagesList); }

  get isTyping() { return this.typing; }

  private set isTyping(value: boolean) {
    window.clearTimeout(this.typingTimeout);
    if (this.typing !== value) {
      this.typing = value;
      this.notify();
    }
    if (value) {
      this.typingTimeout = window.setTimeout(() => {
        this.typing = false;
        this.notify();
      }, 3000);
    }
  }

  subscribe(key: string, notifyChange: () => void) {
    this.notifyChange.set(key, notifyChange);
  }

  unsubscribe(key: string) {
    this.notifyChange.delete(key);
  }

  dispose() {
    this.#socket?.off(this.otherUser);
    this.#socket = null;
    this.#sessionCrypto = null;
    this.notifyChange.clear();
    this.disposed = true;
  }

  private notify() {
    for (const notify of this.notifyChange.values()) {
      notify();
    }
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

  static async instantiate(me: string, encryptionBaseVector: CryptoKey, clientInterface: ClientChatInterface, chatData: ChatData, firstMessage?: { content: string, timestamp: number, delivery?: number }) {
    const { chatDetails, exportedChattingSession, lastActivity, sessionId } = chatData;
    const contactDetails: Contact = await crypto.decryptData(chatDetails, encryptionBaseVector, "ContactDetails");
    const chattingSession = await ChattingSession.importSession(exportedChattingSession, encryptionBaseVector);
    const chat = new Chat(sessionId, me, contactDetails, encryptionBaseVector, clientInterface, chattingSession);
    chat.lastActivityTimestamp = lastActivity;
    chat.chatDetails = chatDetails;
    if (firstMessage) {
      const { content, timestamp, delivery } = firstMessage;
      await chat.encryptStoreMessage({ messageId: "0", sentByMe: true, content, timestamp } , delivery, delivery);
    }
    chat.loadNext().then(() => chat.loadUnprocessedMessages());
    return chat;
  }

  async establishRoom(sessionCrypto: SessionCrypto, socket: Socket) {
    if (this.disposed) {
      return false;
    }
    socket.emit(SocketEvents.RoomEstablished, this.otherUser);
    const confirmed = await new Promise((resolve) => {
      socket.once(this.otherUser, (confirmation: string) => resolve(confirmation === "confirmed"))
      window.setTimeout(() => resolve(false), 20000);
    })
    if (!confirmed) {
      socket.off(this.otherUser);
      return false;
    }
    this.#sessionCrypto = sessionCrypto;
    this.#socket = socket;
    this.#socket.on(this.otherUser, this.receiveMessage.bind(this));
    this.#socket.on("disconnect", () => {
      this.dispose();
    })
    this.loadUnprocessedMessages();
    this.notify();
  }

  async sendMessage(content: string, timestamp: number, replyId?: string) {
    if (this.disposed) {
      return false;
    }
    const sentByMe = true;
    const replyingTo = await this.populateReplyingTo(replyId);
    if (replyingTo === undefined) {
      logError("Failed to come up with replied-to message.");
      return false;
    }
    const messageId = this.#chattingSession.nextMessageId;
    const displayMessage: DisplayMessage = { messageId, timestamp, content, replyingTo, sentByMe, delivery: null };
    this.addMessageToList(displayMessage);
    const encryptedMessage = crypto.encryptData(displayMessage, this.#encryptionBaseVector, this.sessionId).then((content) => ({ messageId, timestamp, content }));
    const exportedChattingSession = await this.#chattingSession.sendMessage({ content, timestamp, replyingTo: replyId }, 
      async (message) => {
        let tries = 0;
        let success = false;
        if (this.hasRoom) {
          while (!success && tries <= 10) {
            tries++;
            success = await new Promise<boolean>((resolve) => {
              this.#socket.emit(this.otherUser, message, (response: boolean) => resolve(response));
            });
          }
        }
        else {
          while (!success && tries <= 10) {
            tries++;
            success = !(await this.clientInterface.SendMessage(message)).reason;
          }
        }
        if (success) {
          await this.clientInterface.StoreMessage(await encryptedMessage);
          displayMessage.delivery = {};
          this.notify();
          return success;
        }
    });
    if (exportedChattingSession) {
      const { lastActivity, chatDetails } = this;
      await this.clientInterface.UpdateChat({ lastActivity, chatDetails, exportedChattingSession });
      return true;
    }
    return false;
  }

  async sendEvent(event: "typing" | "stopped-typing"): Promise<boolean>;
  async sendEvent(event: "delivered" | "seen", messageId: string, timestamp: number): Promise<boolean>;
  async sendEvent(event: "typing" | "stopped-typing" | "delivered" | "seen", messageId?: string, timestamp?: number): Promise<boolean> {
    if (this.disposed) {
      return false;
    }
    if (this.hasRoom) {
      return await new Promise<boolean>((resolve) => {
        this.#socket.emit(this.otherUser, { event, messageId, timestamp }, (response: boolean) => resolve(response));
      });
    }
    else {
      if (event === "seen" || event === "delivered") {
        return !(await this.clientInterface.SendMessageEvent({ addressedTo: this.otherUser, event, messageId, timestamp })).reason;
      }
    }
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
    return await this.openEncryptedMessage(message);    
  }

  private addMessageToList(message: DisplayMessage) {
    this.messagesList.push(message);
    this.notify();
    if (message.timestamp < this.loadedUpto) {
      this.loadedUpto = message.timestamp;
    }
  }

  private async receiveMessage(data: string, ack: (recv: boolean) => void) {
    if (!data) {
      ack(false);
      return;
    }
    if (data === "disconnected") {
      this.#socket?.off(this.otherUser);
      this.#socket = null;
      this.#sessionCrypto = null;
      return;
    }
    try {
      const decryptedData: MessageHeader | ChatEvent = await this.#sessionCrypto.decryptVerify(Buffer.from(data, "base64"), this.me);
      if (!decryptedData) {
        ack(false);
      }
      else if ("event" in decryptedData) {
        const { event } = decryptedData;
        if (event === "typing") {
          this.isTyping = true;
          ack(true);
        }
        else if (event === "stopped-typing") {
          this.isTyping = false;
          ack(true);
        }
        else {
          const { timestamp, messageId } = decryptedData;
          const message = this.messagesList.find((m) => m.messageId === messageId);
          const delivery = event === "delivered" ? { delivered: timestamp } : { seen: timestamp };
          if (message.sentByMe) {
            message.delivery = { ...message.delivery, ...delivery };
          }
          this.notify();
          await this.clientInterface.UpdateMessage({ messageId, timestamp, event });
          ack(true);
        }
      }
      else {
        ack(await this.openEncryptedMessage(decryptedData));
      }
    }
    catch(e: any) {
      logError(e);
      ack(false);
    }
  }

  private async decryptPushMessages(messages: StoredMessage[]) {
    await Promise.all(messages.map(async (message) => {
      const { messageId, timestamp, content: encryptedContent, delivered, seen } = message;
      const { content, replyingTo, sentByMe }: PlainMessage = await crypto.decryptData(encryptedContent, this.#encryptionBaseVector, this.sessionId);
      const rest = { messageId, timestamp, content, replyingTo };
      const displayMessage: DisplayMessage = sentByMe 
                                              ? { sentByMe, delivery: { delivered, seen }, ...rest }
                                              : { sentByMe, ...rest };
      this.addMessageToList(displayMessage);
    }));
  }

  private async encryptStoreMessage(message: PlainMessage, delivered?: number, seen?: number) {
    const { messageId, timestamp } = message;
    const encryptedContent = await crypto.encryptData(message, this.#encryptionBaseVector, this.sessionId);
    const encryptedMessage = { messageId, timestamp, content: encryptedContent, delivered, seen };
    await this.clientInterface.StoreMessage(encryptedMessage); 
  }

  private async openEncryptedMessage(encryptedMessage: MessageHeader): Promise<boolean> {
    const exportedChattingSession = await this.#chattingSession.receiveMessage(encryptedMessage, async (messageBody) => {
      const { sender, recipient, messageId, replyingTo: replyId, timestamp, content } = messageBody;
      if (sender !== this.otherUser || recipient === this.me) {
        return false;
      }
      const replyingTo = await this.populateReplyingTo(replyId);
      if (replyingTo === undefined) {
        logError("Failed to come up with replied-to message.");
        return false;
      }
      const newMessage: PlainMessage = { messageId, timestamp, content, replyingTo, sentByMe: false };
      this.addMessageToList(newMessage);
      await this.encryptStoreMessage(newMessage);
      return true;
    });
    if (typeof exportedChattingSession === "string") {
      logError(exportedChattingSession);
      return false;
    };
    const { lastActivity, chatDetails } = this;
    await this.clientInterface.UpdateChat({ lastActivity, chatDetails, exportedChattingSession });
    return true;
  }

  private async populateReplyingTo(id: string): Promise<{ id: string, replyToOwn: boolean, displayText: string }> {
    if (!id) return null;
    let repliedTo = this.messagesList.find((m) => m.messageId === id);
    if (!repliedTo) {
      const fetched = await this.clientInterface.GetMessageById({ messageId: id });
      if ("reason" in fetched) {
        logError(fetched);
        return undefined;
      };
      repliedTo = await crypto.decryptData(fetched.content, this.#encryptionBaseVector, this.sessionId);
    }
    const replyToOwn = repliedTo.sentByMe;
    const displayText = truncateText(repliedTo.content);
    return { id, replyToOwn, displayText };
  }

  private async loadUnprocessedMessages() {
    let unprocessedMessages = await this.clientInterface.GetUnprocessedMessages();
    if ("reason" in unprocessedMessages) {
      logError(unprocessedMessages.reason);
      return;
    }
    unprocessedMessages = _.sortBy(unprocessedMessages, ["sendingRatchetNumber", "sendingChainNumber"]);
    for (const message of unprocessedMessages) {
      await this.openEncryptedMessage(message);
    }
  }
}

export class ChatRequest {
  readonly otherUser: string;
  readonly contactDetails: Readonly<{ displayName: string, contactName?: string, profilePicture: string }>;
  readonly message: DisplayMessage;
  readonly lastActivity: number;
  readonly sessionId: string;
  private readonly messageRequestHeader: MessageRequestHeader;
  private readonly clientInterface: ClientChatRequestInterface;

  constructor(messageRequestHeader: MessageRequestHeader, clientInterface: ClientChatRequestInterface, viewRequest: ViewMessageRequest) {
    const { firstMessage, timestamp, profile: { username: otherUser, ...contactDetails } } = viewRequest;
    this.sessionId = messageRequestHeader.sessionId;
    this.otherUser = otherUser;
    this.contactDetails = contactDetails;
    this.message = { messageId: "0.0", content: firstMessage, timestamp, sentByMe: false };
    this.lastActivity = timestamp;
    this.messageRequestHeader = messageRequestHeader;
    this.clientInterface = clientInterface;
  }

  async rejectRequest () {
    return await this.clientInterface.rejectRequest(this.otherUser, this.sessionId, this.messageRequestHeader.yourOneTimeKeyIdentifier);
  }
  async respondToRequest (response: string, respondingAt: number) {
    return await this.clientInterface.respondToRequest(this.messageRequestHeader, respondingAt);
  }
}

function sleep(timeInMillis: number) {
  return new Promise((resolve, _) => { window.setTimeout(() => resolve(null), timeInMillis); });
}

function logError(err: any): void {
  const message = err.message;
  const stack = err.stack;
  if (message || stack) {
    console.log(`${message}${stack}`);
  }
  else {
    console.log(`${stringify(err)}`);
  }
}

function truncateText(text: string) {
  const maxChar = 200;
  if (!text) return null;
  if (text.length <= maxChar) return text;
  const truncate = text.indexOf(" ", maxChar);
  return `${ text.slice(0, truncate) } ...`;
}

async function allSettledResults<T>(promises: Promise<T>[]) {
  return (await Promise.allSettled(promises)).filter((result) => result.status === "fulfilled").map((result) => (result as PromiseFulfilledResult<T>).value);
}