import _ from "lodash";
import { match } from "ts-pattern";
import axios, { Axios } from "axios";
import { io, Socket } from "socket.io-client";
import { Buffer } from "./node_modules/buffer";
import { stringify } from "safe-stable-stringify";
import { SessionCrypto } from "../../shared/sessionCrypto";
import { ChattingSession, SendingMessage, ViewChatRequest, ViewPendingRequest, X3DHUser } from "./e2e-encryption";
import * as crypto from "../../shared/cryptoOperator";
import { serialize, deserialize } from "../../shared/cryptoOperator";
import { ErrorStrings, Failure, Username, AuthSetupKey, UserEncryptedData, RegisterNewUserRequest, InitiateAuthenticationResponse, ConcludeAuthenticationRequest, SignInResponse, PublishKeyBundlesRequest, RequestKeyBundleResponse, SocketEvents, randomFunctions, failure, SavedDetails, PasswordEncryptedData, AuthSetupKeyData, NewUserData, AuthChangeData, MessageHeader, ChatRequestHeader, StoredMessage, ChatData, DisplayMessage, Contact, ReplyingToInfo, DeliveryInfo } from "../../shared/commonTypes";

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

export type AwaitedRequest = Readonly<{
  sessionId: string,
  otherUser: string,
  lastActivity: number,
  message: DisplayMessage,
  type: "AwaitedRequest"
}>;

type ClientChatInterface = Readonly<{
  SendMessage: (data: MessageHeader, timeout?: number) => Promise<Failure>,
  GetUnprocessedMessages: (timeout?: number) => Promise<MessageHeader[] | Failure>,
  GetMessagesByNumber: (data: { limit: number, olderThan?: number }, timeout?: number) => Promise<StoredMessage[] | Failure>,
  GetMessagesUptoTimestamp: (data: { newerThan: number, olderThan?: number }, timeout?: number) => Promise<StoredMessage[] | Failure>,
  GetMessagesUptoId: (data: { messageId: string, olderThan?: number }, timeout?: number) => Promise<StoredMessage[] | Failure>,
  GetMessageById: (data: { messageId: string }, timeout?: number) => Promise<StoredMessage | Failure>,
  StoreMessage: (data: Omit<StoredMessage, "sessionId">, timeout?: number) => Promise<Failure>,
  UpdateChat: (data: Omit<ChatData, "sessionId">, timeout?: number) => Promise<Failure>
}>;

type ClientChatRequestInterface = Readonly<{
  rejectRequest: (otherUser: string, sessionId: string, oneTimeKeyId: string) => Promise<boolean>,
  respondToRequest: (request: ChatRequestHeader, respondingAt: number) => Promise<boolean>
}>

export class Client {
  private readonly responseMap: Map<SocketEvents, any> = new Map([
    [SocketEvents.RequestRoom, this.roomRequested] as [SocketEvents, any],
    [SocketEvents.MessageReceived, this.messageReceived],
    [SocketEvents.ChatRequestReceived, this.chatRequestReceived]
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
  #displayName: string;
  #profilePicture: string;
  #username: string;
  #x3dhUser: X3DHUser;
  #sessionReference: string;
  #sessionCrypto: SessionCrypto;
  #encryptionBaseVector: CryptoKey;
  #fileHash: Promise<string>;
  private readonly chatList: string[] = [];
  private readonly chatSessionIdsList = new Map<string, Chat | ChatRequest | AwaitedRequest>();
  private readonly chatUsernamesList = new Map<string, Chat | ChatRequest | AwaitedRequest>();

  private readonly chatInterface: (sessionId: string) => ClientChatInterface = (sessionId) => ({
    SendMessage: (data: MessageHeader, timeout = 0) => {
      return this.request(SocketEvents.SendMessage, data, timeout);
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
    UpdateChat: (data: Omit<ChatData, "sessionId">, timeout = 0) =>  {
      return this.request(SocketEvents.UpdateChat, { sessionId, ...data }, timeout);
    }
  })
 
  private addChat(chat: Chat | ChatRequest | AwaitedRequest) {
    this.chatSessionIdsList.set(chat.sessionId, chat);
    this.chatUsernamesList.set(chat.otherUser, chat);
    this.chatList.push(chat.otherUser);
    if (this.notifyChange && chat.type === "Chat") {
      chat.subscribe("client", this.notifyChange);
    }
    this.notifyChange?.();
  }
 
  private removeChat(key: string, keyType: "username" | "sessionId") {
    const chat = keyType === "username" ? this.chatUsernamesList.get(key) : this.chatSessionIdsList.get(key);
    this.chatSessionIdsList.delete(chat.sessionId);
    this.chatUsernamesList.delete(chat.otherUser);
    _.remove(this.chatList, ([user, _]) => user === chat.otherUser);
    if (chat.type === "Chat") {
      chat.dispose();
    }
    this.notifyChange?.();
  }

  public getChatByUser(otherUser: string): Chat | ChatRequest | AwaitedRequest {
    return this.chatUsernamesList.get(otherUser);
  }

  public getChatDetailsByUser(otherUser: string): { displayName?: string, contactName?: string, profilePicture?: string, lastActivity: number } {
    const chat = this.chatUsernamesList.get(otherUser);
    if (!chat) return null;
    const { lastActivity } = chat;
    if ("contactDetails" in chat) {
      const { contactDetails: { displayName, profilePicture, contactName } } = chat;
      return { displayName, contactName, profilePicture, lastActivity };
    }
    else {
      return { displayName: otherUser, lastActivity };
    }
  }

  public get chatsList() {
    return _.orderBy(this.chatList, [(chat) => this.getChatByUser(chat).lastActivity], ["desc"]);
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
      console.log(`Attempting to establish secure session.`);
      this.notifyClientEvent?.(ClientEvent.Connecting);
      this.connecting = true;
      const { privateKey, publicKey } = await crypto.generateKeyPair("ECDH");
      const { privateKey: signingKey, publicKey: verifyingKey } = await crypto.generateKeyPair("ECDSA");
      const sessionReference = this.#sessionReference ?? getRandomString();
      const publicDHKey = (await crypto.exportKey(publicKey)).toString("base64");
      const publicVerifyingKey = (await crypto.exportKey(verifyingKey)).toString("base64");
      const { serverPublicKey, verifyingKey: serverVerifying } = (await this.axInstance.post("/registerKeys", { sessionReference, publicDHKey, publicVerifyingKey }))?.data || {};
      const serverVerifyingKey = await crypto.importKey(fromBase64(serverVerifying), "ECDSA", "public", true);
      console.log(`ServerPublicKey: ${serverPublicKey}`);
      const serverPublicKeyImported = await crypto.importKey(fromBase64(serverPublicKey), "ECDH", "public", true);
      const sessionKeyBits = await crypto.deriveSymmetricBitsKey(privateKey, serverPublicKeyImported, 512);
      const fileHash = await this.#fileHash;
      const sessionSigned = await crypto.sign(fromBase64(sessionReference), signingKey);
      const auth = { sessionReference, sessionSigned, fileHash, url: this.url };
      this.#socket = io(this.url, { auth, withCredentials: true });
      this.#socket.on("disconnect", this.retryConnect.bind(this));
      let nevermind = false;
      let timeout: number = null;
      const success = await new Promise<boolean>((resolve) => {
        this.#socket.once(SocketEvents.CompleteHandshake, (ref, respond) => {
          const finalize = (complete: boolean) => {
            respond(complete);
            resolve(complete);
          }
          try {
            if (nevermind) {
              console.log("Nevermind");
              finalize(false);
              return;
            }
            if (ref !== sessionReference) {
              const reconnected = this.#sessionReference && ref === "1";
              finalize(reconnected);
              if (reconnected) {
                this.serverUnavailable = false;
              }
              else {
                window.history.go();
              }
              return;
            }
            this.#sessionReference = sessionReference;
            this.#sessionCrypto = new SessionCrypto(sessionReference, sessionKeyBits, signingKey, serverVerifyingKey);
            console.log(`Connected with session reference: ${sessionReference}`);
            if (this.#username) {
              this.notifyClientEvent?.(ClientEvent.SignedOut);
              this.#displayName = null;
              this.#username = null;
              this.#x3dhUser = null;
            }
            finalize(true);
          }
          catch(err) {
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
    while(!this.isConnected && !this.serverUnavailable || window.navigator.onLine) {
      const wait = new Promise((resolve, _) => { 
        this.reportDone = resolve;
        window.setTimeout(() => resolve(null), 10000); });
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
    const { exists }: { exists: boolean } = await this.request(SocketEvents.UsernameExists, { username });
    return exists;
  }

  async userLogInPermitted(username: string): Promise<{ tries: number, allowsAt: number }> {
    return await this.request(SocketEvents.UserLoginPermitted, { username });
  }

  async registerNewUser(username: string, password: string, displayName: string, profilePicture: string, savePassword: boolean): Promise<Failure> {
    if (!this.isConnected) return failure(ErrorStrings.NoConnectivity);
    this.notifyClientEvent?.(ClientEvent.CreatingNewUser);
    try {
      displayName ??= username;
      const encryptionBaseVector = getRandomVector(64);
      const encryptionBase = await this.encrypt(username, password, { encryptionBaseVector }, "Encryption Base");
      const serverProof = await this.encrypt(username, password, { username }, "Server Proof");
      this.#encryptionBaseVector = await crypto.importRaw(encryptionBaseVector);
      const x3dhUser = await X3DHUser.new(username, this.#encryptionBaseVector);
      if (!x3dhUser) {
        this.notifyClientEvent?.(ClientEvent.FailedCreateNewUser);
        return failure(ErrorStrings.ProcessFailed);
      }
      const keyBundles = await x3dhUser.publishKeyBundles();
      const x3dhInfo = await x3dhUser.exportUser();
      const userDetails = await crypto.deriveEncrypt({ profilePicture, displayName }, this.#encryptionBaseVector, "User Details");
      const newUserData: NewUserData = { username, userDetails, serverProof, encryptionBase, x3dhInfo, keyBundles };
      if (!x3dhInfo) {
        this.notifyClientEvent?.(ClientEvent.FailedCreateNewUser);
        return failure(ErrorStrings.ProcessFailed);
      }
      const response = await this.RequestAuthSetupKey({ username });
      if ("reason" in response) {
        this.notifyClientEvent?.(ClientEvent.FailedCreateNewUser);
        return response;
      }
      const keyData = await this.processAuthSetupKey(username, response);
      const newUserRequest = await this.createNewUserAuth(username, password, keyData, newUserData);
      let { reason } = await this.RegisterNewUser(newUserRequest);
      if (reason) {
        this.notifyClientEvent?.(ClientEvent.FailedCreateNewUser);
        return { reason };
      }
      this.#username = username;
      this.#displayName = displayName;
      this.#profilePicture = profilePicture;
      this.#x3dhUser = x3dhUser;
      await this.savePassword(savePassword, username, password);
      this.notifyClientEvent?.(ClientEvent.CreatedNewUser);
      this.notifyClientEvent(ClientEvent.SignedIn);
      return { reason: null };
    }
    catch(err) {
      logError(err);
      this.notifyClientEvent?.(ClientEvent.FailedCreateNewUser);
      return failure(ErrorStrings.ProcessFailed);
    }
  }

  async userLogIn(): Promise<Failure>
  async userLogIn(username: string, password: string, savePassword: boolean): Promise<Failure>;
  async userLogIn(username?: string, password?: string, savePassword?: boolean): Promise<Failure> {
    if (!this.isConnected) return failure(ErrorStrings.NoConnectivity);
    this.notifyClientEvent?.(ClientEvent.SigningIn);
    try {
      if (!username) {
        const savedDetails = JSON.parse(window.localStorage.getItem("SavedDetails"));
        if (!savedDetails) {
          await this.clearCookie();
          this.notifyClientEvent?.(ClientEvent.FailedSignIn);
          return failure(ErrorStrings.InvalidRequest);
        }
        const { saveToken, cookieSavedDetails  } = savedDetails;
        window.localStorage.removeItem("SavedDetails");
        if (!saveToken) {
          await this.clearCookie();
          this.notifyClientEvent?.(ClientEvent.FailedSignIn);
          return failure(ErrorStrings.InvalidRequest);
        }
        const details = await this.GetSavedDetails({ saveToken });
        await this.clearCookie();
        if ("reason" in details) {
          this.notifyClientEvent?.(ClientEvent.FailedSignIn);
          return details;
        }
        [username, password] = await this.extractSavedDetails(cookieSavedDetails, details);
        if (!username) {
          this.notifyClientEvent?.(ClientEvent.FailedSignIn);
          return failure(ErrorStrings.ProcessFailed);
        }
        savePassword = true;
      }
      const response = await this.InitiateAuthentication({ username });
      if ("reason" in response) {
        this.notifyClientEvent?.(ClientEvent.FailedSignIn);
        return response;
      }
      const keyData = await this.processAuthSetupKey(username, response.newAuthSetup);
      const result = await this.createNewAuth(username, password, keyData, response);
      if (!result) {
        this.notifyClientEvent?.(ClientEvent.FailedSignIn);
        return failure(ErrorStrings.ProcessFailed);
      }
      const [concludeRequest, encryptionBaseVector] = result;
      this.#encryptionBaseVector = await crypto.importRaw(encryptionBaseVector);
      const concludeResponse = await this.ConcludeAuthentication(concludeRequest);
      if ("reason" in concludeResponse) {
        this.notifyClientEvent?.(ClientEvent.FailedSignIn);
        return concludeResponse;
      }
      if ((await this.decrypt(username, password, response.authInfo.serverProof, "Server Proof")).username !== username) {
        this.notifyClientEvent?.(ClientEvent.FailedSignIn);
        return failure(ErrorStrings.ProcessFailed);
      }
      const { userDetails, x3dhInfo } = concludeResponse;
      await this.savePassword(savePassword, username, password);
      const x3dhUser = await X3DHUser.importUser(x3dhInfo, this.#encryptionBaseVector);
      if (!x3dhUser) {
        this.notifyClientEvent?.(ClientEvent.FailedSignIn);
        return failure(ErrorStrings.ProcessFailed);
      }
      const { displayName, profilePicture } = await crypto.deriveDecrypt(userDetails, this.#encryptionBaseVector, "User Details");
      this.#username = username;
      this.#displayName = displayName;
      this.#profilePicture = profilePicture;
      this.#x3dhUser = x3dhUser;
      for (const { sessionId, timestamp, otherUser, firstMessage } of this.#x3dhUser.pendingChatRequests) {
        const awaited: AwaitedRequest = { sessionId, otherUser, lastActivity: timestamp, message: { messageId: "i", content: firstMessage, timestamp, sentByMe: true, delivery: { delivered: false, seen: false } }, type: "AwaitedRequest" };
        this.addChat(awaited);
        const result = await this.GetUnprocessedMessages(sessionId);
        if ("reason" in result) {
          logError(result.reason);
          return;
        }
        const firstResponse = _.orderBy(result, ["timestamp"], ["asc"])[0];
        await this.receiveRequestResponse(firstResponse);
      }
      await this.loadChats();
      await this.loadRequests();
      this.notifyClientEvent(ClientEvent.SignedIn);
      return { reason: null };
    }
    catch(err) {
      logError(err);
      this.notifyClientEvent?.(ClientEvent.FailedSignIn);
      return failure(ErrorStrings.ProcessFailed);
    }
  }

  async sendChatRequest(otherUser: string, firstMessage: string, madeAt: number): Promise<Failure> {
    if (!this.isConnected) return failure(ErrorStrings.NoConnectivity);
    if (!(await this.checkUsernameExists(otherUser))) return failure(ErrorStrings.InvalidRequest);
    const keyBundleResponse = await this.RequestKeyBundle({ username: otherUser });
    if ("reason" in keyBundleResponse) {
      logError(keyBundleResponse);
      return keyBundleResponse;
    }
    const { keyBundle } = keyBundleResponse;
    const { displayName, profilePicture } = this;
    const result = await this.#x3dhUser.generateChatRequest(keyBundle, firstMessage, madeAt, { displayName, profilePicture }, async (chatRequest) => {
      const result = await this.SendChatRequest(chatRequest);
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
    const { reason } = await this.UpdateX3DHUser({ x3dhInfo, username: this.username });
    if (reason) {
      logError(reason);
      return failure(ErrorStrings.ProcessFailed);
    }
    this.addChat({ sessionId, otherUser, lastActivity: timestamp, message: { messageId: "i", content: firstMessage, timestamp, sentByMe: true, delivery: { delivered: false, seen: false } }, type: "AwaitedRequest" });
    return { reason: null };
  }

  async userLogOut(): Promise<Failure> {
    if (!this.#username && !this.isConnected) return;
    this.notifyClientEvent?.(ClientEvent.SigningOut);
    const username = this.#username;
    this.#username = null;
    this.#displayName = null;
    this.#x3dhUser = null;
    this.#encryptionBaseVector = null;
    await this.request(SocketEvents.LogOut, { username });
    this.notifyClientEvent?.(ClientEvent.SignedOut);
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

  private async encrypt(username: string, password: string, data: any, purpose: string): Promise<PasswordEncryptedData> {
    const [masterKeyBits, pInfo] = await crypto.deriveMasterKeyBits(`${username}#${password}`);
    const hSalt = getRandomVector(48);
    const encrypted = await crypto.deriveSignEncrypt(masterKeyBits, data, hSalt, purpose);
    return { ...encrypted, ...pInfo, hSalt };
  }

  private async decrypt(username: string, password: string, data: PasswordEncryptedData, purpose: string): Promise<any> {
    const { ciphertext, hSalt, ...pInfo } = data;
    const masterKeyBits = await crypto.deriveMasterKeyBits(`${username}#${password}`, pInfo);
    return await crypto.deriveDecryptVerify(masterKeyBits, ciphertext, hSalt, purpose);
  }

  private async processAuthSetupKey(username: string, authSetupKey: AuthSetupKey): Promise<AuthSetupKeyData> {
    const { authKeyData: { ciphertext }, dInfo: { hSalt, ...pInfo } } = authSetupKey;
    const userKeyBits = await crypto.deriveMasterKeyBits(username, pInfo);
    return await crypto.deriveDecryptVerify(userKeyBits, ciphertext, hSalt, "AuthKeyData");
  }

  private async createNewUserAuth(username: string, password: string, keyData: AuthSetupKeyData, userData: NewUserData): Promise<RegisterNewUserRequest> {
    const { newAuthReference, hSaltAuth, hSaltEncrypt, pInfo } = keyData;
    const newAuthBits = await crypto.deriveMasterKeyBits(`${username}#${password}`, pInfo);
    const signingKey = await crypto.deriveMACKey(newAuthBits, hSaltAuth, "NewUserVerify", 512);
    const newUserData = await crypto.deriveSignEncrypt(newAuthBits, userData, hSaltEncrypt, "NewUser", signingKey);
    return { newAuthReference, newUserData, newAuthBits };
  }

  private async createNewAuth(username: string, password: string, keyData: AuthSetupKeyData, response: InitiateAuthenticationResponse): Promise<[ConcludeAuthenticationRequest, Buffer]> {
    const { currentAuthReference, authInfo: { pInfo: currentPInfo, encryptionBase: oldBase } } = response;
    const { newAuthReference, hSaltAuth, hSaltEncrypt, pInfo } = keyData;
    const { encryptionBaseVector } = await this.decrypt(username, password, oldBase, "Encryption Base");
    const serverProof = await this.encrypt(username, password, { username }, "Server Proof");
    const encryptionBase = await this.encrypt(username, password, { encryptionBaseVector }, "Encryption Base");
    const currentAuthBits = await crypto.deriveMasterKeyBits(`${username}#${password}`, currentPInfo);
    const newAuthBits = await crypto.deriveMasterKeyBits(`${username}#${password}`, pInfo);
    const authChange: AuthChangeData = { username, newAuthBits, encryptionBase, serverProof };
    const signingKey = await crypto.deriveMACKey(currentAuthBits, hSaltAuth, "AuthChangeVerify", 512);
    const authChangeData = await crypto.deriveSignEncrypt(currentAuthBits, authChange, hSaltEncrypt, "AuthChange", signingKey);
    const request: ConcludeAuthenticationRequest = { currentAuthReference, newAuthReference, currentAuthBits, authChangeData };
    return [request, encryptionBaseVector];
  }

  private async createSavedDetails(username: string, password: string) {
    const saveToken = getRandomString();
    const keyBits = getRandomVector(32);
    const hSalt = getRandomVector(48);
    const { ciphertext } = await crypto.deriveSignEncrypt(keyBits, { username, password }, hSalt, "Cookie Saved Details");
    const cookieSavedDetails = ciphertext.toString("base64");
    const savedDetails: SavedDetails = { saveToken, keyBits, hSalt, url: this.url };
    return { cookieSavedDetails, savedDetails };
  }

  private async extractSavedDetails(cookieSavedDetails: string, savedDetails: SavedDetails): Promise<[string, string]> {
    const { hSalt, keyBits } = savedDetails;
    const { username, password } = await crypto.deriveDecryptVerify(keyBits, fromBase64(cookieSavedDetails), hSalt, "Cookie Saved Details");
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
    const requests = await this.GetAllRequests();
    if ("reason" in requests) {
      logError(requests);
      return false;
    }
    const successes = await allSettledResults(requests.map((r) => this.loadRequest(r)));
    return successes.every((s) => s);
  }

  private async respondToRequest(request: ChatRequestHeader, respondingAt: number) {
    const { sessionId } = request;
    const { displayName, profilePicture } = this;
    const viewChatRequest = await this.#x3dhUser.viewChatRequest(request);
    const exportedChattingSession = await this.#x3dhUser.acceptChatRequest(request, respondingAt, { displayName, profilePicture }, async (response) => {
      const sent = await this.SendMessage(response);
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
    const { profile, firstMessage, timestamp } = viewChatRequest;
    const lastActivity = respondingAt;
    const chatDetails = await crypto.deriveEncrypt(profile, this.#encryptionBaseVector, "ContactDetails");
    const chatData = { chatDetails, exportedChattingSession, lastActivity, sessionId };
    await this.CreateChat(chatData);
    const newChat = await Chat.instantiate(this.#username, this.#encryptionBaseVector, this.chatInterface(sessionId), chatData, { content: firstMessage, sentByMe: false, timestamp });
    this.removeChat(sessionId, "sessionId");
    this.addChat(newChat);
    return true;
  }

  private async rejectRequest(sessionId: string, oneTimeKeyId: string) {
    const result = await this.DeleteChatRequest({ sessionId });
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
    const { message: { content, timestamp } } = awaitedRequest;
    const [{ profile, respondedAt }, exportedChattingSession] = response;
    const chatDetails = await crypto.deriveEncrypt(profile, this.#encryptionBaseVector, "ContactDetails");
    const chatData = { chatDetails, exportedChattingSession, lastActivity: respondedAt, sessionId };
    const { reason } = await this.CreateChat(chatData);
    if (reason) {
      logError(reason);
      return false;
    }
    const x3dhInfo = await this.#x3dhUser.deleteWaitingRequest(sessionId);
    const { reason: r2 } = await this.UpdateX3DHUser({ x3dhInfo, username: this.username });
    if (r2) {
      logError(r2);
    }
    const newChat = await Chat.instantiate(this.#username, this.#encryptionBaseVector, this.chatInterface(sessionId), chatData, { content, timestamp, sentByMe: true, deliveredAt: respondedAt });
    this.removeChat(sessionId, "sessionId");
    this.addChat(newChat);
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
  
  private UpdateX3DHUser(data: { x3dhInfo: UserEncryptedData } & Username, timeout = 0): Promise<Failure> { 
    return this.request(SocketEvents.UpdateX3DHUser, data, timeout);
  }
  
  private RequestKeyBundle(data: Username, timeout = 0): Promise<RequestKeyBundleResponse | Failure> { 
    return this.request(SocketEvents.RequestKeyBundle, data, timeout);
  }

  private SendChatRequest(data: ChatRequestHeader, timeout = 0): Promise<Failure> {
    return this.request(SocketEvents.SendChatRequest, data, timeout);
  }

  private GetAllChats(timeout = 0): Promise<ChatData[] | Failure> {
    return this.request(SocketEvents.GetAllChats, {}, timeout);
  }

  private GetUnprocessedMessages(sessionId: string, timeout = 0): Promise<MessageHeader[] | Failure> {
    return this.request(SocketEvents.GetUnprocessedMessages, { sessionId }, timeout);
  }

  private GetAllRequests(timeout = 0): Promise<ChatRequestHeader[] | Failure> {
    return this.request(SocketEvents.GetAllRequests, {}, timeout);
  }

  private SendMessage(data: MessageHeader, timeout = 0): Promise<Failure> {
    return this.request(SocketEvents.SendMessage, data, timeout);
  }
 
  private CreateChat(data: ChatData, timeout = 0): Promise<Failure> {
    return this.request(SocketEvents.CreateChat, data, timeout);
  }

  private DeleteChatRequest(data: { sessionId: string }, timeout = 0): Promise<Failure> {
    return this.request(SocketEvents.DeleteChatRequest, data, timeout);
  }
  
  private RequestRoom(data: Username, timeout = 0): Promise<Failure> { 
    return this.request(SocketEvents.RequestRoom, data, timeout);
  }

  private async request(event: SocketEvents, data: any, timeout = 0): Promise<any | Failure> {
    if (!this.isConnected) {
      return {};
    }
    return new Promise(async (resolve: (result: any) => void) => {
      data = { ...data, fileHash: await this.#fileHash, url: this.url };
      this.#socket.emit(event, (await this.#sessionCrypto.signEncryptToBase64(data, event)), 
      async (response: string) => resolve(response ? await this.#sessionCrypto.decryptVerifyFromBase64(response, event) : {}));
      if (timeout > 0) {
        window.setTimeout(() => resolve({}), timeout);
      }
    })
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
    catch(err) {
      logError(err)
      respond(failure(ErrorStrings.ProcessFailed, err));
    }
  }

  private async roomRequested({ username }: Username) {
    if (username === this.#username) return failure(ErrorStrings.InvalidRequest);
    const chat = this.chatUsernamesList.get(username);
    if (!chat || chat.type !== "Chat") return failure(ErrorStrings.InvalidRequest);
    chat.establishRoom(this.#sessionCrypto, this.#socket);
    return { reason: null };
  }

  private async requestRoom(chat: Chat) {
    const response = await this.RequestRoom({ username: chat.otherUser });
    if (response.reason) {
      return response;
    }
    const confirmed = await chat.establishRoom(this.#sessionCrypto, this.#socket);
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

type MessageContent = Readonly<{
  content: string;
  timestamp: number;
  replyId?: string;
}>

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
    this.#socket?.off(`${this.otherUser} -> ${this.me}`);
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

  static async instantiate(me: string, encryptionBaseVector: CryptoKey, clientInterface: ClientChatInterface, chatData: ChatData, firstMessage?: { content: string, timestamp: number, sentByMe: boolean, deliveredAt?: number }) {
    const { chatDetails, exportedChattingSession, lastActivity, sessionId } = chatData;
    const contactDetails: Contact = await crypto.deriveDecrypt(chatDetails, encryptionBaseVector, "ContactDetails");
    const chattingSession = await ChattingSession.importSession(exportedChattingSession, encryptionBaseVector);
    const chat = new Chat(sessionId, me, contactDetails, encryptionBaseVector, clientInterface, chattingSession);
    chat.lastActivityTimestamp = lastActivity;
    chat.chatDetails = chatDetails;
    if (firstMessage) {
      const { content, timestamp, sentByMe, deliveredAt: deliveredAt } = firstMessage;
      const delivery = { delivered: deliveredAt, seen: deliveredAt }
      await chat.encryptStoreMessage({ messageId: "i", sentByMe, content, timestamp, delivery });
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
    this.#socket.on(`${this.otherUser} -> ${this.me}`, this.receiveMessage.bind(this));
    this.#socket.on("disconnect", () => {
      this.dispose();
    })
    this.loadUnprocessedMessages();
    this.notify();
  }

  async sendMessage(messageContent: MessageContent) {
    if (this.disposed) {
      return false;
    }
    const { content, timestamp, replyId } = messageContent;
    const messageId = getRandomString().slice(0, 10);
    const sendingMessage = { messageId, content, timestamp, replyingTo: replyId };
    const sentByMe = true;
    const replyingTo = await this.populateReplyingTo(replyId);
    if (replyingTo === undefined) {
      logError("Failed to come up with replied-to message.");
      return false;
    }
    const displayMessage: DisplayMessage = { messageId, timestamp, content, replyingTo, sentByMe, delivery: null };
    this.addMessageToList(displayMessage);
    const encryptedMessage = crypto.deriveEncrypt(displayMessage, this.#encryptionBaseVector, this.sessionId).then((content) => ({ messageId, timestamp, content }));
    const exportedChattingSession = await this.#chattingSession.sendMessage(sendingMessage, async (header) => await this.dispatch(header, true));
    if (typeof exportedChattingSession === "string") {
      logError(exportedChattingSession);
      return false;
    }
    await this.clientInterface.StoreMessage(await encryptedMessage);
    displayMessage.delivery = {};
    this.notify();
    const { lastActivity, chatDetails } = this;
    await this.clientInterface.UpdateChat({ lastActivity, chatDetails, exportedChattingSession });
    return true;
  }

  async sendEvent(event: "typing" | "stopped-typing", timestamp: number): Promise<boolean>;
  async sendEvent(event: "delivered" | "seen", timestamp: number, messageId: string): Promise<boolean>;
  async sendEvent(event: "typing" | "stopped-typing" | "delivered" | "seen", timestamp: number, messageId?: string): Promise<boolean> {
    if (this.disposed) {
      return false;
    }
    const sendWithoutRoom = event === "delivered" || event === "seen";
    if (!sendWithoutRoom && !this.hasRoom) {
      return false;
    }
    messageId ||= "";
    const sendingMessage: SendingMessage = { event, messageId, timestamp };
    const exportedChattingSession = await this.#chattingSession.sendMessage(sendingMessage, async (header) => await this.dispatch(header, sendWithoutRoom));
    if (typeof exportedChattingSession === "string") {
      logError(exportedChattingSession);
      return false;
    }
    const { lastActivity, chatDetails } = this;
    await this.clientInterface.UpdateChat({ lastActivity, chatDetails, exportedChattingSession });
  }

  private async dispatch(header: MessageHeader, sendWithoutRoom: boolean) {
    let tries = 0;
    let success = false;
    if (this.hasRoom) {
      while (!success && tries <= 10) {
        tries++;
        success = await new Promise<boolean>((resolve) => {
          this.#socket.emit(`${this.me} -> ${this.otherUser}`, this.#sessionCrypto.signEncryptToBase64(header, `${this.me} -> ${this.otherUser}`), (response: boolean) => resolve(response));
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
    catch(e: any) {
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

  private async encryptStoreMessage(message: DisplayMessage) {
    const { messageId, timestamp } = message;
    const encryptedContent = await crypto.deriveEncrypt(message, this.#encryptionBaseVector, this.sessionId);
    const encryptedMessage = { messageId, timestamp, content: encryptedContent };
    await this.clientInterface.StoreMessage(encryptedMessage); 
  }

  private async processEncryptedMessage(encryptedMessage: MessageHeader): Promise<boolean> {
    const exportedChattingSession = await this.#chattingSession.receiveMessage(encryptedMessage, async (messageBody) => {
      const { sender, messageId, timestamp } = messageBody;
      if (sender !== this.otherUser) {
        return false;
      }
      let message: DisplayMessage = null;
      if ("event" in messageBody) {
        const { event } = messageBody;
        if (event === "typing" || event === "stopped-typing") {
          if ((Date.now() - timestamp) < 5000) {
            this.isTyping = event === "typing";
            return true;
          }
        }
        else {
          let delivery: DeliveryInfo = event === "delivered" ? { delivered: timestamp } : { seen: timestamp };
          this.messagesList.forEach((m) => {
            if (m.messageId === messageId && m.sentByMe) {
              delivery = { ...m.delivery, ...delivery };
              m.delivery = delivery;
              message = m;
              this.notify();
            }
          })
          if (!message) {
            message = await this.getMessageById(messageId, true);
            if (message.sentByMe) {
              delivery = { ...message.delivery, ...delivery };
              message = { ...message, ...delivery };
            }
          }
        }
      }
      else {
        const { content, replyingTo: replyId } = messageBody;
        const replyingTo = await this.populateReplyingTo(replyId);
        if (replyingTo === undefined) {
          logError("Failed to come up with replied-to message.");
          return false;
        }
        message = { messageId, timestamp, content, replyingTo, sentByMe: false };
        this.addMessageToList(message);
      }
      await this.encryptStoreMessage(message);
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

  private async populateReplyingTo(id: string): Promise<ReplyingToInfo> {
    if (!id) return null;
    const repliedTo = await this.getMessageById(id);
    const replyToOwn = repliedTo.sentByMe;
    const displayText = truncateText(repliedTo.content);
    return { id, replyToOwn, displayText };
  }

  private async getMessageById(messageId: string, skipList = false): Promise<DisplayMessage> {
    if (!messageId) return null;
    if (!skipList) {
      const message = this.messagesList.find((m) => m.messageId === messageId);
      if (message) {
        return message;
      }
    }
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

export class ChatRequest {
  readonly type = "ChatRequest";
  readonly otherUser: string;
  readonly contactDetails: Readonly<{ displayName: string, contactName?: string, profilePicture: string }>;
  readonly message: DisplayMessage;
  readonly lastActivity: number;
  readonly sessionId: string;
  private readonly chatRequestHeader: ChatRequestHeader;
  private readonly clientInterface: ClientChatRequestInterface;

  constructor(chatRequestHeader: ChatRequestHeader, clientInterface: ClientChatRequestInterface, viewRequest: ViewChatRequest) {
    const { firstMessage, timestamp, profile: { username: otherUser, ...contactDetails } } = viewRequest;
    this.sessionId = chatRequestHeader.sessionId;
    this.otherUser = otherUser;
    this.contactDetails = contactDetails;
    this.message = { messageId: "0.0", content: firstMessage, timestamp, sentByMe: false };
    this.lastActivity = timestamp;
    this.chatRequestHeader = chatRequestHeader;
    this.clientInterface = clientInterface;
  }

  async rejectRequest () {
    return await this.clientInterface.rejectRequest(this.otherUser, this.sessionId, this.chatRequestHeader.yourOneTimeKeyIdentifier);
  }
  async respondToRequest (respondingAt: number) {
    return await this.clientInterface.respondToRequest(this.chatRequestHeader, respondingAt);
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

function fromBase64(data: string) {
  return Buffer.from(data, "base64");
}

async function allSettledResults<T>(promises: Promise<T>[]) {
  return (await Promise.allSettled(promises)).filter((result) => result.status === "fulfilled").map((result) => (result as PromiseFulfilledResult<T>).value);
}