import axios, { Axios } from "axios";
import { io, Socket } from "socket.io-client";
import { Buffer } from "./node_modules/buffer";
import { stringify } from "safe-stable-stringify";
import { SessionCrypto } from "../../shared/sessionCrypto";
import { X3DHUser } from "./e2e-encryption";
import * as crypto from "../../shared/cryptoOperator";
import { CommonStrings, Failure, Username, AuthSetupKey, UserEncryptedData, RegisterNewUserRequest, InitiateAuthenticationResponse, ConcludeAuthenticationRequest, SignInResponse, PublishKeyBundlesRequest, RequestKeyBundleResponse, SocketEvents, randomFunctions, failure, SavedDetails, PasswordEncryptedData, AuthSetupKeyData, NewUserData, AuthChangeData } from "../../shared/commonTypes";
import BufferSerializer from "./node_modules/buffer-serializer";

const { getRandomVector, getRandomString } = randomFunctions();
axios.defaults.withCredentials = true;
const serializer = new BufferSerializer();
const serialize: (data: any) => Buffer = serializer.toBuffer.bind(serializer);
function deserialize(buff: Buffer, offset = 0): any {
  let result;
  if (!buff) {
    throw "Nothing to deserialize.";
  }
  try {
    result = serializer.fromBuffer(buff, offset);
    if (result && result instanceof Uint8Array) {
      result = null;
    }
  }
  catch(err) {
    logError(err)
    result = null;
  }
  if (result) {
    return result;
  }
  if (offset < 50) {
    return deserialize(buff, offset + 1);
  }
  return {};
}

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

export class Client {
  private readonly url: string;
  private readonly axInstance: Axios;
  private readonly notifyCallback: (status: Status) => void;
  private connecting = false;
  private retryingConnect = false;
  private reportDone: (arg0: any) => void = undefined;
  #socket: Socket;
  #displayName: string;
  #username: string;
  #x3dhUser: X3DHUser;
  #sessionReference: string;
  #sessionCrypto: SessionCrypto;
  #masterKeyBits: Buffer;

  public get username(): string {
    return this.#username;
  }

  public get displayName(): string {
    return this.#displayName;
  }

  public get isConnected(): boolean {
    return this.#socket.connected;
  }

  public get isSignedIn(): boolean {
    return !!this.#username;
  }

  private get connected(): boolean { 
    return this.#socket?.connected ?? false;
  }

  private get id(): string {
    return this.#socket?.id;
  }

  constructor(url: string, notifyCallback?: (status: Status) => void) {
    this.url = url;
    this.axInstance = axios.create({ baseURL: `${this.url}/`, maxRedirects:0 });
    if (notifyCallback) this.notifyCallback = notifyCallback;
  }

  async establishSession() {
    if (!this.connected) {
      console.log(`Attempting to establish secure session.`);
      this.notifyCallback?.(Status.Connecting);
      this.connecting = true;
      const { privateKey, publicKey } = await crypto.generateKeyPair("ECDH");
      const { privateKey: signingKey, publicKey: verifyingKey } = await crypto.generateKeyPair("ECDSA");
      const sessionReference = this.#sessionReference ?? getRandomString();
      const clientPublicKey = (await crypto.exportKey(publicKey)).toString("base64");
      const clientVerifyingKey = (await crypto.exportKey(verifyingKey)).toString("base64");
      const auth = { sessionReference, clientPublicKey, clientVerifyingKey };
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
            this.notifyCallback?.(Status.SignedOut);
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
      console.log(success && this.connected ? "Secure session established." : "Failed to establish secure session.");
      this.notifyCallback?.(this.connected ? Status.Connected : Status.FailedToConnect);
      if (!success || !this.connected) {
        this.#socket?.offAny?.();
        this.#socket?.disconnect?.();
        this.#socket = null;
        this.retryConnect("");
      }
      this.reportDone?.(null);
    }
  }

  private async retryConnect(reason: String) {
    if (this.retryingConnect) return;
    this.#socket?.offAny?.();
    this.#socket?.disconnect?.();
    this.#socket = null;
    this.notifyCallback?.(Status.Disconnected);
    this.notifyCallback?.(Status.SignedOut);
    if (reason === "io client disconnect") return;
    this.retryingConnect = true;
    while(!this.connected) {
      const wait = new Promise((resolve, _) => { 
        this.reportDone = resolve;
        window.setTimeout(() => resolve(null), 10000); });
      if (!this.connecting) {
        console.log("Retrying connect");
        this.notifyCallback?.(Status.Reconnecting);
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

  async registerNewUser(username: string, password: string, displayName: string, savePassword: boolean): Promise<Failure> {
    if (!this.connected) return failure(CommonStrings.NoConnectivity);
    this.notifyCallback?.(Status.CreatingNewUser);
    try {
      displayName ??= username;
      const encryptionBaseVector = getRandomVector(64);
      const encryptionBase = await this.encrypt(username, password, encryptionBaseVector, "Encryption Base");
      const serverProof = await this.encrypt(username, password, serialize({ username }), "Server Proof");
      const x3dhUser = await X3DHUser.new(username);
      if (!x3dhUser) {
        this.notifyCallback?.(Status.FailedCreateNewUser);
        return failure(CommonStrings.ProcessFailed);
      }
      const [encryptedX3DH, hSalt] = await x3dhUser.exportUser(encryptionBaseVector);
      const x3dhInfo: UserEncryptedData = { ...encryptedX3DH, hSalt };
      const newUserData: NewUserData = { username, displayName, serverProof, encryptionBase, x3dhInfo };
      if (!encryptedX3DH) {
        this.notifyCallback?.(Status.FailedCreateNewUser);
        return failure(CommonStrings.ProcessFailed);
      }
      const response = await this.RequestAuthSetupKey({ username });
      if ("reason" in response) {
        this.notifyCallback?.(Status.FailedCreateNewUser);
        return response;
      }
      const keyData = await this.processAuthSetupKey(username, response);
      const newUserRequest = await this.createNewUserAuth(username, password, keyData, newUserData);
      let { reason } = await this.RegisterNewUser(newUserRequest);
      if (reason) {
        this.notifyCallback?.(Status.FailedCreateNewUser);
        return { reason };
      }
      this.#username = username;
      this.#displayName = displayName;
      this.#x3dhUser = x3dhUser;
      this.#masterKeyBits = encryptionBaseVector;
      await this.savePassword(savePassword, username, password);
      this.notifyCallback?.(Status.CreatedNewUser);
      this.notifyCallback(Status.SignedIn);
      return { reason: null };
    }
    catch(err) {
      logError(err);
      this.notifyCallback?.(Status.FailedCreateNewUser);
      return failure(CommonStrings.ProcessFailed);
    }
  }

  async userLogIn(): Promise<Failure>
  async userLogIn(username: string, password: string, savePassword: boolean): Promise<Failure>;
  async userLogIn(username?: string, password?: string, savePassword?: boolean): Promise<Failure> {
    if (!this.connected) return failure(CommonStrings.NoConnectivity);
    this.notifyCallback?.(Status.SigningIn);
    try {
      let start = performance.now();
      if (!username) {
        const { saveToken, cookieSavedDetails  } = JSON.parse(window.localStorage.getItem("SavedDetails"));
        window.localStorage.removeItem("SavedDetails");
        if (!saveToken) {
          this.notifyCallback?.(Status.FailedSignIn);
          return failure(CommonStrings.InvalidRequest);
        }
        const details = await this.GetSavedDetails({ saveToken });
        await this.axInstance.post("/setSaveToken", { saveToken: "0" });
        if ("reason" in details) {
          this.notifyCallback?.(Status.FailedSignIn);
          return details;
        }
        [username, password] = await this.extractSavedDetails(cookieSavedDetails, details);
        if (!username) {
          this.notifyCallback?.(Status.FailedSignIn);
          return failure(CommonStrings.ProcessFailed);
        }
        savePassword = true;
      }
      const response = await this.InitiateAuthentication({ username });
      if ("reason" in response) {
        this.notifyCallback?.(Status.FailedSignIn);
        return response;
      }
      const keyData = await this.processAuthSetupKey(username, response.newAuthSetup);
      const result = await this.createNewAuth(username, password, keyData, response);
      if (!result) {
        this.notifyCallback?.(Status.FailedSignIn);
        return failure(CommonStrings.ProcessFailed);
      }
      const [concludeRequest, encryptionBaseVector] = result;
      const concludeResponse = await this.ConcludeAuthentication(concludeRequest);
      if ("reason" in concludeResponse) {
        this.notifyCallback?.(Status.FailedSignIn);
        return concludeResponse;
      }
      if (deserialize(await this.decrypt(username, password, response.authInfo.serverProof, "Server Proof")).username !== username) {
        this.notifyCallback?.(Status.FailedSignIn);
        return failure(CommonStrings.ProcessFailed);
      }
      const { displayName, x3dhInfo: { ciphertext, hSalt } } = concludeResponse;
      await this.savePassword(savePassword, username, password);
      const x3dhUser = await X3DHUser.importUser({ ciphertext }, encryptionBaseVector, hSalt);
      if (!x3dhUser) {
        this.notifyCallback?.(Status.FailedSignIn);
        return failure(CommonStrings.ProcessFailed);
      }
      this.#username = username;
      this.#displayName = displayName;
      this.#x3dhUser = x3dhUser;
      this.#masterKeyBits = encryptionBaseVector;
      this.notifyCallback(Status.SignedIn);
      return { reason: null };
    }
    catch(err) {
      logError(err);
      this.notifyCallback?.(Status.FailedSignIn);
      return failure(CommonStrings.ProcessFailed);
    }
  }

  async userLogOut(): Promise<Failure> {
    if (!this.#username && !this.connected) return;
    this.notifyCallback?.(Status.SigningOut);
    const username = this.#username;
    this.#username = null;
    this.#displayName = null;
    this.#x3dhUser = null;
    this.#masterKeyBits = null;
    await this.request(SocketEvents.LogOut, { username });
    this.notifyCallback?.(Status.SignedOut);
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
    const [serverProofMasterKeyBits, pInfo] = await crypto.deriveMasterKeyBits(`${username}#${password}`);
    const hSalt = getRandomVector(48);
    data ??= serialize({ username });
    const encrypted = await crypto.deriveSignEncrypt(serverProofMasterKeyBits, data, hSalt, purpose);
    return { ...encrypted, ...pInfo, hSalt };
  }

  private async decrypt(username: string, password: string, data: PasswordEncryptedData, purpose: string) {
    const { ciphertext, hSalt, ...pInfo } = data;
    const serverProofMasterKeyBits = await crypto.deriveMasterKeyBits(`${username}#${password}`, pInfo);
    return await crypto.deriveDecryptVerify(serverProofMasterKeyBits, ciphertext, hSalt, purpose);
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
    const savedDetails: SavedDetails = { saveToken, keyBits, hSalt };
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
      }
    }
  }

  private SetSavedDetails(data: SavedDetails, timeout = 0) : Promise<Failure> { 
    return this.request(SocketEvents.SetSavedDetails, data, timeout);
  }

  private GetSavedDetails(data: { saveToken: string }, timeout = 0) : Promise<SavedDetails | Failure> { 
    return this.request(SocketEvents.GetSavedDetails, data, timeout);
  }

  private RequestAuthSetupKey(data: Username, timeout = 0) : Promise<AuthSetupKey | Failure> { 
    return this.request(SocketEvents.RequestAuthSetupKey, data, timeout);
  }
  
  private RegisterNewUser(data: RegisterNewUserRequest, timeout = 0) : Promise<Failure> { 
    return this.request(SocketEvents.RegisterNewUser, data, timeout);
  }
  
  private InitiateAuthentication(data: Username, timeout = 0) : Promise<InitiateAuthenticationResponse | Failure> { 
    return this.request(SocketEvents.InitiateAuthentication, data, timeout);
  }
  
  private ConcludeAuthentication(data: ConcludeAuthenticationRequest, timeout = 0) : Promise<SignInResponse | Failure> { 
    return this.request(SocketEvents.ConcludeAuthentication, data, timeout);
  }
  
  private PublishKeyBundles(data: PublishKeyBundlesRequest, timeout = 0) : Promise<Failure> { 
    return this.request(SocketEvents.PublishKeyBundles, data, timeout);
  }
  
  private RequestKeyBundle(data: Username, timeout = 0) : Promise<RequestKeyBundleResponse | Failure> { 
    return this.request(SocketEvents.RequestKeyBundle, data, timeout);
  }

  private async request(event: SocketEvents, data: any, timeout = 0): Promise<any | Failure> {
    if (!this.connected) {
      return {};
    }
    return new Promise(async (resolve: (result: any) => void) => {
      this.#socket.emit(event, (await this.#sessionCrypto.signEncrypt(data, event)).toString("base64"), 
      async (response: string) => resolve(response ? await this.#sessionCrypto.decryptVerify(Buffer.from(response, "base64"), event) : {}));
      if (timeout > 0) {
        window.setTimeout(() => resolve({}), timeout);
      }
    })
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
    console.log(`${err}`);
  }
}

async function allSettledResults<T>(promises: Promise<T>[]) {
  return (await Promise.allSettled(promises)).filter((result) => result.status === "fulfilled").map((result) => (result as PromiseFulfilledResult<T>).value);
}