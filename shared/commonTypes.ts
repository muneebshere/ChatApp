import _ from "lodash";
import { Buffer } from "./node_modules/buffer/";
import { isBrowser, isNode, isWebWorker } from "./node_modules/browser-or-node";

export function randomFunctions() {
    let crypto: any = null;
    if (isNode) { 
        crypto = eval(`require("node:crypto").webcrypto`);
    }
    else if (isBrowser) {
        crypto = window.crypto;
    }
    else if (isWebWorker) {
        crypto = self.crypto;
    }
    if (crypto === null) {
        throw "No crypto in this environment";
    }
    function getRandomVector(bytes: number): Buffer {
        let rv = new Uint8Array(bytes);
        crypto.getRandomValues(rv);
        return Buffer.from(rv);
      }
    function getRandomString(chars: number, base: "base64" | "hex") {
        const bitsPerChar = base === "hex" ? 4 : 6;
        const bytes = Math.ceil((chars * bitsPerChar) / 8);
        return getRandomVector(bytes).toString(base).slice(0, chars);
    }
    return { getRandomVector, getRandomString };
}

export function failure(reason: ErrorStrings, details: any = null): Failure {
    return details ? { reason, details } : { reason };
}

export function getPromise<T>(): [Promise<T>, (result: T) => void] {
    let resolve: (result: T) => void;
    const promise = new Promise<T>((res) => {
        resolve = res;
    });
    return [promise, resolve];
}

export type ExposedSignedPublicKey = Readonly<{
    exportedPublicKey: Buffer;
    signature: Buffer; 
}>;

export type SignedKeyPair = ExposedSignedPublicKey & {
    readonly keyPair: CryptoKeyPair;
}

export type ExportedSigningKeyPair = Readonly<{
    wrappedPrivateKey: Buffer;
    exportedPublicKey: Buffer;
}>;

export type ExportedSignedKeyPair = ExportedSigningKeyPair & {
    readonly signature: Buffer;
}

export type KeyBundle = Readonly<{
    owner: string;
    identifier: string;
    preKeyVersion: number;
    verifyingIdentityKey: Buffer;
    publicDHIdentityKey: ExposedSignedPublicKey;
    publicSignedPreKey: ExposedSignedPublicKey;
    publicOneTimeKey?: ExposedSignedPublicKey; 
}>;

export type PasswordDeriveInfo = Readonly<{
    pSalt: Buffer;
    iterSeed: number;
}>;

export type EncryptInfo = Readonly<{
    encryptKey: CryptoKey;
    iv: Buffer
}>

export type EncryptedData = {
    readonly ciphertext: Buffer;
}

export type SignedEncryptedData = EncryptedData & {
    readonly signature: Buffer; 
}

export type UserEncryptedData = EncryptedData & { hSalt: Buffer };

export type PasswordEncryptedData = UserEncryptedData & PasswordDeriveInfo;

export type Profile = Readonly<{
    username: string;
    displayName: string;
    profilePicture: string;
    description: string;
}>;

export type Contact = Profile & {
    readonly contactName?: string;
}

export type ReplyingToInfo = Readonly<{ id: string, replyToOwn: boolean, displayText: string }>;

export type DeliveryInfo = Readonly<({
    delivered: false;
    seen: false;
} | {
    delivered: number;
    seen: number | false;
})>;

export type DisplayMessage =Readonly<{
    messageId: string;
    replyingTo?: ReplyingToInfo;
    timestamp: number;
    text: string;
    sentByMe: boolean;
    delivery?: DeliveryInfo;
}>;

export type MessageHeader = Readonly<{
    addressedTo: string;
    sessionId: string;
    messageId: string;
    timestamp: number;
    receivingRatchetNumber: number;
    sendingRatchetNumber: number;
    sendingChainNumber: number;
    previousChainNumber: number;
    nextDHRatchetKey: ExposedSignedPublicKey;
    messageBody: SignedEncryptedData; 
}>;

export type ChatRequestHeader = Readonly<{
    sessionId: string;
    messageId: string;
    timestamp: number;
    addressedTo: string;
    myVerifyingIdentityKey: Buffer;
    myPublicDHIdentityKey: ExposedSignedPublicKey;
    myPublicEphemeralKey: ExposedSignedPublicKey;
    yourSignedPreKeyVersion: number;
    yourOneTimeKeyIdentifier?: string;
    initialMessage: SignedEncryptedData; 
}>;

export type StoredMessage = Readonly<{
    sessionId: string;
    messageId: string;
    timestamp: number;
    content: UserEncryptedData;
}>;

export type ChatData = Readonly<{
  sessionId: string,
  lastActive: number,
  chatDetails: UserEncryptedData,
  exportedChattingSession: UserEncryptedData
}>;

export type Username = { 
    readonly username: string 
};

export type Failure = Readonly<{
    reason: string;
    details?: any;
}>;

export type LogInRequest = Username & Readonly<{
    clientEphemeralPublicHex: string;
}>;

export type RegisterNewUserRequest = LogInRequest & Readonly<{
    verifierSalt: Buffer,
    verifierPointHex: string,
    clientIdentityVerifyingKey: Buffer
}>

export type LogInChallenge = Readonly<{
    challengeReference: string,
    verifierSalt: Buffer,
    verifierEntangledHex: string,
    serverConfirmationCode: Buffer
}>

export type RegisterNewUserChallenge = Omit<LogInChallenge, "verifierSalt"> & {
    readonly serverIdentityVerifyingKey: Buffer
}

export type LogInChallengeResponse = Readonly<{
    challengeReference: string,
    clientConfirmationCode: Buffer
}>;

export type RegisterNewUserChallengeResponse = LogInChallengeResponse & {
    readonly newUserDataSigned: SignedEncryptedData;
}

export type UserData = Readonly<{
    encryptionBase: PasswordEncryptedData,
    clientIdentitySigningKey: PasswordEncryptedData,
    serverIdentityVerifyingKey: PasswordEncryptedData,
    x3dhInfo: UserEncryptedData,
    profileData: UserEncryptedData
}>;

export type NewUserData = UserData & { 
    readonly keyBundles: PublishKeyBundlesRequest
};

export type PublishKeyBundlesRequest = {
    defaultKeyBundle: KeyBundle;
    oneTimeKeyBundles: KeyBundle[];
}

export type RequestKeyBundleResponse = {
    keyBundle: KeyBundle;
};

enum SocketClientSideEventsEnum {
    UsernameExists, 
    UserLoginPermitted,
    InitiateRegisterNewUser,
    ConcludeRegisterNewUser,
    InitiateLogIn,
    ConcludeLogIn,
    InitiateLogInSaved,
    ConcludeLogInSaved,
    PublishKeyBundles,
    UpdateX3DHUser,
    RequestKeyBundle,
    GetAllChats,
    GetAllRequests,
    GetUnprocessedMessages,
    GetMessagesByNumber,
    GetMessagesUptoTimestamp,
    GetMessagesUptoId,
    GetMessageById,
    StoreMessage,
    CreateChat,
    UpdateChat,
    SendChatRequest,
    SendMessage,
    MessageProcessed,
    DeleteChatRequest,
    LogOut,
    RequestRoom,
    TerminateCurrentSession
}

export type SocketClientSideEventsKey = Exclude<keyof typeof SocketClientSideEventsEnum, number>

type SocketClientSideEventsMap = {
    [E in SocketClientSideEventsKey]: E
}

function constructSocketClientSideEvents() {
    const enums: any = {}
    for (let e in SocketClientSideEventsEnum) {
        if (Number.isNaN(parseInt(e))) enums[e] = e;
    }
    return enums as SocketClientSideEventsMap;
}

export const SocketClientSideEvents = constructSocketClientSideEvents();

type SocketClientRequestParametersMap = {
    UsernameExists: Username, 
    UserLoginPermitted: Username, 
    InitiateRegisterNewUser: RegisterNewUserRequest,
    ConcludeRegisterNewUser: RegisterNewUserChallengeResponse,
    InitiateLogIn: LogInRequest,
    ConcludeLogIn: LogInChallengeResponse,
    InitiateLogInSaved: { serverKeyBits: Buffer },
    ConcludeLogInSaved: { username: string, clientConfirmationCode: Buffer },
    PublishKeyBundles: PublishKeyBundlesRequest,
    UpdateX3DHUser: { x3dhInfo: UserEncryptedData } & Username,
    RequestKeyBundle: Username,
    GetAllChats: [],
    GetAllRequests: [],
    GetUnprocessedMessages: { sessionId: string },
    GetMessagesByNumber: { sessionId: string, limit: number, olderThan?: number },
    GetMessagesUptoTimestamp: { sessionId: string, newerThan: number, olderThan?: number },
    GetMessagesUptoId: { sessionId: string, messageId: string, olderThan?: number },
    GetMessageById: { sessionId: string, messageId: string },
    StoreMessage: StoredMessage,
    CreateChat: ChatData,
    UpdateChat: Omit<ChatData, "chatDetails" | "exportedChattingSession"> & Partial<ChatData>,
    SendChatRequest: { sessionId: string },
    SendMessage: MessageHeader,
    MessageProcessed: { sessionId: string, messageId: string },
    DeleteChatRequest: { sessionId: string },
    LogOut: Username,
    RequestRoom: Username,
    TerminateCurrentSession: []
}

export type SocketClientRequestParameters = {
    [E in SocketClientSideEventsKey]: SocketClientRequestParametersMap[E];
}


type SocketClientRequestReturnMap = {
    UsernameExists: { exists: boolean }, 
    UserLoginPermitted: { tries: number, allowsAt: number }, 
    InitiateRegisterNewUser: RegisterNewUserChallenge,
    ConcludeRegisterNewUser: never,
    InitiateLogIn: LogInChallenge,
    ConcludeLogIn: UserData,
    InitiateLogInSaved: { authKeyBits: Buffer },
    ConcludeLogInSaved: { serverConfirmationCode: Buffer, coreKeyBits: Buffer, userData: Pick<UserData, "profileData" | "x3dhInfo"> },
    PublishKeyBundles: never,
    UpdateX3DHUser: never,
    RequestKeyBundle: RequestKeyBundleResponse,
    GetAllChats: ChatData[],
    GetAllRequests: ChatRequestHeader[],
    GetUnprocessedMessages: MessageHeader[],
    GetMessagesByNumber: StoredMessage[],
    GetMessagesUptoTimestamp: StoredMessage[],
    GetMessagesUptoId: StoredMessage[],
    GetMessageById: StoredMessage,
    StoreMessage: never,
    CreateChat: never,
    UpdateChat: never,
    SendChatRequest: never,
    SendMessage: never,
    MessageProcessed: never,
    DeleteChatRequest: never,
    LogOut: never,
    RequestRoom: never,
    TerminateCurrentSession: never
}

export type SocketClientRequestReturn = {
    [E in SocketClientSideEventsKey]: SocketClientRequestReturnMap[E];
}

enum SocketServerSideEventsEnum {
    CompleteHandshake,
    MessageReceived,
    ChatRequestReceived,
    RoomRequested,
    ClientRoomReady,
    ServerRoomReady
}

export type SocketServerSideEventsKey = Exclude<keyof typeof SocketServerSideEventsEnum, number>

type SocketServerSideEventsMap = {
    [E in SocketServerSideEventsKey]: E
}

function constructSocketServerSideEvents() {
    const enums: any = {}
    for (let e in SocketServerSideEventsEnum) {
        if (Number.isNaN(parseInt(e))) enums[e] = e;
    }
    return enums as SocketServerSideEventsMap;
}

export const SocketServerSideEvents = constructSocketServerSideEvents();


export enum ErrorStrings {
    NoConnectivity = "NoConnectivity",
    DecryptFailure = "DecryptFailure",
    ProcessFailed = "ProcessFailed",
    InvalidReference = "InvalidReference",
    InvalidRequest = "InvalidRequest",
    IncorrectData = "IncorrectData",
    IncorrectPassword = "IncorrectPassword",
    TooManyWrongTries = "TooManyWrongTries"
}

export type Entry<T> = { 
    [K in keyof T]: [K, T[K]] 
}[keyof T]

export function typedEntries<T extends {}>(object: T): ReadonlyArray<Entry<T>> {
  return Object.entries(object) as unknown as ReadonlyArray<Entry<T>>; 
}