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
    const getRandomVector = (bytes: number): Buffer => {
        let rv = new Uint8Array(bytes);
        crypto.getRandomValues(rv);
        return Buffer.from(rv);
      }
    const getRandomString = () => getRandomVector(20).toString("base64").slice(0, 20);
    return { getRandomVector, getRandomString };
}

export function failure(reason: ErrorStrings, details: any = null): Failure {
    return details ? { reason, details } : { reason };
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

export type PasswordEncryptedData = EncryptedData & PasswordDeriveInfo & { hSalt: Buffer };

export type Profile = Readonly<{
    username: string;
    displayName: string;
    profilePicture: string;
}>;

export type Contact = Profile & {
    readonly contactName?: string;
}

export type MessageBody = Readonly<{
    sender: string;
    recipient: string;
    messageId: string;
    replyingTo?: string;
    timestamp: number;
    content: string;
}>;

export type PlainMessage = Readonly<{
    sentByMe: boolean;
    messageId: string;
    replyingTo?: { id: string, replyToOwn: boolean, displayText: string };
    timestamp: number;
    content: string;
}>;

export type DisplayMessage = Omit<PlainMessage, "sentByMe"> & ({ readonly sentByMe: false } | {
    readonly sentByMe: true;
    delivery?: {
        readonly delivered?: number | false;
        readonly seen?: number | false;
    }
})

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

export type MessageRequestHeader = Readonly<{
    sessionId: string;
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
    delivered?: number | false;
    seen?: number | false;
}>;

export type ChatData = Readonly<{
  sessionId: string,
  lastActivity: number,
  chatDetails: UserEncryptedData,
  exportedChattingSession: UserEncryptedData
}>;

export type MessageEvent = Readonly<{
    addressedTo: string;
    sessionId: string;
    messageId: string;
    timestamp: number;
    event: "delivered" | "seen";
}>;

export type Username = { 
    username: string 
};

export type Failure = {
    reason: string;
    details?: any;
}

export type SavedDetails = { 
    saveToken: string,
    keyBits: Buffer, 
    hSalt: Buffer
};

type SecretData = {
    serverProof: PasswordEncryptedData,
    encryptionBase: PasswordEncryptedData
};

export type EstablishData = {
    sessionReference: string,
    publicKey: Buffer,
    verifyingKey: Buffer
}

export type AuthSetupKey = {
    authKeyData: EncryptedData,
    dInfo: PasswordDeriveInfo & { hSalt: Buffer }
}

export type AuthSetupKeyData = { 
    newAuthReference: string,
    pInfo: PasswordDeriveInfo,
    hSaltEncrypt: Buffer,
    hSaltAuth: Buffer
};

export type AuthInfo = { 
    serverProof: PasswordEncryptedData,
    pInfo: PasswordDeriveInfo,
    encryptionBase: PasswordEncryptedData
};

export type UserAuthInfo = SecretData & {
    dInfo: PasswordDeriveInfo & { hSalt: Buffer },
    originalData: Buffer,
    signedData: Buffer
};

export type RegisterNewUserRequest = {
    newAuthReference: string,
    newUserData: SignedEncryptedData,
    newAuthBits: Buffer
};

export type NewUserData = SecretData & {
    username: string,
    x3dhInfo: UserEncryptedData,
    userDetails: UserEncryptedData,
    keyBundles: PublishKeyBundlesRequest
};

export type InitiateAuthenticationResponse = { 
    currentAuthReference: string,
    authInfo: AuthInfo,
    newAuthSetup: AuthSetupKey
};

export type ConcludeAuthenticationRequest = {
    currentAuthReference: string,
    currentAuthBits: Buffer,
    newAuthReference: string,
    authChangeData: SignedEncryptedData
};

export type AuthChangeData = SecretData & {
    username: string,
    newAuthBits: Buffer
};

export type SignInResponse = {
    userDetails: UserEncryptedData,
    x3dhInfo: UserEncryptedData
};

export type PublishKeyBundlesRequest = {
    defaultKeyBundle: KeyBundle;
    oneTimeKeyBundles: KeyBundle[];
}

export type RequestKeyBundleResponse = {
    keyBundle: KeyBundle;
};

export enum SocketEvents {
    CompleteHandshake = "complete-handshake",
    UsernameExists = "username-exists",
    UserLoginPermitted = "user-login-permitted",
    RequestAuthSetupKey = "request-auth-setup-key",

    RegisterNewUser = "register-new-user",
    InitiateAuthentication = "initiate-authentication",
    ConcludeAuthentication = "conclude-authentication",

    SetSavedDetails = "set-saved-details",
    GetSavedDetails = "get-saved-details",

    PublishKeyBundles = "publish-key-bundles",
    RequestKeyBundle = "request-key-bundle",
    
    SendMessageRequest = "send-message-request",
    SendMessage = "send-message",
    SendMessageEvent = "send-message-event",
    DeleteMessageRequest = "delete-message-request",

    MessageReceived = "message-received",
    MessageRequestReceived = "message-request-received",
    MessageEventLogged = "message-event-logged",

    GetAllChats = "get-all-chats",
    GetAllRequests = "get-all-requests",
    GetUnprocessedMessages = "get-unprocessed-messages",
    GetMessagesByNumber = "get-messages-by-number",
    GetMessagesUptoTimestamp = "get-messages-upto-timestamp",
    GetMessagesUptoId = "get-messages-upto-id",
    GetMessageById = "get-message-by-id",

    StoreMessage = "store-message",
    UpdateMessage = "update-message",
    CreateChat = "create-chat",
    UpdateChat = "update-chat",

    RequestRoom = "request-room",
    RoomEstablished = "room-established",
    
    TerminateCurrentSession = "terminate-current-session",
    LogOut = "log-out"
}

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