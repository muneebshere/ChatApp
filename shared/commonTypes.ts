import _ from "lodash";

export type ExposedSignedPublicKey = Readonly<{
    exportedPublicKey: Buffer;
    signature: Buffer; 
}>;

export type SignedKeyPair = ExposedSignedPublicKey & {
    readonly keyPair: CryptoKeyPair;
}

export type ExportedSigningKeyPair = Readonly<{
    wrappedPrivateKey: UserEncryptedData;
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

export type PasswordEntangleInfo = PasswordDeriveInfo & {
    readonly passwordEntangledPoint: Buffer;
}

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

export type LogInPermitted = { 
    readonly login: false | { tries: number, allowsAt: number } 
};

export type Profile = Readonly<{
    username: string;
    displayName: string;
    profilePicture: string;
    description: string;
}>;

export type Contact = Profile & {
    readonly contactName?: string;
}

export type ReplyingToInfo = Readonly<{ replyId: string, replyToOwn: boolean, displayText: string }>;

export type DeliveryInfo = Readonly<({
    delivered: false;
    seen: false;
} | {
    delivered: number;
    seen: number | false;
})>;

export type DisplayMessage =Readonly<{
    messageId: string;
    replyingToInfo?: ReplyingToInfo;
    timestamp: number;
    text: string;
    sentByMe: boolean;
    delivery?: DeliveryInfo;
}>;

export type MessageHeader = Readonly<{
    toAlias: string;
    fromAlias: string;
    sessionId: string;
    headerId: string;
    receivingRatchetNumber: number;
    sendingRatchetNumber: number;
    sendingChainNumber: number;
    previousChainNumber: number;
    nextDHRatchetKey: ExposedSignedPublicKey;
    messageBody: SignedEncryptedData; 
}>;

export type ChatRequestHeader = Readonly<{
    addressedTo: string;
    headerId: string;
    myVerifyingIdentityKey: Buffer;
    myPublicDHIdentityKey: ExposedSignedPublicKey;
    myPublicEphemeralKey: ExposedSignedPublicKey;
    yourSignedPreKeyVersion: number;
    yourOneTimeKeyIdentifier?: string;
    initialMessage: SignedEncryptedData; 
}>;

export type StoredMessage = Readonly<{
    chatId: string;
    hashedId: string;
    timemark: number;
    content: UserEncryptedData;
}>;

export type Backup = Readonly<{
    byAlias: string;
    sessionId: string;
    headerId: string;
    content: UserEncryptedData;
}>;

export type ChatData = Readonly<{
    chatId: string,
    chatDetails: UserEncryptedData,
    exportedChattingSession: UserEncryptedData
}>;

export type Receipt = Readonly<{
    toAlias: string,
    sessionId: string,
    headerId: string,
    signature: string,
    bounced: boolean
}>;

export type Username = { 
    readonly username: string 
};

export type ChatIdentifier = {
    readonly chatId: string;
};

export type MessageIdentifier = Readonly<{
    chatId: string;
    hashedId: string;
}>;

export type HeaderIdentifier = Readonly<{
    sessionId: string;
    headerId: string;
}>;

export type SessionIdentifier = Readonly<{ 
    sessionId: string, 
    toAlias: string
}>;

export type ChatSessionDetails = Readonly<{
    sessionId: string;
    myAlias: string;
    otherAlias: string;
}>;

export type Failure = Readonly<{
    reason: string | false;
    details?: any;
}>;

export type LogInRequest = Username & Readonly<{
    clientReference: string;
    clientEphemeralPublic: Buffer;
}>;

export type LogInSavedRequest = Readonly<{
    clientReference: string;
    serverKeyBits: Buffer;
}>;

export type SavePasswordRequest = Readonly<{
    coreKeyBits: Buffer, 
    authKeyBits: Buffer, 
    serverKeyBits: Buffer, 
    clientEphemeralPublic: Buffer
}>;

export type SavePasswordResponse = Readonly<{ 
    verifierDerive: PasswordDeriveInfo, 
    verifierEntangled: Buffer 
}>;

export type NewAuthData = Readonly<{
    verifierPoint: Buffer,
    clientIdentityVerifyingKey: Buffer
}>;

export type SignUpRequest = LogInRequest & NewAuthData;

export type SignUpChallenge = Readonly<{
    verifierEntangled: Buffer,
    serverIdentityVerifyingKey: Buffer
}>;

export type LogInChallenge = Omit<SignUpChallenge, "serverIdentityVerifyingKey"> & Readonly<{
    verifierEntangled: Buffer,
    verifierDerive: PasswordDeriveInfo,
    databaseAuthKeyDerive: PasswordEntangleInfo
}>;

export type LogInChallengeResponse = Readonly<{
    clientConfirmationCode: Buffer,
    databaseAuthKeyBuffer: Buffer
}>;

export type SignUpChallengeResponse = LogInChallengeResponse & {
    readonly newUserDataSigned: SignedEncryptedData;
};

export type SignUpResponse = Readonly<{ 
    serverConfirmationCode: Buffer,
    sessionRecordKeyDeriveSalt: Buffer
}>;

export type LogInResponse = SignUpResponse & UserData;

export type LogInSavedResponse = Omit<LogInResponse, "encryptionBaseDerive"> & {
    readonly coreKeyBits: Buffer;
}

export type UserData = Readonly<{
    encryptionBaseDerive: PasswordEntangleInfo,
    clientIdentitySigning: UserEncryptedData,
    serverIdentityVerifying: UserEncryptedData,
    x3dhInfo: UserEncryptedData,
    profileData: UserEncryptedData
}>;

export type NewUserData = Readonly<{ 
    userData: UserData;
    verifierDerive: PasswordDeriveInfo,
    databaseAuthKeyDerive: PasswordEntangleInfo;
    keyBundles: PublishKeyBundlesRequest;
}>;

export type PublishKeyBundlesRequest = {
    defaultKeyBundle: KeyBundle;
    oneTimeKeyBundles: KeyBundle[];
}

export type RequestKeyBundleResponse = {
    keyBundle: KeyBundle;
};


enum SocketClientSideEventsEnum {
    UsernameExists,
    PublishKeyBundles,
    UpdateUserData,
    RequestKeyBundle,

    GetAllChats,
    GetAllRequests,
    GetMessageHeaders,
    GetMessagesByNumber,
    GetMessagesUptoTimestamp,
    GetMessagesUptoId,
    GetMessageById,

    StoreMessage,
    CreateChat,
    UpdateChat,

    RegisterPendingSession,
    SendChatRequest,
    SendMessage,
    MessageHeaderProcessed,
    DeleteChatRequest,

    StoreBackup,
    GetBackupById,
    BackupProcessed,

    SendReceipt,
    GetAllReceipts,
    ClearAllReceipts,

    RequestRoom,
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
    PublishKeyBundles: PublishKeyBundlesRequest,
    UpdateUserData: { x3dhInfo?: UserEncryptedData } & Username,
    RequestKeyBundle: Username,
    GetAllChats: [],
    GetAllRequests: [],
    GetMessageHeaders: SessionIdentifier & { fromAlias: string },
    GetMessagesByNumber: ChatIdentifier & { limit: number, olderThanTimemark: number },
    GetMessagesUptoTimestamp: ChatIdentifier & { newerThanTimemark: number, olderThanTimemark: number },
    GetMessagesUptoId: MessageIdentifier & { olderThanTimemark: number },
    GetMessageById: MessageIdentifier,
    StoreMessage: StoredMessage,
    CreateChat: ChatData,
    UpdateChat: Omit<ChatData, "chatDetails" | "exportedChattingSession"> & Partial<ChatData>,
    RegisterPendingSession: Readonly<{ sessionId: string, myAlias: string, otherAlias: string }>,
    SendChatRequest: ChatRequestHeader,
    SendMessage: MessageHeader,
    MessageHeaderProcessed: HeaderIdentifier & SessionIdentifier,
    DeleteChatRequest: { headerId: string },
    StoreBackup: Backup,
    GetBackupById: HeaderIdentifier & { byAlias: string },
    BackupProcessed: HeaderIdentifier & { byAlias: string },
    SendReceipt: Receipt,
    GetAllReceipts: SessionIdentifier,
    ClearAllReceipts: SessionIdentifier,
    RequestRoom: Username,
}

export type SocketClientRequestParameters = {
    [E in SocketClientSideEventsKey]: SocketClientRequestParametersMap[E];
}

type SocketClientRequestReturnMap = {
    UsernameExists: { exists: boolean },
    PublishKeyBundles: never,
    UpdateUserData: never,
    RequestKeyBundle: RequestKeyBundleResponse,
    GetAllChats: ChatData[],
    GetAllRequests: ChatRequestHeader[],
    GetMessageHeaders: MessageHeader[],
    GetMessagesByNumber: StoredMessage[],
    GetMessagesUptoTimestamp: StoredMessage[],
    GetMessagesUptoId: StoredMessage[],
    GetMessageById: StoredMessage,
    StoreMessage: never,
    CreateChat: never,
    UpdateChat: never,
    RegisterPendingSession: never,
    SendChatRequest: never,
    SendMessage: never,
    MessageHeaderProcessed: never,
    DeleteChatRequest: never,
    StoreBackup: never,
    GetBackupById: Backup,
    BackupProcessed: never,
    SendReceipt: never,
    GetAllReceipts: Receipt[],
    ClearAllReceipts: never,
    RequestRoom: never,
}

export type SocketClientRequestReturn = {
    [E in SocketClientSideEventsKey]: SocketClientRequestReturnMap[E];
}

enum SocketServerSideEventsEnum {
    CompleteHandshake,
    MessageReceived,
    ChatRequestReceived,
    ReceiptReceived,
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