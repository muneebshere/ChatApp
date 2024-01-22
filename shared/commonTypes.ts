import _ from "lodash";

export type ExposedSignedPublicKey = Readonly<{
    exportedPublicKey: Buffer;
    signature: Buffer; 
}>;

export type SignedKeyPair = ExposedSignedPublicKey & {
    readonly keyPair: CryptoKeyPair;
};

export type ExportedSigningKeyPair = Readonly<{
    wrappedPrivateKey: EncryptedData;
    exportedPublicKey: Buffer;
}>;

export type ExportedSignedKeyPair = ExportedSigningKeyPair & {
    readonly signature: Buffer;
};

export type ServerMemo = Readonly<{
    memoId: string,
    encryptionPublicKey: Buffer,
    memoData: {
        ciphertext: Buffer,
        hSalt: Buffer,
        signature: Buffer }
}>;

export type PublicIdentity = Readonly<{ 
    publicIdentityVerifyingKey: Buffer, 
    publicDHIdentityKey: ExposedSignedPublicKey 
}>;

export type KeyBundleId = Readonly<{ 
    bundleId: string;
    preKeyVersion: number;
    oneTimeKeyIdentifier?: string; 
}>;

export type KeyBundle = Readonly<{
    bundleId: string;
    owner: string;
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
};

export type EncryptInfo = Readonly<{
    encryptKey: CryptoKey;
    iv: Buffer
}>;

export type EncryptedData = Readonly<{
    ciphertext: Buffer;
    hSalt: Buffer;
}>;

export type SignedEncryptedData = EncryptedData & {
    readonly signature: Buffer; 
};

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
};

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
    yourBundleId: string;
    initialMessage: SignedEncryptedData; 
}>;

export type StoredMessage = Readonly<{
    chatId: string;
    hashedId: string;
    timemark: number;
    content: EncryptedData;
}>;

export type Backup = Readonly<{
    byAlias: string;
    sessionId: string;
    headerId: string;
    content: EncryptedData;
}>;

export type MutableChatData = Readonly<{
    contactDetailsRecord: EncryptedData,
    exportedChattingSession: EncryptedData
}>;

export type ChatData = MutableChatData & Readonly<{
    chatId: string,
    timeRatioRecord: EncryptedData
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
    publicIdentity: PublicIdentity
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
    sessionRecordKeyDeriveSalt: Buffer,
    saveSessionKey: Buffer
}>;

export type LogInResponse = SignUpResponse & UserData;

export type LogInSavedResponse = Omit<LogInResponse, "encryptionBaseDerive"> & {
    readonly coreKeyBits: Buffer;
};

export type X3DHKeysData = {
    readonly x3dhKeys: EncryptedData
};

export type X3DHRequestsData = {
    readonly x3dhRequests: EncryptedData
};

export type X3DHData = X3DHKeysData & X3DHRequestsData;

export type X3DHDataPartial = X3DHKeysData | X3DHRequestsData | X3DHData;

export type UserData = Readonly<{
    encryptionBaseDerive: PasswordEntangleInfo,
    serverIdentityVerifying: EncryptedData,
    x3dhIdentity: EncryptedData,
    x3dhData: X3DHData,
    profileData: SignedEncryptedData
}>;

export type NewUserData = Readonly<{ 
    userData: UserData;
    verifierDerive: PasswordDeriveInfo,
    databaseAuthKeyDerive: PasswordEntangleInfo;
}>;

export type RequestKeyBundleResponse = {
    readonly keyBundle: KeyBundle;
};

export type IssueOneTimeKeysResponse = Readonly<{
    x3dhKeysData: X3DHKeysData;
    oneTimeKeys: [string, ExposedSignedPublicKey][];
}>;

export type ReplacePreKeyResponse = Readonly<{
    x3dhKeysData: X3DHKeysData;
    preKey: [number, ExposedSignedPublicKey];
}>

export type RequestIssueNewKeysResponse = IssueOneTimeKeysResponse | ReplacePreKeyResponse;


enum SocketClientSideEventsEnum {
    ClientLoaded,
    UsernameExists,
    UpdateProfile,
    UpdateX3DHData,
    FetchUserData,
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
    ServerMemosProcessed,

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
    ClientLoaded: [],
    UsernameExists: Username,
    UpdateProfile: { profileData: SignedEncryptedData },
    UpdateX3DHData: { x3dhData: X3DHDataPartial },
    FetchUserData: [],
    RequestKeyBundle: Username,
    GetAllChats: [],
    GetAllRequests: [],
    GetMessageHeaders: SessionIdentifier & { fromAlias: string },
    GetMessagesByNumber: ChatIdentifier & { limit: number, olderThanTimemark: number },
    GetMessagesUptoTimestamp: ChatIdentifier & { newerThanTimemark: number, olderThanTimemark: number },
    GetMessagesUptoId: MessageIdentifier & { olderThanTimemark: number },
    GetMessageById: MessageIdentifier,
    StoreMessage: StoredMessage,
    CreateChat: ChatData & { otherUser: string },
    UpdateChat: ChatIdentifier & Partial<MutableChatData>,
    RegisterPendingSession: Readonly<{ sessionId: string, myAlias: string, otherAlias: string }>,
    SendChatRequest: ChatRequestHeader,
    SendMessage: MessageHeader,
    MessageHeaderProcessed: HeaderIdentifier & SessionIdentifier,
    DeleteChatRequest: { headerId: string },
    StoreBackup: Backup,
    GetBackupById: HeaderIdentifier & { byAlias: string },
    BackupProcessed: HeaderIdentifier & { byAlias: string },
    ServerMemosProcessed: { processed: string[], x3dhData: X3DHKeysData },
    SendReceipt: Receipt,
    GetAllReceipts: SessionIdentifier,
    ClearAllReceipts: SessionIdentifier,
    RequestRoom: Username,
}

export type SocketClientRequestParameters = {
    [E in SocketClientSideEventsKey]: SocketClientRequestParametersMap[E];
}

type SocketClientRequestReturnMap = {
    ClientLoaded: never,
    UsernameExists: { exists: boolean },
    UpdateProfile: never,
    UpdateX3DHData: never,
    FetchUserData: { x3dhIdentity: EncryptedData, x3dhData: X3DHData, profileData: SignedEncryptedData },
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
    ServerMemosProcessed: never,
    SendReceipt: never,
    GetAllReceipts: Receipt[],
    ClearAllReceipts: never,
    RequestRoom: never,
}

export type SocketClientRequestReturn = {
    [E in SocketClientSideEventsKey]: SocketClientRequestReturnMap[E];
}

enum SocketServerSideEventsEnum {
    RequestIssueNewKeys,
    ServerMemoDeposited,
    PollConnection,
    MessageReceived,
    ChatRequestReceived,
    ReceiptReceived,
    RoomRequested,
    ClientRoomReady,
    ServerRoomReady,
    ServerDisconnecting
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

type SocketServerRequestParametersMap = {
    RequestIssueNewKeys: { n: number },
    ServerMemoDeposited: { serverMemos: ServerMemo[] },
    PollConnection: [],
    MessageReceived: { sessionId: string },
    ChatRequestReceived: {},
    ReceiptReceived: { sessionId: string },
    RoomRequested: Username,
    ClientRoomReady: string,
    ServerRoomReady: string,
    ServerDisconnecting: { reason: string }
}

export type SocketServerRequestParameters = {
    [E in SocketServerSideEventsKey]: SocketServerRequestParametersMap[E];
}

type SocketServerRequestReturnMap = {
    RequestIssueNewKeys: RequestIssueNewKeysResponse,
    ServerMemoDeposited: never,
    PollConnection: never,
    MessageReceived: never,
    ChatRequestReceived: never,
    ReceiptReceived: never,
    RoomRequested: Failure,
    ClientRoomReady: never,
    ServerRoomReady: never,
    ServerDisconnecting: {}
}

export type SocketServerRequestReturn = {
    [E in SocketServerSideEventsKey]: SocketServerRequestReturnMap[E];
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