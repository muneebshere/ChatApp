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

export function failure(reason: CommonStrings, details: any = null): Failure {
    return details ? { reason, details } : { reason };
}

export type ExposedSignedPublicKey = {
    readonly exportedPublicKey: Buffer;
    readonly signature: Buffer; 
}

export type SignedKeyPair = ExposedSignedPublicKey & {
    readonly keyPair: CryptoKeyPair;
}

export type ExportedSigningKeyPair = {
    readonly wrappedPrivateKey: Buffer;
    readonly exportedPublicKey: Buffer;
}

export type ExportedSignedKeyPair = ExportedSigningKeyPair & {
    readonly signature: Buffer;
}

export type KeyBundle = {
    readonly owner: string;
    readonly identifier: string;
    readonly preKeyVersion: number;
    readonly verifyingIdentityKey: Buffer;
    readonly publicDHIdentityKey: ExposedSignedPublicKey;
    readonly publicSignedPreKey: ExposedSignedPublicKey;
    readonly publicOneTimeKey?: ExposedSignedPublicKey; 
}

export type PasswordDeriveInfo = {
    pSalt: Buffer;
    iterSeed: number;
} 

export type EncryptInfo = {
    encryptKey: CryptoKey;
    iv: Buffer
}

export type EncryptedData = {
    readonly ciphertext: Buffer;
}

export type SignedEncryptedData = EncryptedData & {
    readonly signature: Buffer; 
}

export type UserEncryptedData = EncryptedData & { hSalt: Buffer };

export type PasswordEncryptedData = EncryptedData & PasswordDeriveInfo & { hSalt: Buffer };

export type MessageHeader = {
    readonly addressedTo: string;
    readonly sessionId: string;
    readonly receivingRatchetNumber: number;
    readonly sendingRatchetNumber: number;
    readonly sendingChainNumber: number;
    readonly previousChainNumber: number;
    readonly nextDHRatchetKey: ExposedSignedPublicKey;
    readonly messageBody: SignedEncryptedData; 
}

export type MessageRequestHeader = {
    readonly addressedTo: string;
    readonly myVerifyingIdentityKey: Buffer;
    readonly myPublicDHIdentityKey: ExposedSignedPublicKey;
    readonly myPublicEphemeralKey: ExposedSignedPublicKey;
    readonly yourSignedPreKeyVersion: number;
    readonly yourOneTimeKeyIdentifier?: string;
    readonly initialMessage: SignedEncryptedData; 
}

export type Message = {
    readonly sentByMe: boolean;
    readonly messageId: string;
    readonly replyingTo?: string;
    readonly timestamp: number;
    readonly content: string;
    delivered: number | false;
    read: number | false;
}

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
    displayName: string,
    x3dhInfo: UserEncryptedData,
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
    displayName: string,
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
    TerminateCurrentSession = "terminate-current-session",
    LogOut = "log-out"
}

export enum CommonStrings {
    NoConnectivity = "NoConnectivity",
    DecryptFailure = "DecryptFailure",
    ProcessFailed = "ProcessFailed",
    InvalidReference = "InvalidReference",
    InvalidRequest = "InvalidRequest",
    IncorrectData = "IncorrectData",
    IncorrectPassword = "IncorrectPassword",
    TooManyWrongTries = "TooManyWrongTries"
}