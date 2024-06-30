import _ from "lodash";
import * as crypto from "../shared/cryptoOperator";
import { ExposedSignedPublicKey, SignedKeyPair, ExportedSignedKeyPair, ExportedSigningKeyPair, KeyBundle, MessageHeader, ChatRequestHeader, Profile, StoredMessage, PublicIdentity, KeyBundleId, IssueOneTimeKeysResponse, ReplacePreKeyResponse, ServerMemo, EncryptedData, SignedEncryptedData, X3DHData, X3DHKeysData, X3DHRequestsData, X3DHDataPartial, NewUserData, DirectChannelRequest } from "../shared/commonTypes";
import { Queue } from "async-await-queue";
import { fromBase64, logError, randomFunctions } from "../shared/commonFunctions";
import { SessionCrypto } from "../shared/sessionCrypto";

const { getRandomVector, getRandomString } = randomFunctions();

const nullSalt = (length: number) => Buffer.alloc(length);

type MessageBody = Readonly<{
    sender: string;
    timestamp: number;
    messageId: string;
}>

type MessageText = Readonly<{
    replyingTo?: string;
    text: string;
}>;

type MessageEvent = Readonly<{
    reportingAbout: string;
    event: "delivered" | "seen";
} | {
    event: "typing" | "stopped-typing";
} | {
    event: "status-online";
    responding: boolean;
} | {
    event: "status-offline";
    responding: false
}>;

type ProfileMessage = {
    readonly profile: Profile
};

export type DirectChannelMessage = Readonly<{
    action: "requesting" | "responding" | "establishing" | "accepted",
    directChannelId: string
}>;

export type RTCSessionMessage = Readonly<{
    rtcSessionId: string,
    role: "offer" | "answer";
    sessionDescription: RTCSessionDescription;
}>;

type ICECandidateMessage = Readonly<{
    rtcSessionId: string,
    candidate: RTCIceCandidate
}>;

type MessageContent = MessageText | MessageEvent | ProfileMessage | DirectChannelMessage | RTCSessionMessage | ICECandidateMessage;

type ReceivingMessage = MessageBody & MessageContent;

export type SendingMessage = Omit<MessageBody, "sender"> & MessageContent;

type ChatRequestBody = Readonly<{
    messageId: string;
    myAlias: string;
    yourAlias: string;
    myKeySignature: string;
    yourKeySignature: string;
    yourUsername: string;
    myDHRatchetInititalizer: ExposedSignedPublicKey;
    timestamp: number;
    text: string;
    profile: Profile;
}>;

export type ViewSentRequest = Readonly<{
    timestamp: number;
    sessionId: string;
    headerId: string;
    myAlias: string;
    otherAlias: string;
    messageId: string;
    otherUser: string;
    text: string;
}>;

type SentChatRequest = ViewSentRequest & Readonly<{
    recipientVerifyKey: CryptoKey;
    sharedRoot: Buffer;
    myPrivateDHRatchetInitializer: CryptoKey;
}>;

export type ViewReceivedRequest = Omit<ViewSentRequest, "otherUser"> & Readonly<{
    profile: Profile;
}>;

type ReceivedChatRequest = ViewReceivedRequest & Readonly<{
    sharedRoot: Buffer,
    importedVerifyingIdentityKey: CryptoKey,
    importedDHInitializer: CryptoKey
}>;

type ExportedSentChatRequest = Omit<SentChatRequest, "recipientVerifyKey" | "myPrivateDHRatchetInitializer"> & Readonly<{
    recipientVerifyKey: Buffer;
    myPrivateDHRatchetInitializer: Buffer;
}>;

type ExportedReceivedChatRequest = Omit<ReceivedChatRequest, "importedVerifyingIdentityKey" |  "importedDHInitializer"> & Readonly<{
    importedVerifyingIdentityKey: Buffer,
    importedDHInitializer: Buffer
}>;

type ExportedX3DHIdentity = Readonly<{
    username: string;
    identitySigningKeyPair: ExportedSigningKeyPair;
    identityDHKeyPair: ExportedSignedKeyPair;
    x3dhBaseEncrypted: SignedEncryptedData;
}>

type ExportedX3DHKeys = Readonly<{
    currentPreKeyVersion: number;
    preKeys: Map<number, EncryptedData>;
    oneTimeKeys: Map<string, EncryptedData>;
    issuedBundles: EncryptedData;
}>;

type ExportedX3DHRequests = Readonly<{
    sentChatRequests: EncryptedData;
    receivedChatRequests: EncryptedData;
    maxSkip: number
}>;

type ExportedChattingSession = Readonly<{
    sessionId: string;
    createdAt: number;
    lastActivity: number;
    sender: string;
    recipient: string;
    senderAlias: string;
    recipientAlias: string;
    maxSkip: number;
    recipientVerifyKey: Buffer;
    currentRootKey: Buffer;
    currentDHRatchetKey: EncryptedData;
    currentDHPublishKey: ExposedSignedPublicKey;
    currentSendingChainKey: Buffer;
    currentReceivingChainKey: Buffer;
    sendingRatchetNumber: number;
    receivingRatchetNumber: number;
    sendingChainNumber: number;
    receivingChainNumber: number;
    previousSendingChainNumber: number;
}>;

interface X3DHIdentityInterface {
    readonly username: string;
    readonly publicIdentityVerifyingKeyBuffer: Buffer;
    readonly publicDHIdentityKey: ExposedSignedPublicKey;
    generateSignedKeyPair(): Promise<SignedKeyPair>;
    deriveSymmetricBits(publicKey: CryptoKey, size: 256 | 512): Promise<Buffer>;
    userWrap(privateKey: CryptoKey, purpose: string): Promise<EncryptedData>,
    userUnwrap(wrappedKey: EncryptedData, name: "ECDH" | "ECDSA", purpose: string, extractable: boolean): Promise<CryptoKey>;
    deriveSignEncrypt<T extends any>(initialData: T, sharedRoot: CryptoKey | Buffer, purpose: string): Promise<SignedEncryptedData>;
    deriveDecryptVerify<T extends any>(encryptedData: SignedEncryptedData, sharedRoot: CryptoKey | Buffer, purpose: string, otherVerifyingKey?: CryptoKey): Promise<T>;
    x3dhEncrypt<T extends any>(initialData: T, purpose: string): Promise<EncryptedData>;
    x3dhDecrypt<T extends any>(encryptedData: EncryptedData, purpose: string): Promise<T>;
    sign(data: Buffer): Promise<Buffer>;
}

interface X3DHKeysInterface {
    getIssuedBundle(bundleId: string): KeyBundleId | undefined;
    getPreKey(version: number): CryptoKey | undefined;
    getOneTimeKey(oneTimeKeyIdentifier: string | undefined): CryptoKey | undefined;
    delete(bundleId: string): Promise<X3DHKeysData | null>
}

class X3DHIdentity {
    readonly username: string;
    readonly publicIdentityVerifyingKeyBuffer: Buffer;
    readonly #x3dhBaseVector: CryptoKey;
    readonly #x3dhBaseEncrypted: SignedEncryptedData;
    readonly #identitySigningKeyPair: CryptoKeyPair;
    readonly #identityDHKeyPair: SignedKeyPair;
    readonly interface: X3DHIdentityInterface;

    private constructor(username: string,
        x3dhBaseVector: CryptoKey,
        x3dhBaseEncrypted: SignedEncryptedData,
        identitySigningKeyPair: CryptoKeyPair,
        publicIdentityVerifyingKeyBuffer: Buffer,
        identityDHKeyPair: SignedKeyPair) {
            this.username = username;
            this.publicIdentityVerifyingKeyBuffer = publicIdentityVerifyingKeyBuffer;
            this.#x3dhBaseVector = x3dhBaseVector;
            this.#x3dhBaseEncrypted = x3dhBaseEncrypted;
            this.#identitySigningKeyPair = identitySigningKeyPair;
            this.#identityDHKeyPair = identityDHKeyPair;
            this.interface = {
                username,
                publicIdentityVerifyingKeyBuffer,
                publicDHIdentityKey: crypto.exposeSignedKey(identityDHKeyPair),
                generateSignedKeyPair: () => this.generateSignedKeyPair(),
                deriveSymmetricBits: (publicKey: CryptoKey, size: 256 | 512) => this.deriveSymmetricBits(publicKey, size),
                userWrap: (privateKey: CryptoKey, purpose: string) => this.userWrap(privateKey, purpose),
                userUnwrap: (wrappedKey: EncryptedData, name: "ECDH" | "ECDSA", purpose: string, extractable: boolean) => this.userUnwrap(wrappedKey, name, purpose, extractable),
                deriveSignEncrypt: <T extends any>(initialData: T, sharedRoot: CryptoKey | Buffer, purpose: string) => this.deriveSignEncrypt(initialData, sharedRoot, purpose),
                deriveDecryptVerify: <T extends any>(encryptedData: SignedEncryptedData, sharedRoot: CryptoKey | Buffer, purpose: string, otherVerifyingKey?: CryptoKey) => this.deriveDecryptVerify(encryptedData, sharedRoot, purpose, otherVerifyingKey),
                x3dhEncrypt: <T extends any>(initialData: T, purpose: string) => this.x3dhEncrypt(initialData, purpose),
                x3dhDecrypt: <T extends any>(encryptedData: EncryptedData, purpose: string) => this.x3dhDecrypt(encryptedData, purpose),
                sign: (data: Buffer) => this.sign(data)
            };
    }

    static async new(username: string, encryptionBaseVector: CryptoKey): Promise<[X3DHIdentity, EncryptedData] | null> {
            const identitySigningKeyPair = await crypto.generateKeyPair("ECDSA");
            const identityDHKeyPair = await crypto.generateSignedKeyPair(identitySigningKeyPair.privateKey);
            const x3dhBase = getRandomVector(64);
            const x3dhBaseEncrypted = await crypto.deriveSignEncrypt({ x3dhBase }, encryptionBaseVector, `User ${username} X3DH Base`, identitySigningKeyPair.privateKey);
            const x3dhBaseVector = await crypto.importRaw(x3dhBase);
            const identity = new X3DHIdentity(username, x3dhBaseVector, x3dhBaseEncrypted, identitySigningKeyPair, await crypto.exportKey(identitySigningKeyPair.publicKey), identityDHKeyPair);
            const exported = await identity.export(encryptionBaseVector);
            if (!exported) return null;
            return [identity, exported];
    }

    static async import(username: string, encryptedIdentity: EncryptedData, encryptionBaseVector: CryptoKey) : Promise<X3DHIdentity | null> {
        try {
            const importedIdentity: ExportedX3DHIdentity = await crypto.deriveDecrypt(encryptedIdentity, encryptionBaseVector,`Export|Import ${username} X3DH Identity`);
            if (!importedIdentity) {
                return null;
            }
            const {
                identitySigningKeyPair: exportedidentityKeyPair,
                identityDHKeyPair: exportedIdentityDHKeyPair,
                x3dhBaseEncrypted } = importedIdentity;
            const identitySigningKeyPair = await crypto.importSigningKeyPair(exportedidentityKeyPair, encryptionBaseVector, `User ${username} X3DH Identity Signing`);
            const identityDHKeyPair = await crypto.importSignedKeyPair(exportedIdentityDHKeyPair, encryptionBaseVector, `User ${username} X3DH Identity DH`);
            const { x3dhBase } = await crypto.deriveDecryptVerify(x3dhBaseEncrypted, encryptionBaseVector, `User ${username} X3DH Base`, identitySigningKeyPair.publicKey);
            const x3dhBaseVector = await crypto.importRaw(x3dhBase);
            const identity = new X3DHIdentity(username, x3dhBaseVector, x3dhBaseEncrypted, identitySigningKeyPair, await crypto.exportKey(identitySigningKeyPair.publicKey), identityDHKeyPair);
            return identity;
        }
        catch(err) {
            logError(`${err}`);
            return null;
        }
    }

    private async export(encryptionBaseVector: CryptoKey): Promise<EncryptedData | null> {
        try {
            const { username } = this;
            const identitySigningKeyPair = await crypto.exportSigningKeyPair(this.#identitySigningKeyPair, encryptionBaseVector, `User ${username} X3DH Identity Signing`);
            const identityDHKeyPair = await crypto.exportSignedKeyPair(this.#identityDHKeyPair, encryptionBaseVector, `User ${username} X3DH Identity DH`);
            const exportedUser: ExportedX3DHIdentity = {
                username,
                x3dhBaseEncrypted: this.#x3dhBaseEncrypted,
                identitySigningKeyPair,
                identityDHKeyPair };
            return await crypto.deriveEncrypt(exportedUser, encryptionBaseVector, `Export|Import ${username} X3DH Identity`);
        }
        catch (err) {
            logError(err);
            return null;
        }
    }

    get publicDHIdentityKey(): ExposedSignedPublicKey {
        return crypto.exposeSignedKey(this.#identityDHKeyPair);
    }

    get publicIdentityVerifyingKey(): ExposedSignedPublicKey {
        return crypto.exposeSignedKey(this.#identityDHKeyPair);
    }

    get publicIdentity(): PublicIdentity {
        const { publicIdentityVerifyingKeyBuffer: publicIdentityVerifyingKey, publicDHIdentityKey } = this;
        return { publicIdentityVerifyingKey, publicDHIdentityKey };
    }

    async generateSignedKeyPair(): Promise<SignedKeyPair> {
        return await crypto.generateSignedKeyPair(this.#identitySigningKeyPair.privateKey);
    }

    async deriveSignEncrypt<T extends any>(initialData: T, sharedRoot: CryptoKey | Buffer, purpose: string): Promise<SignedEncryptedData> {
        return await crypto.deriveSignEncrypt(initialData, sharedRoot, purpose, this.#identitySigningKeyPair.privateKey);
    }

    async deriveDecryptVerify<T extends any>(encryptedData: SignedEncryptedData, sharedRoot: CryptoKey | Buffer, purpose: string, otherVerifyingKey?: CryptoKey): Promise<T> {
        return await crypto.deriveDecryptVerify(encryptedData, sharedRoot, purpose, otherVerifyingKey || this.#identitySigningKeyPair.publicKey);
    }

    async deriveSymmetricBits(publicKey: CryptoKey, size: 256 | 512): Promise<Buffer> {
        return await crypto.deriveSymmetricBits(this.#identityDHKeyPair.keyPair.privateKey, publicKey, size);
    };

    async sign(data: Buffer): Promise<Buffer> {
        return await crypto.sign(data, this.#identitySigningKeyPair.privateKey);
    }

    async x3dhEncrypt<T extends any>(initialData: T, purpose: string): Promise<EncryptedData> {
        return await crypto.deriveSignEncrypt(initialData, this.#x3dhBaseVector, purpose);
    }

    async x3dhDecrypt<T extends any>(encryptedData: EncryptedData, purpose: string): Promise<T> {
        return await crypto.deriveDecrypt(encryptedData, this.#x3dhBaseVector, purpose);
    }

    async userWrap(privateKey: CryptoKey, purpose: string): Promise<EncryptedData> {
        return await crypto.deriveWrap(privateKey, this.#x3dhBaseVector, purpose);
    }

    async userUnwrap(wrappedKey: EncryptedData, name: "ECDH" | "ECDSA", purpose: string, extractable: boolean): Promise<CryptoKey> {
        return await crypto.deriveUnwrap(wrappedKey, this.#x3dhBaseVector, name, purpose, extractable);
    }

    async createSessionCrypto(clientReference: string, sharedKeyBits: CryptoKey, sessionVerifyingKey: Buffer): Promise<SessionCrypto> {
        return new SessionCrypto(clientReference, sharedKeyBits, this.#identitySigningKeyPair.privateKey, await crypto.importKey(sessionVerifyingKey, "ECDSA", "public", false));
    }

    async importChattingSession(encryptedSession: EncryptedData) {
        return await ChattingSession.import(encryptedSession, this.interface);
    }
}

class X3DHKeys {
    readonly #identity: X3DHIdentityInterface;
    readonly #preKeys = new Map<number, CryptoKey>();
    readonly #oneTimeKeys = new Map<string, CryptoKey>();
    readonly #issuedBundles = new Map<string, KeyBundleId>();
    #currentPreKeyVersion: number;
    readonly interface = {
        getIssuedBundle: (bundleId: string) => this.getIssuedBundle(bundleId),
        getPreKey: (version: number) => this.getPreKey(version),
        getOneTimeKey: (oneTimeKeyIdentifier: string | undefined) => this.getOneTimeKey(oneTimeKeyIdentifier),
        delete: (bundleId: string) => this.delete(bundleId)
    };

    private constructor(identity: X3DHIdentityInterface, issuedBundles: Map<string, KeyBundleId>, currentPreKeyVersion: number) {
        this.#identity = identity;
        this.#issuedBundles = issuedBundles;
        this.#currentPreKeyVersion = currentPreKeyVersion;
    }

    static async new(identity: X3DHIdentityInterface): Promise<[NewUserData["firstKeys"], X3DHKeys, X3DHKeysData] | null> {
        const x3dhKeys = new X3DHKeys(identity, new Map(), 0);
        const { preKey } = await x3dhKeys.replacePreKey() || { preKey: null };
        const keys = await x3dhKeys.issueOneTimeKeys(1);
        if (!keys || !preKey) return null;
        const { oneTimeKeys, x3dhKeysData } = keys;
        return [{ preKey, oneTimeKey: oneTimeKeys[0] }, x3dhKeys, x3dhKeysData];
    }

    static async import(encryptedKeys: EncryptedData, identity: X3DHIdentityInterface) : Promise<X3DHKeys | null> {
        try {
            const { username } = identity;
            const importedKeys: ExportedX3DHKeys = await identity.x3dhDecrypt(encryptedKeys, `Export|Import ${username} X3DH Keys`);
            if (!importedKeys) {
                return null;
            }
            const {
                currentPreKeyVersion,
                preKeys,
                oneTimeKeys,
                issuedBundles: encryptedIssuedBundles } = importedKeys;
            const issuedBundles: Map<string, KeyBundleId> = await identity.x3dhDecrypt(encryptedIssuedBundles, `${username} X3DH Issued Bundles`);
            const x3dhKeys = new X3DHKeys(identity, issuedBundles, currentPreKeyVersion);
            for (const [ver, wrappedKey] of preKeys.entries()) {
                x3dhKeys.#preKeys.set(ver, await identity.userUnwrap(wrappedKey, "ECDH", `${username} X3DH PreKey ${ver}`, true));
            }
            for (const [id, wrappedKey] of oneTimeKeys.entries()) {
                x3dhKeys.#oneTimeKeys.set(id, await identity.userUnwrap(wrappedKey, "ECDH", `${username} X3DH OneTimeKey ${id}`, true));
            }
            return x3dhKeys;
        }
        catch(err) {
            logError(`${err}`);
            return null;
        }
    }

    private async export(): Promise<EncryptedData | null> {
        try {
            const currentPreKeyVersion = this.#currentPreKeyVersion;
            const { username } = this.#identity;
            const preKeys = new Map<number, EncryptedData>();
            for (const [ver, key] of this.#preKeys.entries()) {
                preKeys.set(ver, await this.#identity.userWrap(key, `${username} X3DH PreKey ${ver}`));
            }
            const oneTimeKeys = new Map<string, EncryptedData>();
            for (const [id, key] of this.#oneTimeKeys.entries()) {
                oneTimeKeys.set(id, await this.#identity.userWrap(key, `${username} X3DH OneTimeKey ${id}`));
            }
            const issuedBundles = await this.#identity.x3dhEncrypt(this.#issuedBundles, `${username} X3DH Issued Bundles`);
            const exportedUser: ExportedX3DHKeys = {
                currentPreKeyVersion,
                preKeys,
                oneTimeKeys,
                issuedBundles
            };
            const serialized = crypto.serialize(exportedUser);
            const deserialized = crypto.deserialize(serialized);
            return await this.#identity.x3dhEncrypt(exportedUser, `Export|Import ${username} X3DH Keys`);
        }
        catch (err) {
            logError(err);
            return null;
        }
    }

    private async exportData(): Promise<X3DHKeysData | null> {
        const x3dhKeys = await this.export();
        if (!x3dhKeys) return null;
        return { x3dhKeys };
    }

    getIssuedBundle(bundleId: string): KeyBundleId | undefined {
        return this.#issuedBundles.get(bundleId);
    }

    getPreKey(version: number): CryptoKey | undefined {
        return this.#preKeys.get(version);
    }

    getOneTimeKey(oneTimeKeyIdentifier: string | undefined): CryptoKey | undefined {
        if (!oneTimeKeyIdentifier) return undefined;
        return this.#oneTimeKeys.get(oneTimeKeyIdentifier);
    }

    async delete(bundleId: string): Promise<X3DHKeysData | null> {
        const { preKeyVersion, oneTimeKeyIdentifier } = this.#issuedBundles.get(bundleId) || {};
        if (!oneTimeKeyIdentifier) return null;
        this.#issuedBundles.delete(bundleId);
        this.#oneTimeKeys.delete(oneTimeKeyIdentifier);
        if (preKeyVersion! < this.#currentPreKeyVersion && [...this.#issuedBundles.values()].every(({ preKeyVersion: v }) => v !== preKeyVersion)) this.#preKeys.delete(preKeyVersion!);
        return await this.exportData();
    }

    async issueOneTimeKeys(n: number): Promise<IssueOneTimeKeysResponse | null> {
        const oneTimeKeys = new Array<[string, ExposedSignedPublicKey]>();
        for (let i = 0; i < n; i++) {
            const newKey = await this.#identity.generateSignedKeyPair();
            const id = `${getRandomString(10, "base64")}-${Date.now()}`;
            oneTimeKeys.push([id, crypto.exposeSignedKey(newKey)]);
            this.#oneTimeKeys.set(id, newKey.keyPair.privateKey);
        }
        const x3dhKeysData = await this.exportData();
        if (!x3dhKeysData) return null;
        return { x3dhKeysData, oneTimeKeys };
    }

    async replacePreKey(): Promise<ReplacePreKeyResponse | null> {
        const newKey = await this.#identity.generateSignedKeyPair();
        const newVersion = this.#currentPreKeyVersion + 1;
        this.#preKeys.set(newVersion, newKey.keyPair.privateKey);
        this.#currentPreKeyVersion = newVersion;
        const x3dhKeysData = await this.exportData();
        if (!x3dhKeysData) return null;
        return { x3dhKeysData, preKey: [newVersion, crypto.exposeSignedKey(newKey)] };
    }

    async registerBundle(keyBundleId: KeyBundleId): Promise<X3DHKeysData | null> {
        this.#issuedBundles.set(keyBundleId.bundleId, keyBundleId);
        return await this.exportData();
    }
}

class X3DHRequests {
    readonly #identity: X3DHIdentityInterface;
    readonly #keys: X3DHKeysInterface;
    readonly #sentChatRequests = new Map<string, SentChatRequest>();
    readonly #receivedChatRequests = new Map<string, ReceivedChatRequest>();
    private readonly maxSkip: number;

    private constructor(identity: X3DHIdentityInterface, keys: X3DHKeysInterface, maxSkip = 20) {
        this.#identity = identity;
        this.#keys = keys;
        this.maxSkip = maxSkip;
    }

    static async new(identity: X3DHIdentityInterface, keys: X3DHKeysInterface, maxSkip = 20): Promise<[X3DHRequests, X3DHRequestsData] | null> {
        const x3dhRequests = new X3DHRequests(identity, keys, maxSkip);
        const x3dhRequestsData = await x3dhRequests.exportData();
        if (!x3dhRequestsData) return null;
        return [x3dhRequests, x3dhRequestsData];
    }

    static async import(encryptedRequests: EncryptedData, identity: X3DHIdentityInterface, keys: X3DHKeysInterface) : Promise<X3DHRequests | null> {
        try {
            const { username } = identity;
            const importedRequests: ExportedX3DHRequests = await identity.x3dhDecrypt(encryptedRequests, `Export|Import ${username} X3DH Requests`);
            if (!importedRequests) {
                return null;
            }
            const {
                maxSkip,
                sentChatRequests: encryptedSentRequests,
                receivedChatRequests: encryptedReceivedRequests } = importedRequests;
            const x3dhRequests = new X3DHRequests(identity, keys, maxSkip);
            const exportedSentRequests: Map<string, ExportedSentChatRequest> = await identity.x3dhDecrypt(encryptedSentRequests, `${username} X3DH Sent Chat Requests`);
            for (const [sessionId, { myPrivateDHRatchetInitializer, recipientVerifyKey, ...rest }] of exportedSentRequests) {
                x3dhRequests.#sentChatRequests.set(sessionId, {
                    recipientVerifyKey: await crypto.importKey(recipientVerifyKey, "ECDSA", "public", true),
                    myPrivateDHRatchetInitializer: await crypto.importKey(myPrivateDHRatchetInitializer, "ECDH", "private", true),
                    ...rest
                });
            }
            const exportedReceivedRequests: Map<string, ExportedReceivedChatRequest> = await identity.x3dhDecrypt(encryptedReceivedRequests, `${username} X3DH Received Chat Requests`);
            for (const [sessionId, { importedDHInitializer, importedVerifyingIdentityKey, ...rest }] of exportedReceivedRequests) {
                x3dhRequests.#receivedChatRequests.set(sessionId, {
                    importedVerifyingIdentityKey: await crypto.importKey(importedVerifyingIdentityKey, "ECDSA", "public", true),
                    importedDHInitializer: await crypto.importKey(importedDHInitializer, "ECDH", "public", true),
                    ...rest
                });
            }
            return x3dhRequests;
        }
        catch(err) {
            logError(`${err}`);
            return null;
        }
    }

    private async export(): Promise<EncryptedData | null> {
        try {
            const { username } = this.#identity;
            const { maxSkip } = this;
            const exportedSentRequests = new Map<string, ExportedSentChatRequest>();
            for (const [sessionId, { myPrivateDHRatchetInitializer, recipientVerifyKey, ...rest }] of this.#sentChatRequests) {
                exportedSentRequests.set(sessionId, {
                    recipientVerifyKey: await crypto.exportKey(recipientVerifyKey),
                    myPrivateDHRatchetInitializer: await crypto.exportKey(myPrivateDHRatchetInitializer),
                    ...rest
                });
            }
            const sentChatRequests = await this.#identity.x3dhEncrypt(exportedSentRequests, `${username} X3DH Sent Chat Requests`);
            const exportedReceivedRequests = new Map<string, ExportedReceivedChatRequest>();
            for (const [sessionId, { importedDHInitializer, importedVerifyingIdentityKey, ...rest }] of this.#receivedChatRequests) {
                exportedReceivedRequests.set(sessionId, {
                    importedVerifyingIdentityKey: await crypto.exportKey(importedVerifyingIdentityKey),
                    importedDHInitializer: await crypto.exportKey(importedDHInitializer),
                    ...rest
                });
            }
            const receivedChatRequests = await this.#identity.x3dhEncrypt(exportedReceivedRequests, `${username} X3DH Received Chat Requests`);
            const exportedUser: ExportedX3DHRequests = {
                maxSkip,
                sentChatRequests,
                receivedChatRequests
            };
            return await this.#identity.x3dhEncrypt(exportedUser, `Export|Import ${username} X3DH Requests`);
        }
        catch(err) {
            logError(err);
            return null;
        }
    }

    private async exportData(): Promise<X3DHRequestsData | null> {
        const x3dhRequests = await this.export();
        if (!x3dhRequests) return null;
        return { x3dhRequests };
    }

    get allPendingSentRequests(): ViewSentRequest[] {
        return Array.from(this.#sentChatRequests.values()).map((req) => _.pick(req, "messageId", "timestamp", "otherUser", "text", "sessionId", "myAlias", "otherAlias", "headerId"));
    }

    get allPendingReceivedRequests(): ViewReceivedRequest[] {
        return Array.from(this.#receivedChatRequests.values()).map((req) => _.pick(req, "messageId", "timestamp", "otherUser", "text", "sessionId", "myAlias", "otherAlias", "headerId", "profile") as ViewReceivedRequest);
    }

    private get username(): string {
        return this.#identity.username;
    }

    getPendingSentRequest(sessionId: string): ViewSentRequest {
        return _.pick(this.#sentChatRequests.get(sessionId), "messageId", "timestamp", "otherUser", "text", "sessionId", "myAlias", "otherAlias", "headerId") as ViewSentRequest;
    }

    getPendingReceivedRequest(sessionId: string): ViewReceivedRequest {
        return _.pick(this.#receivedChatRequests.get(sessionId), "messageId", "timestamp", "otherUser", "text", "sessionId", "myAlias", "otherAlias", "headerId", "profile") as ViewReceivedRequest;
    }

    async generateChatRequest(keyBundle: KeyBundle, messageId: string, text: string, timestamp: number, profileDetails: Omit<Profile, "username">) : Promise<[X3DHRequestsData, ChatRequestHeader, ViewSentRequest] | "Invalid Identity Signature" | "Invalid PreKey Signature" | "Invalid OneTimeKey Signature" | "Could Not Save"> {
        const {
            bundleId,
            owner: yourUsername,
            verifyingIdentityKey,
            publicDHIdentityKey: otherDHIdentityKey,
            publicSignedPreKey,
            publicOneTimeKey } = keyBundle;
        const importedVerifyingIdentityKey = await this.importVerifyingKey(verifyingIdentityKey);
        const importedDHIdentityKey = await crypto.verifyKey(otherDHIdentityKey, importedVerifyingIdentityKey);
        if (!importedDHIdentityKey) return "Invalid Identity Signature";
        const importedPreKey = await crypto.verifyKey(publicSignedPreKey, importedVerifyingIdentityKey);
        if (!importedPreKey) return "Invalid PreKey Signature";
        let importedOneTimeKey: CryptoKey | null | undefined;
        if (publicOneTimeKey) {
            importedOneTimeKey = await crypto.verifyKey(publicOneTimeKey, importedVerifyingIdentityKey);
            if (!importedOneTimeKey) return "Invalid OneTimeKey Signature";
        }
        const ephemeralKeyPair = await this.#identity.generateSignedKeyPair();
        const myPublicEphemeralKey = crypto.exposeSignedKey(ephemeralKeyPair);
        const dh1 = await this.#identity.deriveSymmetricBits(importedPreKey, 512);
        const dh2 = await crypto.deriveSymmetricBits(ephemeralKeyPair.keyPair.privateKey, importedDHIdentityKey, 512);
        const dh3 = await crypto.deriveSymmetricBits(ephemeralKeyPair.keyPair.privateKey, importedPreKey, 512);
        const dh4 = (importedOneTimeKey !== undefined)
                    ? [await crypto.deriveSymmetricBits(ephemeralKeyPair.keyPair.privateKey, importedOneTimeKey!, 512)]
                    : [];
        const sharedRoot = Buffer.concat([dh1, dh2, dh3, ...dh4]);
        const myKeySignature = this.#identity.publicDHIdentityKey.signature.toString("base64");
        const yourKeySignature = otherDHIdentityKey.signature.toString("base64");
        const dhRatchetInitializer = await this.#identity.generateSignedKeyPair();
        const myDHRatchetInititalizer = crypto.exposeSignedKey(dhRatchetInitializer);
        const myAlias = getRandomString(4, "hex");
        let yourAlias = getRandomString(4, "hex");
        while (yourAlias === myAlias) {
            yourAlias = getRandomString(4, "hex");
        }
        const profile = { ...profileDetails, username: this.username };
        const initialData: ChatRequestBody = {
            messageId,
            myAlias,
            yourAlias,
            myKeySignature,
            yourKeySignature,
            yourUsername,
            myDHRatchetInititalizer,
            timestamp,
            text,
            profile
         };
         const sessionId = (await crypto.digestToBase64("SHA-256", sharedRoot)).slice(0, 15);
        const initialCiphertext = await this.#identity.deriveSignEncrypt(initialData, sharedRoot, `${sessionId} Message Request`);
        const myPublicSigningIdentityKey = this.#identity.publicIdentityVerifyingKeyBuffer;
        const myPublicDHIdentityKey = this.#identity.publicDHIdentityKey;
        const headerId = getRandomString(15, "base64");
        const request: ChatRequestHeader = {
            addressedTo: yourUsername,
            headerId,
            myVerifyingIdentityKey: myPublicSigningIdentityKey,
            myPublicDHIdentityKey,
            myPublicEphemeralKey,
            yourBundleId: bundleId,
            initialMessage: initialCiphertext };
        const pendingRequest: ViewSentRequest = {
            timestamp,
            sessionId,
            headerId,
            myAlias,
            otherAlias: yourAlias,
            messageId,
            text,
            otherUser: yourUsername };
        const waitingRequest: SentChatRequest = {
            ...pendingRequest,
            myAlias,
            otherAlias: yourAlias,
            recipientVerifyKey: importedVerifyingIdentityKey,
            sharedRoot,
            myPrivateDHRatchetInitializer: dhRatchetInitializer.keyPair.privateKey };

        this.#sentChatRequests.set(sessionId, waitingRequest);
        const data = await this.exportData();
        if (!data) return "Could Not Save";
        return [data, request, pendingRequest];
    }

    async receiveChatRequestResponse(responseHeader: MessageHeader, saveSession: (arg: EncryptedData | null) => Promise<boolean>): Promise<[X3DHRequestsData, { profile: Profile, respondedAt: number }] | "Session Id Mismatch" | "Unverified Next Ratchet Key" | "Receving Ratchet Number Mismatch" | "Failed To Decrypt" | "Message Invalid" | "Could Not Save" | "Response Not According To Protocol" | "No Such Pending Request"> {
        const { sessionId, nextDHRatchetKey } = responseHeader;
        const waitingDetails = this.#sentChatRequests.get(sessionId);
        if (!waitingDetails) {
            return "No Such Pending Request";
        }
        const {
            myAlias,
            otherAlias,
            otherUser,
            recipientVerifyKey,
            sharedRoot,
            myPrivateDHRatchetInitializer: myDHRatchetInitializer } = waitingDetails;
        const importedDHInitializer = await crypto.verifyKey(nextDHRatchetKey, recipientVerifyKey);
        if (!importedDHInitializer) {
            return "Unverified Next Ratchet Key";
        }
        const chattingSession = await ChattingSession.new(this.#identity,
            this.username,
            otherUser,
            myAlias,
            otherAlias,
            recipientVerifyKey,
            sharedRoot,
            this.maxSkip,
            importedDHInitializer,
            myDHRatchetInitializer);
        const [messageBody] = await chattingSession.receiveMessage(responseHeader, saveSession);
        if (typeof messageBody === "string") {
            logError(messageBody);
            return messageBody;
        }
        const { timestamp: respondedAt, profile } = messageBody as (MessageBody & { profile: Profile })
        if (!profile || typeof profile.displayName !== "string" || typeof profile.username !== "string" || typeof profile.profilePicture !== "string" ) {
            logError("Response Not According To Protocol");
            return "Response Not According To Protocol";
        }
        this.#sentChatRequests.delete(sessionId);
        const x3dhRequestsData = await this.exportData();
        if (!x3dhRequestsData) return "Could Not Save";
        return [x3dhRequestsData, { profile, respondedAt }];
    }

    async processReceivedChatRequest(initialMessage: ChatRequestHeader)
    : Promise<[X3DHDataPartial, ViewReceivedRequest] | "Incorrectly Addressed" | "Bundle Not Found" | "Invalid Identity Signature" | "Invalid Ephemeral Signature" | "Failed To Decrypt Message" | "Problem With Decrypted Message" | "Duplicate Chat Request" | "Unknown Error"> {
        try {
            const {
                addressedTo,
                headerId,
                myVerifyingIdentityKey: otherVerifyingIdentityKey,
                myPublicDHIdentityKey: otherPublicDHIdentityKey,
                myPublicEphemeralKey: otherPublicEphemeralKey,
                yourBundleId,
                initialMessage: initMessage } = initialMessage;
            if (addressedTo !== this.username) return "Incorrectly Addressed";
            const bundle = this.#keys.getIssuedBundle(yourBundleId);
            if (!bundle) return "Bundle Not Found";
            const { preKeyVersion, oneTimeKeyIdentifier } = bundle;
            const preKey = this.#keys.getPreKey(preKeyVersion)!;
            const oneTimeKey = this.#keys.getOneTimeKey(oneTimeKeyIdentifier);
            const importedVerifyingIdentityKey = await this.importVerifyingKey(otherVerifyingIdentityKey);
            const importedDHIdentityKey = await crypto.verifyKey(otherPublicDHIdentityKey, importedVerifyingIdentityKey);
            if (!importedDHIdentityKey) return "Invalid Identity Signature";
            const importedEphemeralKey = await crypto.verifyKey(otherPublicEphemeralKey, importedVerifyingIdentityKey);
            if (!importedEphemeralKey) return "Invalid Ephemeral Signature";
            try {
                const dh1 = await crypto.deriveSymmetricBits(preKey, importedDHIdentityKey, 512);
                const dh2 = await this.#identity.deriveSymmetricBits(importedEphemeralKey, 512);
                const dh3 = await crypto.deriveSymmetricBits(preKey, importedEphemeralKey, 512);
                const dh4 = (oneTimeKey !== undefined)
                            ? [await crypto.deriveSymmetricBits(oneTimeKey, importedEphemeralKey, 512)]
                            : [];
                const sharedRoot = Buffer.concat([dh1, dh2, dh3, ...dh4]);
                const sessionId = (await crypto.digestToBase64("SHA-256", sharedRoot)).slice(0, 15);
                const message: ChatRequestBody = await this.#identity.deriveDecryptVerify(initMessage, sharedRoot, `${sessionId} Message Request`, importedVerifyingIdentityKey);
                if (!message) return "Failed To Decrypt Message";
                const { myKeySignature: otherKeySignature,
                    yourKeySignature: myKeySignature,
                    yourUsername: myUsername,
                    myAlias: otherAlias,
                    yourAlias: myAlias,
                    timestamp,
                    messageId,
                    text,
                    profile,
                    myDHRatchetInititalizer: dhRatchetInitializer } = message;
                const importedDHInitializer = await crypto.verifyKey(dhRatchetInitializer, importedVerifyingIdentityKey);
                if ((myKeySignature as string) !== this.#identity.publicDHIdentityKey.signature.toString("base64")
                || (otherKeySignature as string) !== otherPublicDHIdentityKey.signature.toString("base64")
                || !profile.username
                || !importedDHInitializer
                || (myUsername as string) !== this.username) return "Problem With Decrypted Message";
                if ([...this.#receivedChatRequests.values()].some(({ profile: { username }}) => username === profile.username)) return "Duplicate Chat Request";
                const receivedRequest: ReceivedChatRequest = {
                    sessionId,
                    headerId,
                    messageId,
                    myAlias,
                    otherAlias,
                    profile,
                    timestamp,
                    text,
                    importedVerifyingIdentityKey,
                    sharedRoot,
                    importedDHInitializer
                };
                this.#receivedChatRequests.set(sessionId, receivedRequest);
                const x3dhKeysData = await this.#keys.delete(yourBundleId);
                const x3dhRequestsData = await this.exportData();
                if (!x3dhKeysData || !x3dhRequestsData) return "Unknown Error"
                const x3dhData = { ...x3dhKeysData, ...x3dhRequestsData };
                return [x3dhData, _.pick(receivedRequest, "timestamp", "sessionId", "headerId", "myAlias", "otherAlias", "messageId", "otherUser", "text") as ViewReceivedRequest];
            }
            catch (err) {
                logError(`${err}`);
                return "Failed To Decrypt Message";
            }
        }
        catch (err) {
            logError(`${err}`);
            return "Unknown Error";
        }
    }

    async acceptChatRequest(sessionId: string, timestamp: number, profileDetails: Omit<Profile, "username">, saveSession: (arg: EncryptedData | null) => Promise<boolean>)
        : Promise<[X3DHRequestsData, MessageHeader] | "No Such Request" | "Could Not Save"> {
            const receivedRequest = this.#receivedChatRequests.get(sessionId);
            if (!receivedRequest) return "No Such Request";
            const { username } = this;
            const { profile: { username: otherUser }, myAlias, otherAlias, importedDHInitializer, importedVerifyingIdentityKey, sharedRoot } =  receivedRequest;
            const chattingSession = await ChattingSession.new(this.#identity,
                username,
                otherUser,
                myAlias,
                otherAlias,
                importedVerifyingIdentityKey,
                sharedRoot,
                this.maxSkip,
                importedDHInitializer);
            const messageId = `f${getRandomString(14, "hex")}`;
            const profile = { ...profileDetails, username };
            const result = await chattingSession.sendMessage({ messageId, timestamp, profile }, saveSession);
            if (typeof result === "string") return result;
            this.#receivedChatRequests.delete(sessionId);
            const x3dhRequestsData = await this.exportData();
            if (!x3dhRequestsData) return "Could Not Save"
            return [x3dhRequestsData, result];
    }

    async rejectReceivedRequest(sessionId: string): Promise<X3DHRequestsData | null> {
        this.#receivedChatRequests.delete(sessionId);
        return await this.exportData();
    }

    async deleteSentRequest(sessionId: string): Promise<X3DHRequestsData | null> {
        this.#sentChatRequests.delete(sessionId);
        return await this.exportData();
    }

    private async importVerifyingKey(verifyingKey: Buffer) {
        return await crypto.importKey(verifyingKey, "ECDSA", "public", true);
    }
}

export class X3DHManager {
    readonly #x3dhIdentity: X3DHIdentity;
    readonly #x3dhKeys: X3DHKeys;
    readonly #x3dhRequests: X3DHRequests;
    readonly publicIdentity: PublicIdentity;

    constructor(x3dhIdentity: X3DHIdentity, x3dhKeys: X3DHKeys, x3dhRequests: X3DHRequests) {
        this.#x3dhIdentity = x3dhIdentity;
        this.#x3dhKeys = x3dhKeys;
        this.#x3dhRequests = x3dhRequests;
        this.publicIdentity = x3dhIdentity.publicIdentity;
    }

    static async new(username: string, encryptionBaseVector: CryptoKey): Promise<[X3DHManager, { firstKeys: NewUserData["firstKeys"], x3dhIdentity: EncryptedData, x3dhData: X3DHData }]> {
        const [identity, x3dhIdentity] = (await X3DHIdentity.new(username, encryptionBaseVector))!;
        const [firstKeys, keys, x3dhKeysData] = (await X3DHKeys.new(identity.interface))!;
        const [requests, x3dhRequestsData] = (await X3DHRequests.new(identity.interface, keys.interface))!;
        const manager = new X3DHManager(identity, keys, requests);
        return [manager, { firstKeys, x3dhIdentity, x3dhData: { ...x3dhKeysData, ...x3dhRequestsData } }]
    }

    static async import(username: string, x3dhIdentity: EncryptedData, x3dhData: X3DHData, encryptionBaseVector: CryptoKey): Promise<X3DHManager> {
        const { x3dhKeys, x3dhRequests } = x3dhData;
        const identity = await X3DHIdentity.import(username, x3dhIdentity, encryptionBaseVector);
        if (!identity) throw new Error("Failed To Import Identity");
        const { interface: identityInterface } = identity;
        const keys = await X3DHKeys.import(x3dhKeys, identityInterface);
        if (!keys) throw new Error("Failed To Import Keys");
        const { interface: keysInterface } = keys;
        const requests = await X3DHRequests.import(x3dhRequests, identityInterface, keysInterface);
        if (!requests) throw new Error("Failed To Import Requests");
        return new X3DHManager(identity, keys, requests);
    }

    get allPendingSentRequests(): ViewSentRequest[] {
        return this.#x3dhRequests.allPendingSentRequests;
    }

    get allPendingReceivedRequests(): ViewReceivedRequest[] {
        return this.#x3dhRequests.allPendingReceivedRequests;
    }

    getPendingSentRequest(sessionId: string): ViewSentRequest {
        return this.#x3dhRequests.getPendingSentRequest(sessionId);
    }

    getPendingReceivedRequest(sessionId: string): ViewReceivedRequest {
        return this.#x3dhRequests.getPendingReceivedRequest(sessionId);
    }

    async generateChatRequest(keyBundle: KeyBundle, messageId: string, text: string, timestamp: number, profileDetails: Omit<Profile, "username">) : Promise<[X3DHRequestsData, ChatRequestHeader, ViewSentRequest] | "Invalid Identity Signature" | "Invalid PreKey Signature" | "Invalid OneTimeKey Signature" | "Could Not Save"> {
        return await this.#x3dhRequests.generateChatRequest(keyBundle, messageId, text, timestamp, profileDetails);
    }

    async receiveChatRequestResponse(responseHeader: MessageHeader, saveSession: (arg: EncryptedData | null) => Promise<boolean>): Promise<[X3DHRequestsData, { profile: Profile, respondedAt: number }] | "Session Id Mismatch" | "Unverified Next Ratchet Key" | "Receving Ratchet Number Mismatch" | "Failed To Decrypt" | "Message Invalid" | "Could Not Save" | "Response Not According To Protocol" | "No Such Pending Request"> {
        return await this.#x3dhRequests.receiveChatRequestResponse(responseHeader, saveSession);
    }

    async processReceivedChatRequest(initialMessage: ChatRequestHeader)
    : Promise<[X3DHDataPartial, ViewReceivedRequest] | "Incorrectly Addressed" | "Bundle Not Found" | "Invalid Identity Signature" | "Invalid Ephemeral Signature" | "Failed To Decrypt Message" | "Problem With Decrypted Message" | "Duplicate Chat Request" | "Unknown Error"> {
        return await this.#x3dhRequests.processReceivedChatRequest(initialMessage);
    }

    async acceptChatRequest(sessionId: string, timestamp: number, profileDetails: Omit<Profile, "username">, saveSession: (arg: EncryptedData | null) => Promise<boolean>)
        : Promise<[X3DHRequestsData, MessageHeader] | "No Such Request" | "Could Not Save"> {
            return await this.#x3dhRequests.acceptChatRequest(sessionId, timestamp, profileDetails, saveSession);
    }

    async rejectReceivedRequest(sessionId: string): Promise<X3DHRequestsData | null> {
        return await this.#x3dhRequests.rejectReceivedRequest(sessionId);
    }

    async deleteSentRequest(sessionId: string): Promise<X3DHRequestsData | null> {
        return await this.#x3dhRequests.deleteSentRequest(sessionId);
    }

    async issueOneTimeKeys(n: number): Promise<IssueOneTimeKeysResponse | null> {
        return await this.#x3dhKeys.issueOneTimeKeys(n);
    }

    async replacePreKey(): Promise<ReplacePreKeyResponse | null> {
        return await this.#x3dhKeys.replacePreKey();
    }

    async registerBundle(keyBundleId: KeyBundleId): Promise<X3DHKeysData | null> {
        return await this.#x3dhKeys.registerBundle(keyBundleId);
    }

    async unpackServerMemo<T extends any>(serverMemo: ServerMemo, serverVerifyingKey: CryptoKey): Promise<{ memoId: string, memoData: T } | null> {
        try {
            const { memoId, encryptionPublicKey, memoData } = serverMemo;
            const importedKey = await crypto.importKey(encryptionPublicKey, "ECDH", "public", false);
            const sharedBits = await this.#x3dhIdentity.deriveSymmetricBits(importedKey, 512);
            const data = await this.#x3dhIdentity.deriveDecryptVerify(memoData, sharedBits, `ServerMemo for ${this.#x3dhIdentity.username}: ${memoId}`, serverVerifyingKey) as T;
            if (!memoData) return null;
            return { memoId, memoData: data };
        }
        catch (err) {
            logError(err);
            return null;
        }
    }

    async importChattingSession(encryptedSession: EncryptedData) {
        return await this.#x3dhIdentity.importChattingSession(encryptedSession);
    }

    async createSessionCrypto(clientReference: string, sharedKeyBits: CryptoKey, sessionVerifyingKey: Buffer): Promise<SessionCrypto> {
        return await this.#x3dhIdentity.createSessionCrypto(clientReference, sharedKeyBits, sessionVerifyingKey);
    }

    async deriveSignEncrypt<T extends any>(initialData: T, sharedRoot: CryptoKey | Buffer, purpose: string): Promise<SignedEncryptedData> {
        return await this.#x3dhIdentity.deriveSignEncrypt(initialData, sharedRoot, purpose);
    }

    async deriveDecryptVerify<T extends any>(encryptedData: SignedEncryptedData, sharedRoot: CryptoKey | Buffer, purpose: string, otherVerifyingKey?: CryptoKey): Promise<T> {
        return await this.#x3dhIdentity.deriveDecryptVerify(encryptedData, sharedRoot, purpose, otherVerifyingKey);
    }
}

export class ChattingSession {
    readonly sessionId: string;
    readonly myAlias: string;
    readonly otherAlias: string;
    readonly createdAt: number;
    readonly me: string;
    readonly otherUser: string;
    readonly #maxSkip: number;
    readonly #identity: X3DHIdentityInterface;
    readonly #otherVerifyKey: CryptoKey;
    #currentRootKey: Buffer;
    #currentDHRatchetKey: CryptoKey | undefined;
    #currentDHPublishKey: ExposedSignedPublicKey | undefined;
    #currentSendingChainKey: Buffer | undefined;
    #currentReceivingChainKey: Buffer | undefined;
    #sendingRatchetNumber: number | undefined;
    #receivingRatchetNumber: number | undefined;
    #sendingChainNumber = 0;
    #receivingChainNumber = 0;
    #previousSendingChainNumber = 0;
    #skippedKeys = new Map<[number, number], Buffer>();
    private queue = new Queue(1, 10);
    private lastActivityTimestamp: number;

    private constructor(
        sessionId: string,
        identity: X3DHIdentityInterface,
        createdAt: number,
        lastActivity: number,
        sender: string,
        recipient: string,
        senderAlias: string,
        recipientAlias: string,
        recipientVerify: CryptoKey,
        currentRootKey: Buffer,
        maxSkip: number) {
            this.sessionId = sessionId;
            this.createdAt = createdAt;
            this.#identity = identity;
            this.me = sender;
            this.otherUser = recipient;
            this.myAlias = senderAlias;
            this.otherAlias = recipientAlias;
            this.#otherVerifyKey = recipientVerify;
            this.#currentRootKey = currentRootKey;
            this.#maxSkip = maxSkip;
            this.lastActivityTimestamp = lastActivity;
    }

    get lastActivity() {
        return this.lastActivityTimestamp;
    }

    static async new(identity: X3DHIdentityInterface,
        sender: string,
        recipient: string,
        senderAlias: string,
        recipientAlias: string,
        recipientVerify: CryptoKey,
        sharedRoot: Buffer,
        maxSkip: number,
        dhRatchetOtherPublic: CryptoKey,
        dhRatcherMyPrivate: CryptoKey | null = null): Promise<ChattingSession> {
            const now = Date.now();
            const amInitiator = !!dhRatcherMyPrivate;
            const sessionId = (await crypto.digestToBase64("SHA-256", sharedRoot)).slice(0, 15);
            const chattingSession = new ChattingSession(sessionId, identity, now, now, sender, recipient, senderAlias, recipientAlias, recipientVerify, sharedRoot, maxSkip);
            chattingSession.#receivingRatchetNumber = amInitiator ? -1 : 0;
            if (amInitiator) {
                chattingSession.#currentDHRatchetKey = dhRatcherMyPrivate;
                await chattingSession.advanceFirstHalfDHRatchet(dhRatchetOtherPublic);
            }
            chattingSession.#sendingRatchetNumber = amInitiator ? 0 : -1;
            await chattingSession.advanceSecondHalfDHRatchet(dhRatchetOtherPublic);
            return chattingSession;
    }

    static async import(encryptedSession: EncryptedData, identity: X3DHIdentityInterface) : Promise<ChattingSession | null> {
        const { username } = identity;
        const decryptedSession: ExportedChattingSession = await identity.x3dhDecrypt(encryptedSession, `Export|Import ${username} Chatting Session`);
        if (!decryptedSession) {
            return null;
        }
        try {
            const {
                sessionId,
                createdAt,
                lastActivity,
                sender,
                recipient,
                senderAlias,
                recipientAlias,
                maxSkip,
                recipientVerifyKey,
                currentRootKey,
                currentDHRatchetKey,
                currentDHPublishKey,
                currentSendingChainKey,
                currentReceivingChainKey,
                sendingRatchetNumber,
                receivingRatchetNumber,
                sendingChainNumber,
                receivingChainNumber,
                previousSendingChainNumber }: ExportedChattingSession = decryptedSession;
            const unwrappedRatchetKey = await identity.userUnwrap(currentDHRatchetKey, "ECDH", `${sessionId} DH Ratchet Key`, true);
            const importedVerifyKey = await crypto.importKey(recipientVerifyKey, "ECDSA", "public", true);
            const exportedSession = new ChattingSession(sessionId, identity, createdAt, lastActivity, sender, recipient, senderAlias, recipientAlias, importedVerifyKey, currentRootKey, maxSkip);
            exportedSession.#currentDHRatchetKey = unwrappedRatchetKey;
            exportedSession.#currentDHPublishKey = currentDHPublishKey;
            exportedSession.#currentSendingChainKey = currentSendingChainKey;
            exportedSession.#currentReceivingChainKey = currentReceivingChainKey;
            exportedSession.#sendingRatchetNumber = sendingRatchetNumber;
            exportedSession.#receivingRatchetNumber = receivingRatchetNumber;
            exportedSession.#sendingChainNumber = sendingChainNumber;
            exportedSession.#receivingChainNumber = receivingChainNumber;
            exportedSession.#previousSendingChainNumber = previousSendingChainNumber;
            return exportedSession;
        }
        catch(err) {
            logError(`${err}`);
            return null;
        }
    }

    private async export(): Promise<EncryptedData | null> {
        try {
            const sessionId = this.sessionId;
            const createdAt = this.createdAt;
            const lastActivity = this.lastActivityTimestamp;
            const sender = this.me;
            const recipient = this.otherUser;
            const senderAlias = this.myAlias;
            const recipientAlias = this.otherAlias;
            const maxSkip = this.#maxSkip;
            const recipientVerifyKey = await crypto.exportKey(this.#otherVerifyKey);
            const currentRootKey = this.#currentRootKey;
            const currentDHRatchetKey = await this.#identity.userWrap(this.#currentDHRatchetKey!, `${sessionId} DH Ratchet Key`);
            const currentDHPublishKey = this.#currentDHPublishKey!;
            const currentSendingChainKey = this.#currentSendingChainKey!;
            const currentReceivingChainKey = this.#currentReceivingChainKey!;
            const sendingRatchetNumber = this.#sendingRatchetNumber!;
            const receivingRatchetNumber = this.#receivingRatchetNumber!;
            const sendingChainNumber = this.#sendingChainNumber;
            const receivingChainNumber = this.#receivingChainNumber;
            const previousSendingChainNumber = this.#previousSendingChainNumber;
            const exportedSession: ExportedChattingSession = {
                sessionId,
                createdAt,
                lastActivity,
                sender,
                recipient,
                senderAlias,
                recipientAlias,
                maxSkip,
                recipientVerifyKey,
                currentRootKey: currentRootKey,
                currentDHRatchetKey,
                currentDHPublishKey,
                currentSendingChainKey,
                currentReceivingChainKey,
                sendingRatchetNumber,
                receivingRatchetNumber,
                sendingChainNumber,
                receivingChainNumber,
                previousSendingChainNumber };
            return await this.#identity.x3dhEncrypt(exportedSession, `Export|Import ${sender} Chatting Session`);
        }
        catch(err) {
            logError(err);
            return null;
        }
    }

    private async advanceFirstHalfDHRatchet(nextDHPublicKey: CryptoKey) {
        const dhReceivingChainInput = await crypto.deriveSymmetricBits(this.#currentDHRatchetKey!, nextDHPublicKey, 256);
        const { nextRootKey, output: recvInput } = await this.rootChainKDFDerive(dhReceivingChainInput);
        this.#currentRootKey = nextRootKey;
        this.#currentReceivingChainKey = recvInput;
        this.#receivingRatchetNumber! += 2;
        this.#receivingChainNumber = 0;
    }

    private async advanceSecondHalfDHRatchet(nextDHPublicKey: CryptoKey) {
        const nextRatchetKeyPair = await this.#identity.generateSignedKeyPair();
        this.#currentDHRatchetKey = nextRatchetKeyPair.keyPair.privateKey;
        this.#currentDHPublishKey = crypto.exposeSignedKey(nextRatchetKeyPair);
        const dhSendingChainInput = await crypto.deriveSymmetricBits(this.#currentDHRatchetKey, nextDHPublicKey, 256);
        const { nextRootKey, output: sendInput } = await this.rootChainKDFDerive(dhSendingChainInput);
        this.#currentRootKey = nextRootKey;
        this.#currentSendingChainKey = sendInput;
        this.#sendingRatchetNumber! += 2;
        this.#previousSendingChainNumber = this.#sendingChainNumber;
        this.#sendingChainNumber = 0;
    }

    private async advanceDHRatchet(nextDHPublicKey: CryptoKey) {
        await this.advanceFirstHalfDHRatchet(nextDHPublicKey);
        await this.advanceSecondHalfDHRatchet(nextDHPublicKey);
    }

    private async ratchetToCurrentReceived(nextDHPublicKey: CryptoKey,
        sendingRatchetNumber: number,
        sendingChainNumber: number,
        previousChainNumber: number): Promise<Buffer | null> {
            let output: Buffer | null = null;
            if ((sendingRatchetNumber - this.#receivingRatchetNumber!) === 2) {
                while (this.#receivingChainNumber < previousChainNumber) {
                    output = await this.advanceSymmetricRatchet("Receiving");
                    if (this.#receivingChainNumber < sendingChainNumber) {
                        this.#skippedKeys.set([sendingRatchetNumber, this.#receivingChainNumber], output);
                    }
                }
                await this.advanceDHRatchet(nextDHPublicKey);
            }
            if ((sendingRatchetNumber - this.#receivingRatchetNumber!) === 0) {
                while (this.#receivingChainNumber < sendingChainNumber) {
                    output = await this.advanceSymmetricRatchet("Receiving");
                    if (this.#receivingChainNumber < sendingChainNumber) {
                        this.#skippedKeys.set([sendingRatchetNumber, this.#receivingChainNumber], output);
                    }
                }
            }
            if (!output) {
                const missedId: [number, number] = [sendingRatchetNumber, sendingChainNumber];
                const missed = this.#skippedKeys.get(missedId);
                if (!!missed) {
                    this.#skippedKeys.delete(missedId);
                    output = missed;
                }
            }
            return output;
    }

    private async advanceSymmetricRatchet(chain: "Sending" | "Receiving"): Promise<Buffer> {
        const chainKey = chain === "Sending" ? this.#currentSendingChainKey! : this.#currentReceivingChainKey!;
        const { nextChainKey, messageKeyBits } = await this.messageChainKDFDerive(chainKey);
        if (chain === "Sending") {
            this.#currentSendingChainKey = nextChainKey;
            this.#sendingChainNumber += 1;
        }
        else {
            this.#currentReceivingChainKey = nextChainKey;
            this.#receivingChainNumber += 1;
        }
        return messageKeyBits;
    }

    private async rootChainKDFDerive(dhInput: Buffer): Promise<{ nextRootKey: Buffer, output: Buffer }> {
        const kdfOutput = await crypto.deriveHKDF(dhInput, this.#currentRootKey, "Root Symmetric Ratchet", 512);
        const nextRootKey = crypto.subarray(kdfOutput, 0, 32);
        const output = crypto.subarray(kdfOutput, 32, 64);
        return { nextRootKey, output };
    }

    private async messageChainKDFDerive(chainKey: Buffer): Promise<{ nextChainKey: Buffer, messageKeyBits: Buffer }> {
        const chainDeriveKey = await crypto.deriveHKDF(chainKey, nullSalt(64), "Messaging Chain Symmetric Ratchet", 512);
        const nextDeriveBits = crypto.subarray(chainDeriveKey, 0, 32);
        const messageDeriveBits = crypto.subarray(chainDeriveKey, 32, 64);
        const nextChainKey = await crypto.deriveHKDF(nextDeriveBits, nullSalt(32), "Next Chain Key");
        const messageKeyBits = await crypto.deriveHKDF(messageDeriveBits, nullSalt(32), "Message Key Bits");
        return { nextChainKey, messageKeyBits }
    }

    private async advanceReversibly(advance: () => Promise<Buffer | null>, saveSession: (arg: EncryptedData | null) => Promise<boolean>): Promise<Buffer| null | undefined> {
        const token = Symbol();
        await this.queue.wait(token);
        const currentRootKey = this.#currentRootKey;
        const currentDHRatchetKey = this.#currentDHRatchetKey;
        const currentDHPublishKey = this.#currentDHPublishKey;
        const currentSendingChainKey = this.#currentSendingChainKey;
        const currentReceivingChainKey = this.#currentReceivingChainKey;
        const sendingRatchetNumber = this.#sendingRatchetNumber;
        const receivingRatchetNumber = this.#receivingRatchetNumber;
        const sendingChainNumber = this.#sendingChainNumber;
        const receivingChainNumber = this.#receivingChainNumber;
        const previousSendingChainNumber = this.#previousSendingChainNumber;
        const skippedKeys = this.#skippedKeys;
        const lastActivityTimestamp = this.lastActivityTimestamp;
        this.lastActivityTimestamp = Date.now();
        const output = await advance();
        if (!output || !(await saveSession(await this.export()))) {
            this.#currentRootKey = currentRootKey;
            this.#currentDHRatchetKey = currentDHRatchetKey;
            this.#currentDHPublishKey = currentDHPublishKey;
            this.#currentSendingChainKey = currentSendingChainKey;
            this.#currentReceivingChainKey = currentReceivingChainKey;
            this.#sendingRatchetNumber = sendingRatchetNumber;
            this.#receivingRatchetNumber = receivingRatchetNumber;
            this.#sendingChainNumber = sendingChainNumber;
            this.#receivingChainNumber = receivingChainNumber;
            this.#previousSendingChainNumber = previousSendingChainNumber;
            this.#skippedKeys = skippedKeys;
            this.lastActivityTimestamp = lastActivityTimestamp;
            return output ? null : undefined;
        }
        this.queue.end(token);
        return output;
    }

    async sendMessage(sendingMessage: SendingMessage, saveSession: (arg: EncryptedData | null) => Promise<boolean>): Promise<MessageHeader | "Could Not Save"> {
        const messageKeyBits = await this.advanceReversibly(() => this.advanceSymmetricRatchet("Sending"), saveSession);
        if (!messageKeyBits) return "Could Not Save";
        const sender = this.me;
        const fromAlias = this.myAlias;
        const toAlias = this.otherAlias;
        const sessionId = this.sessionId;
        const receivingRatchetNumber = this.#receivingRatchetNumber! + 2;
        const sendingRatchetNumber = this.#sendingRatchetNumber!;
        const sendingChainNumber = this.#sendingChainNumber;
        const previousChainNumber = this.#previousSendingChainNumber;
        const nextDHRatchetKey = this.#currentDHPublishKey!;
        const message: ReceivingMessage = { sender, ...sendingMessage };
        const headerId = getRandomString(15, "base64");
        const messageBody = await this.#identity.deriveSignEncrypt(message, messageKeyBits, `${headerId} Message Send|Receive`);
        const messageHeader: MessageHeader = {
            fromAlias,
            toAlias,
            sessionId,
            headerId,
            receivingRatchetNumber,
            sendingRatchetNumber,
            sendingChainNumber,
            previousChainNumber,
            nextDHRatchetKey,
            messageBody
        };
        return messageHeader;
    }

    async receiveMessage(messageHeader: MessageHeader, saveSession: (arg: EncryptedData | null) => Promise<boolean>): Promise<[ReceivingMessage | "Session Id Mismatch" | "Unverified Next Ratchet Key" | "Receving Ratchet Number Mismatch" | "Failed To Decrypt" | "Message Invalid" | "Could Not Save", string]> {
        const {
            fromAlias,
            toAlias,
            sessionId,
            headerId,
            sendingRatchetNumber,
            sendingChainNumber,
            previousChainNumber,
            nextDHRatchetKey,
            messageBody } = messageHeader;
        const signature = await this.signReceipt(headerId, true);
        if (sessionId !== this.sessionId || toAlias !== this.myAlias || fromAlias !== this.otherAlias ) return ["Session Id Mismatch", signature];
        const nextDHPublicKey = await crypto.verifyKey(nextDHRatchetKey, this.#otherVerifyKey);
        if (!nextDHPublicKey) return ["Unverified Next Ratchet Key", signature];
        const messageKeyBits = await this.advanceReversibly(() => this.ratchetToCurrentReceived(nextDHPublicKey, sendingRatchetNumber, sendingChainNumber, previousChainNumber), saveSession);
        if (!messageKeyBits) return [messageKeyBits === undefined ? "Receving Ratchet Number Mismatch" : "Could Not Save", signature]
        const message: ReceivingMessage = await this.#identity.deriveDecryptVerify(messageBody, messageKeyBits, `${headerId} Message Send|Receive`, this.#otherVerifyKey);
        if (!message) return ["Failed To Decrypt", signature]
        if (message.sender !== this.otherUser) return ["Message Invalid", signature]
        return [message, await this.signReceipt(headerId, false)];
    }

    async verifyReceipt(headerId: string, signature: string, bounced: boolean) {
        if (!headerId) return false;
        return await crypto.verify(fromBase64(headerId + bounced ? "0" : "1"), fromBase64(signature), this.#otherVerifyKey);
    }

    private async signReceipt(headerId: string, bounced: boolean) {
        return (await this.#identity.sign(fromBase64(headerId + bounced ? "0" : "1"))).toString("base64");
    }
}