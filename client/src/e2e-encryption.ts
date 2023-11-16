import _, { identity } from "lodash";
import * as crypto from "../../shared/cryptoOperator";
import { serialize, deserialize } from "../../shared/cryptoOperator";
import { ExposedSignedPublicKey, SignedKeyPair, ExportedSignedKeyPair, ExportedSigningKeyPair, KeyBundle, MessageHeader, ChatRequestHeader, UserEncryptedData, Profile, StoredMessage, PublicIdentity, KeyBundleId, IssueOneTimeKeysResponse, ReplacePreKeyResponse, ServerMemo } from "../../shared/commonTypes";
import { Queue } from "async-await-queue";
import { fromBase64, logError, randomFunctions } from "../../shared/commonFunctions";
import { SessionCrypto } from "../../shared/sessionCrypto";

const { getRandomVector, getRandomString } = randomFunctions();

const nullSalt = (length: number) => Buffer.alloc(length);

type MessageBody = Readonly<{
    sender: string;
    timestamp: number;
    messageId: string;
}>

type MessageContent = Readonly<{
    replyingTo?: string;
    text: string;
}>;

type MessageEvent = Readonly<{
    reportingAbout: string;
    event: "delivered" | "seen";
} | {
    event: "typing" | "stopped-typing";
}>;

export type SendingMessage = Omit<MessageBody, "sender"> & (MessageContent | MessageEvent);

type ReceivingMessage = MessageBody & (MessageContent | MessageEvent);

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
}>

type ExportedX3DHManager = Readonly<{
    username: string;
    currentPreKeyVersion: number;
    preKeys: Map<number, UserEncryptedData>;
    oneTimeKeys: Map<string, UserEncryptedData>;
    issuedBundles: UserEncryptedData;
    sentChatRequests: UserEncryptedData;
    receivedChatRequests: UserEncryptedData;
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
    currentDHRatchetKey: UserEncryptedData;
    currentDHPublishKey: ExposedSignedPublicKey;
    currentSendingChainKey: Buffer;
    currentReceivingChainKey: Buffer;
    sendingRatchetNumber: number;
    receivingRatchetNumber: number;
    sendingChainNumber: number;
    receivingChainNumber: number;
    previousSendingChainNumber: number;
}>;

export class X3DHIdentity {
    readonly username: string;
    readonly publicIdentityVerifyingKey: Buffer;
    readonly #identitySigningKeyPair: CryptoKeyPair;
    readonly #identityDHKeyPair: SignedKeyPair;

    public get publicDHIdentityKey(): ExposedSignedPublicKey {
        return crypto.exposeSignedKey(this.#identityDHKeyPair);
    }

    public get publicIdentity(): PublicIdentity {
        return _.pick(this, ["publicIdentityVerifyingKey", "publicDHIdentityKey"]);
    }

    private constructor(username: string,
        identitySigningKeyPair: CryptoKeyPair,
        publicIdentityVerifyingKey: Buffer,
        identityDHKeyPair: SignedKeyPair) {
            this.username = username;
            this.publicIdentityVerifyingKey = publicIdentityVerifyingKey;
            this.#identitySigningKeyPair = identitySigningKeyPair;
            this.#identityDHKeyPair = identityDHKeyPair;
    }

    private async export(encryptionBaseVector: CryptoKey): Promise<UserEncryptedData> {
        const { username } = this;
        const identitySigningKeyPair = await crypto.exportSigningKeyPair(this.#identitySigningKeyPair, encryptionBaseVector, `User ${username} X3DH Identity`);
        const identityDHKeyPair = await crypto.exportSignedKeyPair(this.#identityDHKeyPair, encryptionBaseVector, `User ${username} X3DH Identity DH`);
        const exportedUser: ExportedX3DHIdentity = {
            username,
            identitySigningKeyPair,
            identityDHKeyPair };
        return await crypto.deriveEncrypt(exportedUser, encryptionBaseVector, "Export|Import X3DH Identity");
    }

    static async import(encryptedIdentity: UserEncryptedData, encryptionBaseVector: CryptoKey) : Promise<X3DHIdentity> {
        try {
            const importedUser: ExportedX3DHIdentity = await crypto.deriveDecrypt(encryptedIdentity, encryptionBaseVector, "Export|Import X3DH Identity");
            if (!importedUser) {
                return null;
            }
            const {
                username,
                identitySigningKeyPair: exportedidentityKeyPair,
                identityDHKeyPair: exportedIdentityDHKeyPair } = importedUser;
            const identitySigningKeyPair = await crypto.importSigningKeyPair(exportedidentityKeyPair, encryptionBaseVector, `User ${username} X3DH Identity`);
            const identityDHKeyPair = await crypto.importSignedKeyPair(exportedIdentityDHKeyPair, encryptionBaseVector, `User ${username} X3DH Identity DH`);
            const identity = new X3DHIdentity(username, identitySigningKeyPair, await crypto.exportKey(identitySigningKeyPair.publicKey), identityDHKeyPair);
            return identity;
        }
        catch(err) {
            logError(`${err}`);
            return null;
        }
    }

    static async new(username: string,
        encryptionBaseVector: CryptoKey): Promise<[X3DHIdentity, UserEncryptedData]> {
            const identitySigningKeyPair = await crypto.generateKeyPair("ECDSA");
            const identityDHKeyPair = await crypto.generateSignedKeyPair(identitySigningKeyPair.privateKey);
            const identity = new X3DHIdentity(username, identitySigningKeyPair, await crypto.exportKey(identitySigningKeyPair.publicKey), identityDHKeyPair);
            const exported = await identity.export(encryptionBaseVector);
            return [identity, exported];
    }

    public async generateSignedKeyPair(): Promise<SignedKeyPair> {
        return await crypto.generateSignedKeyPair(this.#identitySigningKeyPair.privateKey);
    }

    public async deriveSignEncrypt<T extends any>(sharedRoot: CryptoKey | Buffer, initialData: T, salt: Buffer, purpose: string) {
        return await crypto.deriveSignEncrypt(sharedRoot, initialData, salt, purpose, this.#identitySigningKeyPair.privateKey);
    }

    public async deriveSymmetricBits(publicKey: CryptoKey, size: 256 | 512) {
        return await crypto.deriveSymmetricBits(this.#identityDHKeyPair.keyPair.privateKey, publicKey, size);
    };

    public async sign(data: Buffer) {
        return await crypto.sign(data, this.#identitySigningKeyPair.privateKey);
    }

    public async createSession(clientReference: string, sharedKeyBits: CryptoKey, sessionVerifyingKey: Buffer) {
        return new SessionCrypto(clientReference, sharedKeyBits, this.#identitySigningKeyPair.privateKey, await crypto.importKey(sessionVerifyingKey, "ECDSA", "public", false));
    }
}

export class X3DHManager {
    readonly #identity: X3DHIdentity;
    readonly #encryptionBaseVector: CryptoKey;
    private readonly maxSkip: number;
    #currentPreKeyVersion: number;
    #preKeys = new Map<number, CryptoKey>();
    #oneTimeKeys = new Map<string, CryptoKey>();
    #sentChatRequests = new Map<string, SentChatRequest>();
    #receivedChatRequests = new Map<string, ReceivedChatRequest>();
    #issuedBundles = new Map<string, KeyBundleId>();

    public get username() { 
        return this.#identity.username; 
    }

    public get allPendingSentRequests(): ViewSentRequest[] {
        return Array.from(this.#sentChatRequests.values()).map((req) => _.pick(req, "messageId", "timestamp", "otherUser", "text", "sessionId", "myAlias", "otherAlias", "headerId"));
    }

    public get allPendingReceivedRequests(): ViewReceivedRequest[] {
        return Array.from(this.#receivedChatRequests.values()).map((req) => _.pick(req, "messageId", "timestamp", "otherUser", "text", "sessionId", "myAlias", "otherAlias", "headerId", "profile") as ViewReceivedRequest);
    }

    public get publicIdentity(): PublicIdentity {
        return this.#identity.publicIdentity;
    }

    private constructor(identity: X3DHIdentity, encryptionBaseVector: CryptoKey, currentPreKeyVersion: number, maxSkip = 20) {
        this.#identity = identity;
        this.#encryptionBaseVector = encryptionBaseVector;
        this.#currentPreKeyVersion = currentPreKeyVersion;
        this.maxSkip = maxSkip;
    }

    async export(): Promise<UserEncryptedData> {
        const username = this.username;
        const currentPreKeyVersion = this.#currentPreKeyVersion;
        const preKeys = new Map<number, UserEncryptedData>();
        for (const [ver, key] of this.#preKeys.entries()) {
            preKeys.set(ver, await crypto.deriveWrap(this.#encryptionBaseVector, key, `${username} X3DH Manager PreKey ${ver}`));
        }
        const oneTimeKeys = new Map<string, UserEncryptedData>();
        for (const [id, key] of this.#oneTimeKeys.entries()) {
            oneTimeKeys.set(id, await crypto.deriveWrap(this.#encryptionBaseVector, key, `${username} X3DH User OneTimeKey ${id}`));
        }
        const issuedBundles = await crypto.deriveEncrypt(this.#issuedBundles, this.#encryptionBaseVector, `${username} X3DH Manager Issued Bundles`);
        const exportedSentRequests = new Map<string, ExportedSentChatRequest>();
        for (const [sessionId, { myPrivateDHRatchetInitializer, recipientVerifyKey, ...rest }] of this.#sentChatRequests) {
            exportedSentRequests.set(sessionId, {
                recipientVerifyKey: await crypto.exportKey(recipientVerifyKey),
                myPrivateDHRatchetInitializer: await crypto.exportKey(myPrivateDHRatchetInitializer),
                ...rest
            });
        }
        const sentChatRequests = await crypto.deriveEncrypt(exportedSentRequests, this.#encryptionBaseVector, `${username} X3DH Manager Sent Chat Requests`);
        const exportedReceivedRequests = new Map<string, ExportedReceivedChatRequest>();
        for (const [sessionId, { importedDHInitializer, importedVerifyingIdentityKey, ...rest }] of this.#receivedChatRequests) {
            exportedReceivedRequests.set(sessionId, {
                importedVerifyingIdentityKey: await crypto.exportKey(importedVerifyingIdentityKey),
                importedDHInitializer: await crypto.exportKey(importedDHInitializer),
                ...rest
            });
        }
        const receivedChatRequests = await crypto.deriveEncrypt(exportedReceivedRequests, this.#encryptionBaseVector, `${username} X3DH Manager Received Chat Requests`);
        const exportedUser: ExportedX3DHManager = {
            username,
            currentPreKeyVersion,
            preKeys,
            oneTimeKeys,
            issuedBundles,
            sentChatRequests,
            receivedChatRequests
        };
        return await crypto.deriveEncrypt(exportedUser, this.#encryptionBaseVector, "Export|Import X3DH User");
    }

    static async import(encryptedManager: UserEncryptedData, encryptedIdentity: UserEncryptedData, encryptionBaseVector: CryptoKey) : Promise<X3DHManager> {
        try {
            const importedUser: ExportedX3DHManager = await crypto.deriveDecrypt(encryptedManager, encryptionBaseVector, "Export|Import X3DH User");
            if (!importedUser) {
                return null;
            }
            const identity = await X3DHIdentity.import(encryptedIdentity, encryptionBaseVector);
            const {
                username,
                currentPreKeyVersion,
                preKeys, 
                oneTimeKeys, 
                issuedBundles: encryptedIssuedBundles, 
                sentChatRequests: encryptedSentRequests,
                receivedChatRequests: encryptedReceivedRequests } = importedUser;
            const manager = new X3DHManager(identity, encryptionBaseVector, currentPreKeyVersion);
            for (const [ver, wrappedKey] of preKeys.entries()) {
                manager.#preKeys.set(ver, await crypto.deriveUnwrap(encryptionBaseVector, wrappedKey, "ECDH", `${username} X3DH Manager PreKey ${ver}`, true));
            }
            for (const [id, wrappedKey] of oneTimeKeys.entries()) {
                manager.#oneTimeKeys.set(id, await crypto.deriveUnwrap(encryptionBaseVector, wrappedKey, "ECDH", `${username} X3DH User OneTimeKey ${id}`, true));
            }
            manager.#issuedBundles = await crypto.deriveDecrypt(encryptedIssuedBundles, encryptionBaseVector, `${username} X3DH Manager Issued Bundles`);
            const exportedSentRequests: Map<string, ExportedSentChatRequest> = await crypto.deriveDecrypt(encryptedSentRequests, encryptionBaseVector, `${username} X3DH Manager Sent Chat Requests`);
            for (const [sessionId, { myPrivateDHRatchetInitializer, recipientVerifyKey, ...rest }] of exportedSentRequests) {
                manager.#sentChatRequests.set(sessionId, {
                    recipientVerifyKey: await crypto.importKey(recipientVerifyKey, "ECDSA", "public", true),
                    myPrivateDHRatchetInitializer: await crypto.importKey(myPrivateDHRatchetInitializer, "ECDH", "private", true),
                    ...rest
                });
            }
            const exportedReceivedRequests: Map<string, ExportedReceivedChatRequest> = await crypto.deriveDecrypt(encryptedReceivedRequests, encryptionBaseVector, `${username} X3DH Manager Received Chat Requests`);
            for (const [sessionId, { importedDHInitializer, importedVerifyingIdentityKey, ...rest }] of exportedReceivedRequests) {
                manager.#receivedChatRequests.set(sessionId, {
                    importedVerifyingIdentityKey: await crypto.importKey(importedVerifyingIdentityKey, "ECDSA", "public", true),
                    importedDHInitializer: await crypto.importKey(importedDHInitializer, "ECDH", "public", true),
                    ...rest
                });
            }
            return manager;
        }
        catch(err) {
            logError(`${err}`);
            return null;
        }
    }

    static async new(
        username: string,
        encryptionBaseVector: CryptoKey): Promise<[X3DHManager, UserEncryptedData]> {
            const [identity, encryptedIdentity] = await X3DHIdentity.new(username, encryptionBaseVector);
        const manager = new X3DHManager(identity, encryptionBaseVector, 0);
        return [manager, encryptedIdentity];
    }

    public async deriveSignEncrypt<T extends any>(sharedRoot: CryptoKey | Buffer, initialData: T, salt: Buffer, purpose: string) {
        return await this.#identity.deriveSignEncrypt(sharedRoot, initialData, salt, purpose);
    }

    async createSession(clientReference: string, sharedKeyBits: CryptoKey, sessionVerifyingKey: Buffer) {
        return await this.#identity.createSession(clientReference, sharedKeyBits, sessionVerifyingKey);
    }

    async importChattingSession(encryptedSession: UserEncryptedData) {
        return await ChattingSession.import(encryptedSession, this.#encryptionBaseVector, this.#identity);
    }

    async generateChatRequest(keyBundle: KeyBundle, messageId: string, text: string, timestamp: number, profileDetails: Omit<Profile, "username">) : Promise<[ChatRequestHeader, ViewSentRequest, UserEncryptedData] | "Invalid Identity Signature" | "Invalid PreKey Signature" | "Invalid OneTimeKey Signature"> {
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
        if (!importedDHIdentityKey) return "Invalid PreKey Signature";
        let importedOneTimeKey: CryptoKey;
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
                    ? [await crypto.deriveSymmetricBits(ephemeralKeyPair.keyPair.privateKey, importedOneTimeKey, 512)]
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
        const initialCiphertext = await this.#identity.deriveSignEncrypt(sharedRoot, initialData, nullSalt(48), "Message Request");
        const myPublicSigningIdentityKey = this.#identity.publicIdentityVerifyingKey;
        const myPublicDHIdentityKey = this.#identity.publicDHIdentityKey;
        const sessionId = (await crypto.digestToBase64("SHA-256", sharedRoot)).slice(0, 15);
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
        return [request, pendingRequest, await this.export()];
    }

    async processReceivedChatRequest(initialMessage: ChatRequestHeader)
    : Promise<[UserEncryptedData, ViewReceivedRequest] | "Incorrectly Addressed" | "Bundle Not Found" | "Invalid Identity Signature" | "Invalid Ephemeral Signature" | "Failed To Decrypt Message" | "Problem With Decrypted Message" | "Duplicate Chat Request" | "Unknown Error"> {
        try {
            const {
                addressedTo,
                headerId,
                myVerifyingIdentityKey: otherVerifyingIdentityKey,
                myPublicDHIdentityKey: otherPublicDHIdentityKey,
                myPublicEphemeralKey: otherPublicEphemeralKey,
                yourBundleId,
                initialMessage: initMessage } = initialMessage;
            const { preKeyVersion, oneTimeKeyIdentifier } = this.#issuedBundles.get(yourBundleId); 
            if (addressedTo !== this.username) return "Incorrectly Addressed";
            if (!preKeyVersion) return "Bundle Not Found";
            const preKey = this.#preKeys.get(preKeyVersion);
            const oneTimeKey = this.#oneTimeKeys.get(oneTimeKeyIdentifier);
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
                const message: ChatRequestBody = await crypto.deriveDecryptVerify(sharedRoot, initMessage, nullSalt(48), "Message Request", importedVerifyingIdentityKey);
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
                this.#issuedBundles.delete(yourBundleId);
                this.#oneTimeKeys.delete(oneTimeKeyIdentifier);
                if (preKeyVersion < this.#currentPreKeyVersion && [...this.#issuedBundles.values()].every(({ preKeyVersion: v }) => v !== preKeyVersion)) {
                    this.#preKeys.delete(preKeyVersion);
                }
                const x3dhInfo = await this.export();
                return [x3dhInfo, _.pick(receivedRequest, "timestamp", "sessionId", "headerId", "myAlias", "otherAlias", "messageId", "otherUser", "text") as ViewReceivedRequest];
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

    async acceptChatRequest(sessionId: string, timestamp: number, profileDetails: Omit<Profile, "username">, saveSession: (arg: UserEncryptedData) => Promise<boolean>)
        : Promise<[UserEncryptedData, MessageHeader] | "No Such Request" | "Could Not Save"> {
            const receivedRequest = this.#receivedChatRequests.get(sessionId);
            if (!receivedRequest) return "No Such Request";
            const { profile, myAlias, otherAlias, importedDHInitializer, importedVerifyingIdentityKey, sharedRoot } =  receivedRequest;
            const chattingSession = await ChattingSession.new(this.#encryptionBaseVector,
                this.#identity,
                this.username, 
                profile.username,
                myAlias,
                otherAlias,
                importedVerifyingIdentityKey,
                sharedRoot,
                this.maxSkip,
                importedDHInitializer);
            const text = serialize({ ...profileDetails, username: this.username }).toString("base64");
            const messageId = `f${getRandomString(14, "hex")}`;
            const result = await chattingSession.sendMessage({ messageId, text, timestamp }, saveSession);
            if (typeof result === "string") return result;
            this.#receivedChatRequests.delete(sessionId);
            const x3dhInfo = await this.export();
            return [x3dhInfo, result];            
    }

    async receiveChatRequestResponse(responseHeader: MessageHeader, saveSession: (arg: UserEncryptedData) => Promise<boolean>): Promise<{ profile: Profile, respondedAt: number } | "Session Id Mismatch" | "Unverified Next Ratchet Key" | "Receving Ratchet Number Mismatch" | "Failed To Decrypt" | "Message Invalid" | "Could Not Save" | "Response Not According To Protocol" | "No Such Pending Request"> {
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
        const chattingSession = await ChattingSession.new(this.#encryptionBaseVector, 
            this.#identity,
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
        const { timestamp: respondedAt, text } = messageBody as (MessageBody & MessageContent);
        const profile: Profile = deserialize(Buffer.from(text, "base64"));
        if (!profile || typeof profile.displayName !== "string" || typeof profile.username !== "string" || typeof profile.profilePicture !== "string" ) {
            logError("Response Not According To Protocol");
            return "Response Not According To Protocol";
        }
        return { profile, respondedAt };
    }

    async rejectReceivedRequest(sessionId: string) {
        this.#receivedChatRequests.delete(sessionId);
        return await this.export();
    }

    async deleteSentRequest(sessionId: string) {
        this.#sentChatRequests.delete(sessionId);
        return await this.export();
    }

    getPendingSentRequest(sessionId: string): ViewSentRequest {
        return _.pick(this.#sentChatRequests.get(sessionId), "messageId", "timestamp", "otherUser", "text", "sessionId", "myAlias", "otherAlias", "headerId");
    }

    getPendingReceivedRequest(sessionId: string): ViewReceivedRequest {
        return _.pick(this.#receivedChatRequests.get(sessionId), "messageId", "timestamp", "otherUser", "text", "sessionId", "myAlias", "otherAlias", "headerId", "profile") as ViewReceivedRequest;
    }

    async issueOneTimeKeys(n: number): Promise<IssueOneTimeKeysResponse> {
        const oneTimeKeys = new Array<[string, ExposedSignedPublicKey]>();
        for (let i = 0; i < n; i++) {
            const newKey = await this.#identity.generateSignedKeyPair();
            const id = `${getRandomString(10, "base64")}-${Date.now()}`;
            oneTimeKeys.push([id, crypto.exposeSignedKey(newKey)]);
            this.#oneTimeKeys.set(id, newKey.keyPair.privateKey);
        }
        const x3dhInfo = await this.export();
        return { x3dhInfo, oneTimeKeys };
    }

    async replacePreKey(): Promise<ReplacePreKeyResponse> {
        const newKey = await this.#identity.generateSignedKeyPair();
        const newVersion = this.#currentPreKeyVersion + 1;
        this.#preKeys.set(newVersion, newKey.keyPair.privateKey);
        this.#currentPreKeyVersion = newVersion;
        const x3dhInfo = await this.export();
        return { x3dhInfo, preKey: [newVersion, crypto.exposeSignedKey(newKey)] };
    }

    async registerBundle(keyBundleId: KeyBundleId) {
        this.#issuedBundles.set(keyBundleId.bundleId, keyBundleId);
        return await this.export();
    }

    async unpackServerMemo<T extends any>(serverMemo: ServerMemo, serverVerifyingKey: CryptoKey) {
        try {
            const { memoId, encryptionPublicKey, memoData: { hSalt, ...encryptedData } } = serverMemo;
            const importedKey = await crypto.importKey(encryptionPublicKey, "ECDH", "public", false);
            const sharedBits = await this.#identity.deriveSymmetricBits(importedKey, 512);
            const memoData = await crypto.deriveDecryptVerify(sharedBits, encryptedData, hSalt, `ServerMemo for ${this.#identity.username}: ${memoId}`, serverVerifyingKey) as T;
            if (!memoData) return null;
            return { memoId, memoData };
        }
        catch (err) {
            logError(err);
            return null;
        }
    }

    private async importVerifyingKey(verifyingKey: Buffer) {
        return await crypto.importKey(verifyingKey, "ECDSA", "public", true);
    }
}

export class ChattingSession {
    readonly sessionId: string;
    readonly myAlias: string;
    readonly otherAlias: string;
    readonly createdAt: number;
    readonly #encryptionBaseVector: CryptoKey;
    readonly me: string;
    readonly otherUser: string;
    readonly #maxSkip: number;
    readonly #identity: X3DHIdentity;
    readonly #otherVerifyKey: CryptoKey;
    #currentRootKey: Buffer;
    #currentDHRatchetKey: CryptoKey;
    #currentDHPublishKey: ExposedSignedPublicKey;
    #currentSendingChainKey: Buffer;
    #currentReceivingChainKey: Buffer;
    #sendingRatchetNumber: number;
    #receivingRatchetNumber: number;
    #sendingChainNumber = 0;
    #receivingChainNumber = 0;
    #previousSendingChainNumber = 0;
    #skippedKeys = new Map<[number, number], Buffer>();
    private queue = new Queue(1, 10);
    private lastActivityTimestamp: number;

    public get lastActivity() {
        return this.lastActivityTimestamp;
    }

    static async import(encryptedSession: UserEncryptedData, encryptionBaseVector: CryptoKey, identity: X3DHIdentity) : Promise<ChattingSession> {
        const decryptedSession = await crypto.deriveDecrypt(encryptedSession, encryptionBaseVector, "Export|Import Chatting Session");
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
            const unwrappedRatchetKey = await crypto.deriveUnwrap(encryptionBaseVector, currentDHRatchetKey, "ECDH", "DH Ratchet Key", true);
            const importedVerifyKey = await crypto.importKey(recipientVerifyKey, "ECDSA", "public", true);
            const exportedSession = new ChattingSession(sessionId, encryptionBaseVector, identity, createdAt, lastActivity, sender, recipient, senderAlias, recipientAlias, importedVerifyKey, currentRootKey, maxSkip);
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

    private async export(): Promise<UserEncryptedData> {
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
        const currentDHRatchetKey = await crypto.deriveWrap(this.#encryptionBaseVector, this.#currentDHRatchetKey, "DH Ratchet Key");
        const currentDHPublishKey = this.#currentDHPublishKey;
        const currentSendingChainKey = this.#currentSendingChainKey;
        const currentReceivingChainKey = this.#currentReceivingChainKey;
        const sendingRatchetNumber = this.#sendingRatchetNumber;
        const receivingRatchetNumber = this.#receivingRatchetNumber;
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
        return await crypto.deriveEncrypt(exportedSession, this.#encryptionBaseVector, "Export|Import Chatting Session");
    }

    private constructor(
        sessionId: string,
        encryptionBaseVector: CryptoKey,
        identity: X3DHIdentity,
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
            this.#encryptionBaseVector = encryptionBaseVector;
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
    
    static async new(encryptionBaseVector: CryptoKey,
        identity: X3DHIdentity,
        sender: string,
        recipient: string,
        senderAlias: string,
        recipientAlias: string,
        recipientVerify: CryptoKey,
        sharedRoot: Buffer,
        maxSkip: number,
        dhRatchetOtherPublic: CryptoKey,
        dhRatcherMyPrivate: CryptoKey = null): Promise<ChattingSession> {
            const now = Date.now();
            const amInitiator = !!dhRatcherMyPrivate;
            const sessionId = (await crypto.digestToBase64("SHA-256", sharedRoot)).slice(0, 15);
            const chattingSession = new ChattingSession(sessionId, encryptionBaseVector, identity, now, now, sender, recipient, senderAlias, recipientAlias, recipientVerify, sharedRoot, maxSkip);
            chattingSession.#receivingRatchetNumber = amInitiator ? -1 : 0;
            if (amInitiator) {
                chattingSession.#currentDHRatchetKey = dhRatcherMyPrivate;
                await chattingSession.advanceFirstHalfDHRatchet(dhRatchetOtherPublic);
            }
            chattingSession.#sendingRatchetNumber = amInitiator ? 0 : -1;
            await chattingSession.advanceSecondHalfDHRatchet(dhRatchetOtherPublic);
            return chattingSession;
    }

    private async advanceFirstHalfDHRatchet(nextDHPublicKey: CryptoKey) {
        const dhReceivingChainInput = await crypto.deriveSymmetricBits(this.#currentDHRatchetKey, nextDHPublicKey, 256);
        const { nextRootKey, output: recvInput } = await this.rootChainKDFDerive(dhReceivingChainInput);
        this.#currentRootKey = nextRootKey;
        this.#currentReceivingChainKey = recvInput;
        this.#receivingRatchetNumber += 2;
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
        this.#sendingRatchetNumber += 2;
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
        previousChainNumber: number): Promise<Buffer> {
            let output: Buffer = null;
            if ((sendingRatchetNumber - this.#receivingRatchetNumber) === 2) {
                while (this.#receivingChainNumber < previousChainNumber) {
                    output = await this.advanceSymmetricRatchet("Receiving");
                    if (this.#receivingChainNumber < sendingChainNumber) {
                        this.#skippedKeys.set([sendingRatchetNumber, this.#receivingChainNumber], output);
                    }
                }
                await this.advanceDHRatchet(nextDHPublicKey);
            }
            if ((sendingRatchetNumber - this.#receivingRatchetNumber) === 0) {
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
        const chainKey = chain === "Sending" ? this.#currentSendingChainKey : this.#currentReceivingChainKey;
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
    
    private async advanceReversibly(advance: () => Promise<Buffer>, saveSession: (arg: UserEncryptedData) => Promise<boolean>): Promise<Buffer> {
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

    async sendMessage(sendingMessage: SendingMessage, saveSession: (arg: UserEncryptedData) => Promise<boolean>): Promise<MessageHeader | "Could Not Save"> {
        let { timestamp, messageId } = sendingMessage;
        const messageKeyBits = await this.advanceReversibly(() => this.advanceSymmetricRatchet("Sending"), saveSession);
        if (!messageKeyBits) return "Could Not Save";
        const sender = this.me;
        const fromAlias = this.myAlias;
        const toAlias = this.otherAlias;
        const sessionId = this.sessionId;
        const receivingRatchetNumber = this.#receivingRatchetNumber + 2;
        const sendingRatchetNumber = this.#sendingRatchetNumber;
        const sendingChainNumber = this.#sendingChainNumber;
        const previousChainNumber = this.#previousSendingChainNumber;
        const nextDHRatchetKey = this.#currentDHPublishKey;
        const message: ReceivingMessage = { sender, messageId, timestamp, ...sendingMessage };
        const { ciphertext, signature } = 
        await this.#identity.deriveSignEncrypt(messageKeyBits, message, nullSalt(48), "Message Send|Receive");
        const headerId = getRandomString(15, "base64");
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
            messageBody: {
                ciphertext,
                signature
            }
        };
        return messageHeader;
    }

    async receiveMessage(messageHeader: MessageHeader, saveSession: (arg: UserEncryptedData) => Promise<boolean>): Promise<[ReceivingMessage | "Session Id Mismatch" | "Unverified Next Ratchet Key" | "Receving Ratchet Number Mismatch" | "Failed To Decrypt" | "Message Invalid" | "Could Not Save", string]> {
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
        const message: ReceivingMessage = await crypto.deriveDecryptVerify(messageKeyBits, messageBody, nullSalt(48), "Message Send|Receive", this.#otherVerifyKey);
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