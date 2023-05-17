import { Buffer } from "./node_modules/buffer";
import * as crypto from "../../shared/cryptoOperator";
import { serialize, deserialize } from "../../shared/cryptoOperator";
import { ExposedSignedPublicKey, SignedKeyPair, ExportedSignedKeyPair, ExportedSigningKeyPair, KeyBundle, MessageHeader, ChatRequestHeader, randomFunctions, UserEncryptedData, Profile } from "../../shared/commonTypes";
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
    content: string;
}>;

type MessageEvent = Readonly<{
    event: "delivered" | "seen" | "typing" | "stopped-typing";
}>;

export type SendingMessage = (MessageContent | MessageEvent) & Omit<MessageBody, "sender">;

type ReceivingMessage = MessageBody & (MessageContent | MessageEvent);

type ChatRequestBody = Readonly<{ 
    myKeySignature: string;
    yourKeySignature: string;
    yourUsername: string;
    myDHRatchetInititalizer: ExposedSignedPublicKey;
    timestamp: number;
    firstMessage: string;
    profile: Profile;
}>;

type ChatRequestInWaiting = Readonly<{
    timestamp: number;
    sessionId: string;
    otherUser: string;
    recipientVerifyKey: CryptoKey;
    sharedRoot: Buffer;
    myPrivateDHRatchetInitializer: CryptoKey;
    firstMessage: string;
}>;

export type ViewPendingRequest = Readonly<{
    timestamp: number;
    sessionId: string;
    otherUser: string;
    firstMessage: string;
}>;

type ChatRequestProcessResult = Readonly<{ 
    profile: Profile,
    firstMessage: string, 
    timestamp: number, 
    sharedRoot: Buffer, 
    importedVerifyingIdentityKey: CryptoKey, 
    importedDHInitializer: CryptoKey,
    myOneTimeKeyIdentifier: string
}>;

export type ViewChatRequest = Readonly<{ 
    firstMessage: string, 
    timestamp: number,
    profile: Profile;
}>;

type ExportedChatRequestInWaiting = Readonly<{
    timestamp: number;
    sessionId: string;
    otherUser: string;
    recipientVerifyKey: Buffer;
    sharedRoot: Buffer;
    myPrivateDHRatchetInitializer: Buffer;
    firstMessage: string;
}>;

type ExportedX3DHUser = Readonly<{
    username: string;
    version: number;
    minOneTimeKeys: number;
    maxOneTimeKeys: number;
    replaceKeyAtInMillis: number;
    identitySigningKeyPair: ExportedSigningKeyPair;
    identityDHKeyPair: ExportedSignedKeyPair;
    signedPreKeyPair: ExportedSignedKeyPair;
    signedOneTimeKeys: Map<string, ExportedSignedKeyPair>;
    waitingChatRequests: UserEncryptedData;
    keyLastReplaced: number;
    preKeyVersion: number
}>;

type ExportedChattingSession = Readonly<{
    sessionId: string;
    createdAt: number;
    lastActivity: number;
    sender: string;
    recipient: string;
    maxSkip: number;
    senderSignRecipientVerifyKeys: ExportedSigningKeyPair;
    currentRootKey: Buffer;
    currentDHRatchetKey: Buffer;
    currentDHPublishKey: ExposedSignedPublicKey;
    currentSendingChainKey: Buffer;
    currentReceivingChainKey: Buffer;
    sendingRatchetNumber: number;
    receivingRatchetNumber: number;
    sendingChainNumber: number;
    receivingChainNumber: number;
    previousSendingChainNumber: number;
    skippedKeys: Map<[number, number], Buffer>;
}>;

export class X3DHUser {
    readonly username: string;
    readonly #minOneTimeKeys: number;
    readonly #maxOneTimeKeys: number;
    readonly #replaceKeyAtInMillis: number;
    readonly #version: number;
    readonly #encryptionBaseVector: CryptoKey;
    private readonly maxSkip: number;
    #identitySigningKeyPair: CryptoKeyPair;
    #identitySigningKey: CryptoKey;
    #identityDHKeyPair: SignedKeyPair;
    #signedPreKeyPair: SignedKeyPair;
    #currentOneTimeKeys = new Map<string, SignedKeyPair>();
    #usedOneTimeKeys = new Map<string, SignedKeyPair>();
    #waitingChatRequests = new Map<string, ChatRequestInWaiting>();
    #keyLastReplaced: number = null;
    #preKeyVersion = 0;

    public get version() {
        return this.#version;
    }

    public get pendingChatRequests(): ViewPendingRequest[] {
        return Array.from(this.#waitingChatRequests.values()).map(({ timestamp, otherUser, firstMessage, sessionId }) => ({ timestamp, otherUser, firstMessage, sessionId }));
    }

    private constructor(username: string,
        encryptionBaseVector: CryptoKey,
        version = 0,
        minOneTimeKeys = 10,
        maxOneTimeKeys = minOneTimeKeys,
        replaceKeyAtInDays = 7,
        maxSkip = 20) {
            this.username = username;
            this.#encryptionBaseVector = encryptionBaseVector;
            this.#version = version;
            this.#minOneTimeKeys = minOneTimeKeys;
            this.#maxOneTimeKeys = maxOneTimeKeys;
            this.#replaceKeyAtInMillis = replaceKeyAtInDays * 24 * 3600 * 1000;
            this.maxSkip = maxSkip;
    }

    async exportUser(): Promise<UserEncryptedData> {
        await this.regularProtocolRun();
        const username = this.username;
        const version = this.#version;
        const minOneTimeKeys = this.#minOneTimeKeys;
        const maxOneTimeKeys = this.#maxOneTimeKeys;
        const replaceKeyAtInMillis = this.#replaceKeyAtInMillis;
        const hSalt = getRandomVector(48);
        const identitySigningKeyPair = await crypto.exportSigningKeyPair(this.#identitySigningKeyPair, this.#encryptionBaseVector, hSalt, "X3DH User Identity");
        const identityDHKeyPair = await crypto.exportSignedKeyPair(this.#identityDHKeyPair, this.#encryptionBaseVector, hSalt, "X3DH User Identity DH");
        const signedPreKeyPair = await crypto.exportSignedKeyPair(this.#signedPreKeyPair, this.#encryptionBaseVector, hSalt, "X3DH User PreKey");
        const signedOneTimeKeys = new Map<string, ExportedSignedKeyPair>();
        for (const [id, key] of this.#currentOneTimeKeys.entries()) {
            signedOneTimeKeys.set(id, await crypto.exportSignedKeyPair(key, this.#encryptionBaseVector, hSalt, `X3DH User OneTimeKey ${id}`));
        }
        const keyLastReplaced = this.#keyLastReplaced;
        const preKeyVersion = this.#preKeyVersion;
        const exportedRequests = new Map<string, ExportedChatRequestInWaiting>();
        for (const [sessionId, { timestamp, otherUser, firstMessage, sharedRoot, myPrivateDHRatchetInitializer, recipientVerifyKey }] of this.#waitingChatRequests) {
            exportedRequests.set(sessionId, {
                timestamp,
                sessionId,
                otherUser,
                recipientVerifyKey: await crypto.exportKey(recipientVerifyKey),
                sharedRoot,
                myPrivateDHRatchetInitializer: await crypto.exportKey(myPrivateDHRatchetInitializer),
                firstMessage
            });
        }
        const waitingChatRequests = await crypto.deriveEncrypt(exportedRequests, this.#encryptionBaseVector, "Waiting Message Requests");
        const exportedUser: ExportedX3DHUser = {
            username,
            version,
            minOneTimeKeys,
            maxOneTimeKeys,
            replaceKeyAtInMillis,
            identitySigningKeyPair,
            identityDHKeyPair,
            signedPreKeyPair,
            signedOneTimeKeys,
            waitingChatRequests,
            keyLastReplaced,
            preKeyVersion };
        return await crypto.deriveEncrypt(exportedUser, this.#encryptionBaseVector, "Export|Import X3DH User", hSalt);
    }

    static async importUser(encryptedUser: UserEncryptedData, encryptionBaseVector: CryptoKey) : Promise<X3DHUser> {
        const { hSalt } = encryptedUser
        try {
            const importedUser: ExportedX3DHUser = await crypto.deriveDecrypt(encryptedUser, encryptionBaseVector, "Export|Import X3DH User");
            if (!importedUser) {
                return null;
            }
            const {
                username,
                version,
                minOneTimeKeys,
                maxOneTimeKeys,
                replaceKeyAtInMillis,
                identitySigningKeyPair: exportedidentityKeyPair,
                identityDHKeyPair: exportedIdentityDHKeyPair,
                signedPreKeyPair: exportedSignedPreKeyPair,
                signedOneTimeKeys: exportedSignedOneTimeKeys,
                waitingChatRequests,
                keyLastReplaced,
                preKeyVersion } = importedUser;
            const replaceKeyAtInDays = replaceKeyAtInMillis / (24 * 3600 * 1000);
            const user = new X3DHUser(username, encryptionBaseVector, version + 1, minOneTimeKeys, maxOneTimeKeys, replaceKeyAtInDays);
            user.#identitySigningKeyPair = await crypto.importSigningKeyPair(exportedidentityKeyPair, encryptionBaseVector, hSalt, "X3DH User Identity");
            user.#identityDHKeyPair = await crypto.importSignedKeyPair(exportedIdentityDHKeyPair, encryptionBaseVector, hSalt, "X3DH User Identity DH");
            user.#signedPreKeyPair = await crypto.importSignedKeyPair(exportedSignedPreKeyPair, encryptionBaseVector, hSalt, "X3DH User PreKey");
            const signedOneTimeKeys = new Map<string, SignedKeyPair>();
            for (const [id, key] of exportedSignedOneTimeKeys.entries()) {
                signedOneTimeKeys.set(id, await crypto.importSignedKeyPair(key, encryptionBaseVector, hSalt, `X3DH User OneTimeKey ${id}`));
            }
            user.#identitySigningKey = user.#identitySigningKeyPair.privateKey;
            user.#currentOneTimeKeys = signedOneTimeKeys;
            const exportedWaitingChatRequests: Map<string, ExportedChatRequestInWaiting> = await crypto.deriveDecrypt(waitingChatRequests, encryptionBaseVector, "Waiting Message Requests");
            for (const [sessionId, { timestamp, otherUser, firstMessage, sharedRoot, myPrivateDHRatchetInitializer, recipientVerifyKey }] of exportedWaitingChatRequests) {
                user.#waitingChatRequests.set(sessionId, {
                    timestamp,
                    sessionId,
                    otherUser,
                    recipientVerifyKey: await crypto.importKey(recipientVerifyKey, "ECDSA", "public", true),
                    sharedRoot,
                    myPrivateDHRatchetInitializer: await crypto.importKey(myPrivateDHRatchetInitializer, "ECDH", "private", true),
                    firstMessage
                });
            }
            user.#keyLastReplaced = keyLastReplaced;
            user.#preKeyVersion = preKeyVersion;
            await user.regularProtocolRun();
            return user;
        }
        catch(err) {
            console.log(`${err}`);
            return null;
        }
    }

    static async new(username: string,
        encryptionBaseVector: CryptoKey,
        minOneTimeKeys = 10,
        maxOneTimeKeys = minOneTimeKeys,
        replaceKeyAtInDays = 7): Promise<X3DHUser> {
        const user = new X3DHUser(username, encryptionBaseVector, 0, minOneTimeKeys, maxOneTimeKeys, replaceKeyAtInDays);
        user.#identitySigningKeyPair = await crypto.generateKeyPair("ECDSA");
        user.#identitySigningKey = user.#identitySigningKeyPair.privateKey;
        user.#identityDHKeyPair = await crypto.generateSignedKeyPair(user.#identitySigningKey);
        await user.regularProtocolRun();
        return user;
    }

    async publishKeyBundles(): Promise<{ defaultKeyBundle: KeyBundle, oneTimeKeyBundles: KeyBundle[] }> {
        await this.regularProtocolRun();
        const owner = this.username;
        const publicSigningIdentityKey = await crypto.exportKey(this.#identitySigningKeyPair.publicKey);
        const publicDHIdentityKey = crypto.exposeSignedKey(this.#identityDHKeyPair);
        const publicSignedPreKey = crypto.exposeSignedKey(this.#signedPreKeyPair);
        const preKeyVersion = this.#preKeyVersion;
        const oneTimeKeyBundles: KeyBundle[] = [];
        for (const [identifier, key] of this.#currentOneTimeKeys.entries()) {
            const publicOneTimeKey = crypto.exposeSignedKey(key);
            oneTimeKeyBundles.push({ identifier, owner, verifyingIdentityKey: publicSigningIdentityKey, publicDHIdentityKey, publicSignedPreKey, publicOneTimeKey, preKeyVersion });
        }
        const defaultKeyBundle: KeyBundle = { identifier: `${preKeyVersion}`, owner, verifyingIdentityKey: publicSigningIdentityKey, publicDHIdentityKey, publicSignedPreKey, preKeyVersion, publicOneTimeKey: null };
        return { defaultKeyBundle, oneTimeKeyBundles };
    }

    async generateChatRequest(keyBundle: KeyBundle, firstMessage: string, timestamp: number, profileDetails: Omit<Profile, "username">, sendChatRequest: (request: ChatRequestHeader) => Promise<boolean>) : Promise<[ViewPendingRequest, UserEncryptedData] | "Invalid Identity Signature" | "Invalid PreKey Signature" | "Invalid OneTimeKey Signature" | "Sending Request Failed"> {
        const {
            identifier,
            preKeyVersion,
            owner: yourUsername,
            verifyingIdentityKey,
            publicDHIdentityKey: otherDHIdentityKey,
            publicSignedPreKey,
            publicOneTimeKey } = keyBundle;
        const importedVerifyingIdentityKey = await this.importVerifyingKey(verifyingIdentityKey);
        const importedDHIdentityKey = await crypto.verifyKey(otherDHIdentityKey, importedVerifyingIdentityKey);
        if (!importedDHIdentityKey) {
            return "Invalid Identity Signature";
        }
        const importedPreKey = await crypto.verifyKey(publicSignedPreKey, importedVerifyingIdentityKey);
        if (!importedDHIdentityKey) {
            return "Invalid PreKey Signature";
        }
        let importedOneTimeKey: CryptoKey = undefined;
        let yourOneTimeKeyIdentifier: string = null;
        if (publicOneTimeKey) {
            importedOneTimeKey = await crypto.verifyKey(publicOneTimeKey, importedVerifyingIdentityKey);
            if (!importedOneTimeKey) {
                return "Invalid OneTimeKey Signature";
            }
            yourOneTimeKeyIdentifier = identifier;
        }
        const ephemeralKeyPair = await crypto.generateSignedKeyPair(this.#identitySigningKey);
        const myPublicEphemeralKey = crypto.exposeSignedKey(ephemeralKeyPair);
        const dh1 = await crypto.deriveSymmetricBits(this.#identityDHKeyPair.keyPair.privateKey, importedPreKey, 512);
        const dh2 = await crypto.deriveSymmetricBits(ephemeralKeyPair.keyPair.privateKey, importedDHIdentityKey, 512);
        const dh3 = await crypto.deriveSymmetricBits(ephemeralKeyPair.keyPair.privateKey, importedPreKey, 512);
        const dh4 = (importedOneTimeKey !== undefined) 
                    ? [await crypto.deriveSymmetricBits(ephemeralKeyPair.keyPair.privateKey, importedOneTimeKey, 512)]
                    : [];
        const sharedRoot = Buffer.concat([dh1, dh2, dh3, ...dh4]);
        const myKeySignature = this.#identityDHKeyPair.signature.toString("base64");
        const yourKeySignature = otherDHIdentityKey.signature.toString("base64");
        const dhRatchetInitializer = await crypto.generateSignedKeyPair(this.#identitySigningKey);
        const myDHRatchetInititalizer = crypto.exposeSignedKey(dhRatchetInitializer);
        const profile = { ...profileDetails, username: this.username }
        const initialData: ChatRequestBody = {
            myKeySignature, 
            yourKeySignature,
            yourUsername, 
            myDHRatchetInititalizer,
            timestamp,
            firstMessage,
            profile
         };
        const initialCiphertext = await crypto.deriveSignEncrypt(sharedRoot, initialData, nullSalt(48), "Message Request", this.#identitySigningKey);
        const myPublicSigningIdentityKey = await crypto.exportKey(this.#identitySigningKeyPair.publicKey);
        const myPublicDHIdentityKey = crypto.exposeSignedKey(this.#identityDHKeyPair);
        const sessionId = sharedRoot.toString("base64").slice(0, 15);
        const request: ChatRequestHeader = {
            sessionId,
            timestamp,
            addressedTo: yourUsername,
            myVerifyingIdentityKey: myPublicSigningIdentityKey,
            myPublicDHIdentityKey,
            myPublicEphemeralKey,
            yourSignedPreKeyVersion: preKeyVersion,
            yourOneTimeKeyIdentifier,
            initialMessage: initialCiphertext };
        const pendingRequest: ViewPendingRequest = {
            timestamp, 
            sessionId, 
            firstMessage,
            otherUser: yourUsername };
        const waitingRequest: ChatRequestInWaiting = {
            ...pendingRequest,
            recipientVerifyKey: importedVerifyingIdentityKey, 
            sharedRoot, 
            myPrivateDHRatchetInitializer: dhRatchetInitializer.keyPair.privateKey };
        if (await sendChatRequest(request)) {
            this.#waitingChatRequests.set(sessionId, waitingRequest);
            return [pendingRequest, await this.exportUser()];
        }
        return "Sending Request Failed";
    }

    private async processChatRequest(initialMessage: ChatRequestHeader)
    : Promise<ChatRequestProcessResult | "Incorrectly Addressed" | "PreKey Version Mismatch" | "OneTimeKey Not Found" | "Invalid Identity Signature" | "Invalid Ephemeral Signature" | "Failed To Decrypt Message" | "Problem With Decrypted Message" | "Unknown Error"> {
        try {
            await this.regularProtocolRun();
            const {
                addressedTo,
                myVerifyingIdentityKey: otherVerifyingIdentityKey,
                myPublicDHIdentityKey: otherPublicDHIdentityKey,
                myPublicEphemeralKey: otherPublicEphemeralKey,
                yourSignedPreKeyVersion: mySignedPreKeyVersion,
                yourOneTimeKeyIdentifier: myOneTimeKeyIdentifier,
                initialMessage: initMessage } = initialMessage;
            if (addressedTo !== this.username) {
                return "Incorrectly Addressed";
            }
            if (mySignedPreKeyVersion !== this.#preKeyVersion) {
                return "PreKey Version Mismatch";
            }
            let oneTimeKey: SignedKeyPair = undefined;
            if (myOneTimeKeyIdentifier) {
                oneTimeKey = this.#currentOneTimeKeys.get(myOneTimeKeyIdentifier);
                if (oneTimeKey === undefined) {
                    return "OneTimeKey Not Found";
                }
            }
            const importedVerifyingIdentityKey = await this.importVerifyingKey(otherVerifyingIdentityKey);
            const importedDHIdentityKey = await crypto.verifyKey(otherPublicDHIdentityKey, importedVerifyingIdentityKey);
            if (!importedDHIdentityKey) {
                return "Invalid Identity Signature";
            }
            const importedEphemeralKey = await crypto.verifyKey(otherPublicEphemeralKey, importedVerifyingIdentityKey);
            if (!importedEphemeralKey) {
                return "Invalid Ephemeral Signature";
            }
            try {
                const dh1 = await crypto.deriveSymmetricBits(this.#signedPreKeyPair.keyPair.privateKey, importedDHIdentityKey, 512);
                const dh2 = await crypto.deriveSymmetricBits(this.#identityDHKeyPair.keyPair.privateKey, importedEphemeralKey, 512);
                const dh3 = await crypto.deriveSymmetricBits(this.#signedPreKeyPair.keyPair.privateKey, importedEphemeralKey, 512);
                const dh4 = (oneTimeKey !== undefined) 
                            ? [await crypto.deriveSymmetricBits(oneTimeKey.keyPair.privateKey, importedEphemeralKey, 512)]
                            : [];
                const sharedRoot = Buffer.concat([dh1, dh2, dh3, ...dh4]);
                const plaintext = await crypto.deriveDecryptVerify(sharedRoot, initMessage, nullSalt(48), "Message Request", importedVerifyingIdentityKey);
                if (!plaintext) {
                    return "Failed To Decrypt Message";
                }
                const message: ChatRequestBody = plaintext;
                const { myKeySignature: otherKeySignature, 
                    yourKeySignature: myKeySignature,
                    yourUsername: myUsername, 
                    timestamp,
                    firstMessage,
                    profile,
                    myDHRatchetInititalizer: dhRatchetInitializer } = message;
                const importedDHInitializer = await crypto.verifyKey(dhRatchetInitializer, importedVerifyingIdentityKey);
                if ((myKeySignature as string) !== this.#identityDHKeyPair.signature.toString("base64") 
                || (otherKeySignature as string) !== otherPublicDHIdentityKey.signature.toString("base64")
                || !profile.username
                || !importedDHInitializer
                || (myUsername as string) !== this.username) {
                    return "Problem With Decrypted Message";
                }
                return {
                    profile,
                    timestamp, 
                    firstMessage, 
                    importedVerifyingIdentityKey, 
                    sharedRoot,
                    importedDHInitializer,
                    myOneTimeKeyIdentifier
                };
            }
            catch (err) {
                console.log(`${err}`);
                return "Failed To Decrypt Message";
            }
        }
        catch (err) {
            console.log(`${err}`);
            return "Unknown Error";
        }
    }

    async viewChatRequest(initialMessage: ChatRequestHeader)
        : Promise<ViewChatRequest | "Incorrectly Addressed" | "PreKey Version Mismatch" | "OneTimeKey Not Found" | "Invalid Identity Signature" | "Invalid Ephemeral Signature" | "Failed To Decrypt Message" | "Problem With Decrypted Message" | "Unknown Error"> {
            const chatRequestResult = await this.processChatRequest(initialMessage);
            if (typeof chatRequestResult === "string") return chatRequestResult;
            const { profile, firstMessage, timestamp } =  chatRequestResult;
            return { profile, firstMessage, timestamp };
    }

    async acceptChatRequest(initialMessage: ChatRequestHeader, timestamp: number, profileDetails: Omit<Profile, "username">, sendResponse: (responseHeader: MessageHeader) => Promise<boolean>)
        : Promise<UserEncryptedData | "Incorrectly Addressed" | "PreKey Version Mismatch" | "OneTimeKey Not Found" | "Invalid Identity Signature" | "Invalid Ephemeral Signature" | "Failed To Decrypt Message" | "Problem With Decrypted Message" | "Unknown Error" | "Couldn't Send Message" | "Concurrent Process Attempted"> {
            const chatRequestResult = await this.processChatRequest(initialMessage);
            if (typeof chatRequestResult === "string") return chatRequestResult;
            const { profile, importedDHInitializer, importedVerifyingIdentityKey, myOneTimeKeyIdentifier, sharedRoot } =  chatRequestResult;
            const chattingSession = await ChattingSession.new(this.#encryptionBaseVector,
                this.username, 
                profile.username, 
                this.#identitySigningKeyPair.privateKey,
                importedVerifyingIdentityKey,
                sharedRoot,
                this.maxSkip,
                importedDHInitializer);
            const content = serialize({ ...profileDetails, username: this.username }).toString("base64");
            const exportedChattingSession = await chattingSession.sendMessage({ content, timestamp, messageId: "0" }, sendResponse);
            if (myOneTimeKeyIdentifier && typeof exportedChattingSession !== "string") {
                // this.#currentOneTimeKeys.delete(myOneTimeKeyIdentifier);
                return exportedChattingSession;
            }
    }

    async receiveChatRequestResponse(responseHeader: MessageHeader): Promise<[{ profile: Profile, respondedAt: number }, UserEncryptedData] | "Session Id Mismatch" | "Unverified Next Ratchet Key" | "Receving Ratchet Number Mismatch" | "Failed To Decrypt" | "Message Invalid" | "Failed To Commit Message" | "No Such Pending Request" | "Unverified Key" | "Concurrent Process Attempted"> {
        const { sessionId, nextDHRatchetKey } = responseHeader;
        const waitingDetails = this.#waitingChatRequests.get(sessionId);
        if (!waitingDetails) {
            return "No Such Pending Request";
        }
        const {
            otherUser,
            recipientVerifyKey,
            sharedRoot,
            myPrivateDHRatchetInitializer: myDHRatchetInitializer } = waitingDetails;
        const importedDHInitializer = await crypto.verifyKey(nextDHRatchetKey, recipientVerifyKey);
        if (!importedDHInitializer) {
            return "Unverified Key";
        }
        const chattingSession = await ChattingSession.new(this.#encryptionBaseVector, 
            this.username, 
            otherUser, 
            this.#identitySigningKey,
            recipientVerifyKey,
            sharedRoot,
            this.maxSkip,
            importedDHInitializer,
            myDHRatchetInitializer);
        let response: { profile: Profile, respondedAt: number } = null;
        const exportedChattingSession = await chattingSession.receiveMessage(responseHeader, async (messageBody) => {
            const { timestamp: respondedAt, content } = messageBody as (MessageBody & MessageContent);
            const profile: Profile = deserialize(Buffer.from(content, "base64"));
            if (!profile || typeof profile.displayName !== "string" || typeof profile.username !== "string" || typeof profile.profilePicture !== "string") {
                console.log("Request response violated protocol.");
                return false;
            }
            response = { profile, respondedAt };
            return true;
        });
        if (typeof exportedChattingSession === "string") {
            console.log(exportedChattingSession);
            return exportedChattingSession;
        }
        return [response, exportedChattingSession];
    }

    disposeOneTimeKey(oneTimeId: string) {
        // this.#currentOneTimeKeys.delete(oneTimeId);
        return this.exportUser();
    }

    deleteWaitingRequest(sessionId: string) {
        this.#waitingChatRequests.delete(sessionId);
        return this.exportUser();
    }

    private async regularProtocolRun() {
        if (this.version > 0) return; // temp
        await this.regeneratePreKey();
        await this.generateOneTimeKeys();
    }

    private async regeneratePreKey() {
        if (this.version > 0) return; // temp
        if (this.#keyLastReplaced && (Date.now() - this.#keyLastReplaced) < this.#replaceKeyAtInMillis) {
            return;
        };
        this.#signedPreKeyPair = await crypto.generateSignedKeyPair(this.#identitySigningKey);
        this.#preKeyVersion += 1;
        this.#keyLastReplaced = Date.now();
    }

    private async generateOneTimeKeys(generateMinKeys = true) {
        if (this.version > 0) return; // temp
        const currentKeys = this.#currentOneTimeKeys.size;
        if (currentKeys >= this.#maxOneTimeKeys) {
            return;
        }
        if (generateMinKeys && currentKeys >= this.#minOneTimeKeys) {
            return;
        }
        for (let k = 0; k < (this.#maxOneTimeKeys - currentKeys); k++) {
            const createdAt = Date.now();
            const identifier = `${getRandomString()}-${createdAt}`;
            const key = await crypto.generateSignedKeyPair(this.#identitySigningKey);
            this.#currentOneTimeKeys.set(identifier, key);
        }
    }

    private async importVerifyingKey(verifyingKey: Buffer) {
        return await crypto.importKey(verifyingKey, "ECDSA", "public", true);
    }
}

export class ChattingSession {
    readonly sessionId: string;
    readonly createdAt: number;
    readonly #encryptionBaseVector: CryptoKey;
    readonly #me: string;
    readonly #otherUser: string;
    readonly #maxSkip: number;
    readonly #mySignKey: CryptoKey;
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
    private processing = false;
    private lastActivityTimestamp: number;

    public get lastActivity() {
        return this.lastActivityTimestamp;
    }

    static async importSession(encryptedSession: UserEncryptedData, encryptionBaseVector: CryptoKey) : Promise<ChattingSession> {
        const { hSalt } = encryptedSession;
        const decryptedSession = await crypto.deriveDecrypt(encryptedSession, encryptionBaseVector, "Export|Import Chatting Session");
        if (!decryptedSession) {
            return null;
        }
        try {
            const {
                sessionId,
                createdAt,
                sender,
                lastActivity,
                recipient,
                maxSkip,
                senderSignRecipientVerifyKeys,
                currentRootKey,
                currentDHRatchetKey,
                currentDHPublishKey,
                currentSendingChainKey,
                currentReceivingChainKey,
                sendingRatchetNumber,
                receivingRatchetNumber,
                sendingChainNumber,
                receivingChainNumber,
                previousSendingChainNumber,
                skippedKeys }: ExportedChattingSession = decryptedSession;
            const { publicKey, privateKey } = await crypto.importSigningKeyPair(senderSignRecipientVerifyKeys, encryptionBaseVector, hSalt, "Identity");
            const unwrappedRatchetKey = await crypto.deriveUnwrap(encryptionBaseVector, currentDHRatchetKey, hSalt, "ECDH", "DH Ratchet Key", true);
            const exportedSession = new ChattingSession(sessionId, encryptionBaseVector, createdAt, lastActivity, sender, recipient, privateKey, publicKey, currentRootKey, maxSkip);
            exportedSession.#currentDHRatchetKey = unwrappedRatchetKey;
            exportedSession.#currentDHPublishKey = currentDHPublishKey;
            exportedSession.#currentSendingChainKey = currentSendingChainKey;
            exportedSession.#currentReceivingChainKey = currentReceivingChainKey;
            exportedSession.#sendingRatchetNumber = sendingRatchetNumber;
            exportedSession.#receivingRatchetNumber = receivingRatchetNumber;
            exportedSession.#sendingChainNumber = sendingChainNumber;
            exportedSession.#receivingChainNumber = receivingChainNumber;
            exportedSession.#previousSendingChainNumber = previousSendingChainNumber;
            exportedSession.#skippedKeys = skippedKeys;
            return exportedSession;
        }
        catch(err) {
            console.log(`${err}`);
            return null;
        }
    }

    private async exportSession(): Promise<UserEncryptedData> {
        const hSalt = getRandomVector(48);
        const sessionId = this.sessionId;
        const createdAt = this.createdAt;
        const lastActivity = this.lastActivityTimestamp;
        const sender = this.#me;
        const recipient = this.#otherUser;
        const maxSkip = this.#maxSkip;
        const signingKeyPair = {
            publicKey: this.#otherVerifyKey,
            privateKey: this.#mySignKey };
        const senderSignRecipientVerifyKeys = await crypto.exportSigningKeyPair(signingKeyPair, this.#encryptionBaseVector, hSalt, "Identity");
        const currentRootKey = this.#currentRootKey;
        const currentDHRatchetKey = await crypto.deriveWrap(this.#encryptionBaseVector, this.#currentDHRatchetKey, hSalt, "DH Ratchet Key");
        const currentDHPublishKey = this.#currentDHPublishKey;
        const currentSendingChainKey = this.#currentSendingChainKey;
        const currentReceivingChainKey = this.#currentReceivingChainKey;
        const sendingRatchetNumber = this.#sendingRatchetNumber;
        const receivingRatchetNumber = this.#receivingRatchetNumber;
        const sendingChainNumber = this.#sendingChainNumber;
        const receivingChainNumber = this.#receivingChainNumber;
        const previousSendingChainNumber = this.#previousSendingChainNumber;
        const skippedKeys = this.#skippedKeys;
        const exportedSession: ExportedChattingSession = {
            sessionId,
            createdAt,
            lastActivity,
            sender,
            recipient,
            maxSkip,
            senderSignRecipientVerifyKeys,
            currentRootKey: currentRootKey,
            currentDHRatchetKey,
            currentDHPublishKey,
            currentSendingChainKey,
            currentReceivingChainKey,
            sendingRatchetNumber,
            receivingRatchetNumber,
            sendingChainNumber,
            receivingChainNumber,
            previousSendingChainNumber,
            skippedKeys };
        return await crypto.deriveEncrypt(exportedSession, this.#encryptionBaseVector, "Export|Import Chatting Session", hSalt);
    }

    private constructor(
        sessionId: string,
        encryptionBaseVector: CryptoKey,
        createdAt: number,
        lastActivity: number,
        sender: string,
        recipient: string,
        senderSign: CryptoKey,
        recipientVerify: CryptoKey,
        currentRootKey: Buffer,
        maxSkip: number) {
            this.sessionId = sessionId;
            this.createdAt = createdAt;
            this.#encryptionBaseVector = encryptionBaseVector;
            this.#me = sender;
            this.#otherUser = recipient;
            this.#mySignKey = senderSign;
            this.#otherVerifyKey = recipientVerify;
            this.#currentRootKey = currentRootKey;
            this.#maxSkip = maxSkip;
            this.lastActivityTimestamp = lastActivity;
    }
    
    static async new(encryptionBaseVector: CryptoKey,
        sender: string,
        recipient: string,
        senderSign: CryptoKey,
        recipientVerify: CryptoKey,
        sharedRoot: Buffer,
        maxSkip: number,
        dhRatchetOtherPublic: CryptoKey,
        dhRatcherMyPrivate: CryptoKey = null): Promise<ChattingSession> {
            const now = Date.now();
            const amInitiator = !!dhRatcherMyPrivate;
            const chattingSession = new ChattingSession(sharedRoot.toString("base64").slice(0, 15), encryptionBaseVector, now, now, sender, recipient, senderSign, recipientVerify, sharedRoot, maxSkip);
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
        const nextRatchetKeyPair = await crypto.generateSignedKeyPair(this.#mySignKey);
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

    private async ratchetToCurrentReceived<T>(nextDHPublicKey: CryptoKey, 
        sendingRatchetNumber: number, 
        sendingChainNumber: number, 
        previousChainNumber: number,
        operation: (output: Buffer) => Promise<T | undefined>): Promise<T | "Concurrent Process Attempted" | undefined> {
            return await this.advanceReversibly(async () => {
                let output: Buffer = null;
                const skippedKeys = new Map<[number, number], Buffer>();
                if ((sendingRatchetNumber - this.#receivingRatchetNumber) === 2) {
                    while (this.#receivingChainNumber < previousChainNumber) {
                        output = await this.advanceSymmetricRatchet("Receiving");
                        if (this.#receivingChainNumber < sendingChainNumber) {
                            skippedKeys.set([sendingRatchetNumber, this.#receivingChainNumber], output);
                        }
                    }
                    await this.advanceDHRatchet(nextDHPublicKey);
                }
                if ((sendingRatchetNumber - this.#receivingRatchetNumber) === 0) {
                    while (this.#receivingChainNumber < sendingChainNumber) {
                        output = await this.advanceSymmetricRatchet("Receiving");
                        if (this.#receivingChainNumber < sendingChainNumber) {
                            skippedKeys.set([sendingRatchetNumber, this.#receivingChainNumber], output);
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
                const error = await operation(output);
                if (!error) {
                    for (const [key, value] of skippedKeys) {
                        this.#skippedKeys.set(key, value);
                    }
                }
                return error;
            })
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

    private async advanceReversibly<T>(advance: () => Promise<T | undefined>): Promise<T | "Concurrent Process Attempted" | undefined> {
        if (this.processing) {
            console.log("Concurrent processing not allowed");
            return "Concurrent Process Attempted"
        };
        this.processing = true;
        console.log("Beginning process.");
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
        const error = await advance();
        if (error) {
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
        }
        this.processing = false;
        return error;
    }

    private verifyMessageIntegrity(header: MessageHeader, body: MessageBody) {
        return header.timestamp === body.timestamp 
            && header.messageId === body.messageId
            && body.sender === this.#otherUser
    }

    async sendMessage(sendingMessage: SendingMessage, send: (messageHeader: MessageHeader) => Promise<boolean>): Promise<UserEncryptedData | "Couldn't Send Message" | "Concurrent Process Attempted"> {
        const error = await this.advanceReversibly(async () => {
            const messageKeyBits = await this.advanceSymmetricRatchet("Sending");
            const sender = this.#me;
            const addressedTo = this.#otherUser;
            const sessionId = this.sessionId;
            const receivingRatchetNumber = this.#receivingRatchetNumber + 2;
            const sendingRatchetNumber = this.#sendingRatchetNumber;
            const sendingChainNumber = this.#sendingChainNumber;
            const previousChainNumber = this.#previousSendingChainNumber;
            const nextDHRatchetKey = this.#currentDHPublishKey;
            const { messageId, timestamp }= sendingMessage;
            const message: ReceivingMessage = { sender, timestamp, ...sendingMessage };
            const { ciphertext, signature } = 
            await crypto.deriveSignEncrypt(messageKeyBits, message, nullSalt(48), "Message Send|Receive", this.#mySignKey);
            const messageHeader = {
                addressedTo,
                sessionId,
                messageId,
                timestamp,
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
            if (await send(messageHeader)) {
                this.lastActivityTimestamp = timestamp;
                return undefined;
            }
            return "Couldn't Send Message" as const;
        });
        return error ? error : this.exportSession();
    }

    async receiveMessage(messageHeader: MessageHeader, receive: (message: ReceivingMessage) => Promise<boolean>): Promise<UserEncryptedData | "Session Id Mismatch" | "Unverified Next Ratchet Key" | "Receving Ratchet Number Mismatch" | "Failed To Decrypt" | "Message Invalid" | "Failed To Commit Message" | "Concurrent Process Attempted"> {
        const {
            addressedTo,
            sessionId,
            sendingRatchetNumber,
            sendingChainNumber,
            previousChainNumber,
            nextDHRatchetKey,
            messageBody } = messageHeader;
        if (sessionId !== this.sessionId || addressedTo !== this.#me ) {
            return "Session Id Mismatch";
        }
        const nextDHPublicKey = await crypto.verifyKey(nextDHRatchetKey, this.#otherVerifyKey);
        if (!nextDHPublicKey) {
            return "Unverified Next Ratchet Key";
        }
        const error = await this.ratchetToCurrentReceived(nextDHPublicKey, 
            sendingRatchetNumber, 
            sendingChainNumber, 
            previousChainNumber, 
            async (messageKeyBits) => {
                if (!messageKeyBits) {
                    return "Receving Ratchet Number Mismatch";
                }
                const message: ReceivingMessage = await crypto.deriveDecryptVerify(messageKeyBits, messageBody, nullSalt(48), "Message Send|Receive", this.#otherVerifyKey);
                let success = false;
                if (!message) {
                    console.log(error);
                    return "Failed To Decrypt";
                }
                else {
                    if (this.verifyMessageIntegrity(messageHeader, message)) {
                        success = await receive(message);
                    }
                    else {
                        return "Message Invalid";
                    }
                }
                if (success) {
                    this.lastActivityTimestamp = Date.now();
                    return undefined;
                }
                return "Failed To Commit Message";
        });
        return error ? error : this.exportSession();
    }
}