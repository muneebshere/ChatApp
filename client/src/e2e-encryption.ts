import { Buffer } from "./node_modules/buffer";
import * as crypto from "../../shared/cryptoOperator";
import { serialize, deserialize } from "../../shared/cryptoOperator";
import { ExposedSignedPublicKey, SignedKeyPair, ExportedSignedKeyPair, ExportedSigningKeyPair, KeyBundle, EncryptedData, SignedEncryptedData, MessageHeader, MessageRequestHeader, randomFunctions, UserEncryptedData, MessageBody, Profile } from "../../shared/commonTypes";

const { getRandomVector, getRandomString } = randomFunctions();

const nullSalt = (length: number) => Buffer.alloc(length);

type MessageRequestBody = Readonly<{ 
    myKeySignature: string;
    yourKeySignature: string;
    yourUsername: string;
    myDHRatchetInititalizer: ExposedSignedPublicKey;
    timestamp: number;
    firstMessage: string;
    profile: Profile;
}>;

type MessageRequestInWaiting = Readonly<{
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

type MessageRequestProcessResult = Readonly<{ 
    profile: Profile,
    firstMessage: string, 
    timestamp: number, 
    sharedRoot: Buffer, 
    importedVerifyingIdentityKey: CryptoKey, 
    importedDHInitializer: CryptoKey,
    myOneTimeKeyIdentifier: string
}>;

export type ViewMessageRequest = Readonly<{ 
    firstMessage: string, 
    timestamp: number,
    profile: Profile;
}>;

type ExportedX3DHUser = {
    readonly username: string;
    readonly version: number;
    readonly minOneTimeKeys: number;
    readonly maxOneTimeKeys: number;
    readonly replaceKeyAtInMillis: number;
    readonly identitySigningKeyPair: ExportedSigningKeyPair;
    readonly identityDHKeyPair: ExportedSignedKeyPair;
    readonly signedPreKeyPair: ExportedSignedKeyPair;
    readonly signedOneTimeKeys: Map<string, ExportedSignedKeyPair>;
    readonly waitingMessageRequests: UserEncryptedData;
    readonly keyLastReplaced: number;
    readonly preKeyVersion: number
}

type ExportedChattingSession = {
    readonly sessionId: string;
    readonly createdAt: number;
    readonly lastActivity: number;
    readonly sender: string;
    readonly recipient: string;
    readonly maxSkip: number;
    readonly senderSignRecipientVerifyKeys: ExportedSigningKeyPair;
    readonly currentRootKey: Buffer;
    readonly currentDHRatchetKey: Buffer;
    readonly currentDHPublishKey: ExposedSignedPublicKey;
    readonly currentSendingChainKey: Buffer;
    readonly currentReceivingChainKey: Buffer;
    readonly dhSendingRatchetNumber: number;
    readonly dhReceivingRatchetNumber: number;
    readonly sendingChainNumber: number;
    readonly receivingChainNumber: number;
    readonly previousSendingChainNumber: number;
    readonly skippedKeys: Map<[number, number], Buffer>;
}

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
    #waitingMessageRequests = new Map<string, MessageRequestInWaiting>();
    #keyLastReplaced: number = null;
    #preKeyVersion = 0;

    public get version() {
        return this.#version;
    }

    public get pendingMessageRequests(): ViewPendingRequest[] {
        return Array.from(this.#waitingMessageRequests.values()).map(({ timestamp, otherUser, firstMessage, sessionId }) => ({ timestamp, otherUser, firstMessage, sessionId }));
    }

    private constructor(username: string,
        encryptionBaseVector: CryptoKey,
        version = 1,
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
        const waitingMessageRequests = await crypto.encryptData(this.#waitingMessageRequests, this.#encryptionBaseVector, "Waiting Message Requests");
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
            waitingMessageRequests,
            keyLastReplaced,
            preKeyVersion };
        return await crypto.encryptData(exportedUser, this.#encryptionBaseVector, "Export|Import X3DH User", hSalt);
    }

    static async importUser(encryptedUser: UserEncryptedData, encryptionBaseVector: CryptoKey) : Promise<X3DHUser> {
        const { hSalt } = encryptedUser
        try {
            const importedUser: ExportedX3DHUser = await crypto.decryptData(encryptedUser, encryptionBaseVector, "Export|Import X3DH User");
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
                waitingMessageRequests,
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
            user.#waitingMessageRequests = await crypto.decryptData(waitingMessageRequests, encryptionBaseVector, "Waiting Message Requests");
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
        const user = new X3DHUser(username, encryptionBaseVector, 1, minOneTimeKeys, maxOneTimeKeys, replaceKeyAtInDays);
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
        const defaultKeyBundle = { identifier: `${preKeyVersion}`, owner, verifyingIdentityKey: publicSigningIdentityKey, publicDHIdentityKey, publicSignedPreKey, preKeyVersion };
        return { defaultKeyBundle, oneTimeKeyBundles };
    }

    async generateMessageRequest(keyBundle: KeyBundle, firstMessage: string, timestamp: number, profileDetails: Omit<Profile, "username">): Promise<MessageRequestHeader | "Invalid Identity Signature" | "Invalid PreKey Signature" | "Invalid OneTimeKey Signature"> {
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
        let yourOneTimeKeyIdentifier: string = undefined;
        if (!publicOneTimeKey) {
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
        let dh4: Buffer = undefined;
        if (importedOneTimeKey !== undefined)
            dh4 = await crypto.deriveSymmetricBits(ephemeralKeyPair.keyPair.privateKey, importedOneTimeKey, 512);
        const buffConcat = Buffer.concat(dh4 === undefined ? [dh1, dh2, dh3] : [dh1, dh2, dh3, dh4]);
        const myKeySignature = this.#identityDHKeyPair.signature.toString("base64");
        const yourKeySignature = otherDHIdentityKey.signature.toString("base64");
        const myUsername = this.username;
        const dhRatchetInitializer = await crypto.generateSignedKeyPair(this.#identitySigningKey);
        const myDHRatchetInititalizer = crypto.exposeSignedKey(dhRatchetInitializer);
        const profile = { ...profileDetails, username: this.username }
        const initialData: MessageRequestBody = {
            myKeySignature, 
            yourKeySignature,
            yourUsername, 
            myDHRatchetInititalizer,
            timestamp,
            firstMessage,
            profile
         };
        const initialCiphertext = await crypto.deriveSignEncrypt(buffConcat, serialize(initialData), nullSalt(48), "Message Request", this.#identitySigningKey);
        const myPublicSigningIdentityKey = await crypto.exportKey(this.#identitySigningKeyPair.publicKey);
        const myPublicDHIdentityKey = crypto.exposeSignedKey(this.#identityDHKeyPair);
        const sessionId = buffConcat.toString("base64").slice(0, 15);
        const initialMessage: MessageRequestHeader = {
            sessionId,
            timestamp,
            addressedTo: myUsername,
            myVerifyingIdentityKey: myPublicSigningIdentityKey,
            myPublicDHIdentityKey,
            myPublicEphemeralKey,
            yourSignedPreKeyVersion: preKeyVersion,
            yourOneTimeKeyIdentifier,
            initialMessage: initialCiphertext };
        const waitingRequest: MessageRequestInWaiting = {
            timestamp, 
            sessionId, 
            firstMessage,
            otherUser: yourUsername, 
            recipientVerifyKey: importedVerifyingIdentityKey, 
            sharedRoot: buffConcat, 
            myPrivateDHRatchetInitializer: dhRatchetInitializer.keyPair.privateKey };
        this.#waitingMessageRequests.set(sessionId, waitingRequest);
        return initialMessage;
    }

    private async processMessageRequest(initialMessage: MessageRequestHeader)
    : Promise<MessageRequestProcessResult | "Incorrectly Addressed" | "PreKey Version Mismatch" | "OneTimeKey Not Found" | "Invalid Identity Signature" | "Invalid Ephemeral Signature" | "Failed To Decrypt Message" | "Problem With Decrypted Message" | "Unknown Error"> {
        try {
            await this.regularProtocolRun();
            const {
                addressedTo,
                myVerifyingIdentityKey: otherVerifyingIdentityKey,
                myPublicDHIdentityKey: otherPublicDHIdentityKey,
                myPublicEphemeralKey: otherPublicEphemeralKey,
                yourSignedPreKeyVersion: mySignedPreKeyVersion,
                yourOneTimeKeyIdentifier: myOneTimeKeyIdentifier,
                initialMessage: { ciphertext, signature } } = initialMessage;
            if (addressedTo !== this.username) {
                return "Incorrectly Addressed";
            }
            if (mySignedPreKeyVersion !== this.#preKeyVersion) {
                return "PreKey Version Mismatch";
            }
            let oneTimeKey: SignedKeyPair = undefined;
            if (!myOneTimeKeyIdentifier) {
                const oneTimeKey = this.#currentOneTimeKeys.get(myOneTimeKeyIdentifier);
                if (oneTimeKey !== undefined) {
                    this.#currentOneTimeKeys.delete(myOneTimeKeyIdentifier);
                    await this.regularProtocolRun();
                }
                else {
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
                let dh4: Buffer = undefined;
                if (oneTimeKey !== undefined) {
                    dh4 = await crypto.deriveSymmetricBits(oneTimeKey.keyPair.privateKey, importedEphemeralKey, 512);
                }
                const sharedRoot = Buffer.concat(dh4 === undefined ? [dh1, dh2, dh3] : [dh1, dh2, dh3, dh4]);
                const plaintext = await crypto.deriveDecryptVerify(sharedRoot, ciphertext, nullSalt(48), "Message Request", signature, importedVerifyingIdentityKey);
                if (!plaintext) {
                    return "Failed To Decrypt Message";
                }
                const message: MessageRequestBody = deserialize(plaintext);
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

    async viewMessageRequest(initialMessage: MessageRequestHeader)
        : Promise<ViewMessageRequest | "Incorrectly Addressed" | "PreKey Version Mismatch" | "OneTimeKey Not Found" | "Invalid Identity Signature" | "Invalid Ephemeral Signature" | "Failed To Decrypt Message" | "Problem With Decrypted Message" | "Unknown Error"> {
            const messageRequestResult = await this.processMessageRequest(initialMessage);
            if (typeof messageRequestResult === "string") return messageRequestResult;
            const { profile, firstMessage, timestamp } =  messageRequestResult;
            return { profile, firstMessage, timestamp };
    }

    async acceptMessageRequest(initialMessage: MessageRequestHeader, timestamp: number, profileDetails: Omit<Profile, "username">, sendResponse: (responseHeader: MessageHeader) => Promise<boolean>)
        : Promise<UserEncryptedData | "Incorrectly Addressed" | "PreKey Version Mismatch" | "OneTimeKey Not Found" | "Invalid Identity Signature" | "Invalid Ephemeral Signature" | "Failed To Decrypt Message" | "Problem With Decrypted Message" | "Unknown Error" | "Sending Response Failed"> {
            const messageRequestResult = await this.processMessageRequest(initialMessage);
            if (typeof messageRequestResult === "string") return messageRequestResult;
            const { profile, firstMessage, importedDHInitializer, importedVerifyingIdentityKey, myOneTimeKeyIdentifier, sharedRoot } =  messageRequestResult;
            const chattingSession = await ChattingSession.new(this.#encryptionBaseVector,
                this.username, 
                profile.username, 
                this.#identitySigningKeyPair.privateKey,
                importedVerifyingIdentityKey,
                sharedRoot,
                this.maxSkip,
                importedDHInitializer);
            const content = serialize({ ...profileDetails, username: this.username }).toString("base64");
            const exportedChattingSession = await chattingSession.sendMessage({ content, timestamp }, sendResponse);
            if (exportedChattingSession && myOneTimeKeyIdentifier) {
                this.#currentOneTimeKeys.delete(myOneTimeKeyIdentifier);
            }
            return exportedChattingSession ? exportedChattingSession : "Sending Response Failed";
    }

    async receiveMessageRequestResponse(responseHeader: MessageHeader): Promise<[{ profile: Profile, respondedAt: number }, UserEncryptedData] | "No Such Pending Request" | "Unverified Key" | "Message Receipt Failed"> {
        const { sessionId, nextDHRatchetKey } = responseHeader;
        const waitingDetails = this.#waitingMessageRequests.get(sessionId);
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
            if (typeof messageBody === "string") {
                console.log(messageBody);
                return false;
            }
            const { timestamp: respondedAt, content } = messageBody;
            const profile: Profile = deserialize(Buffer.from(content, "base64"));
            if (!profile || typeof profile.displayName !== "string" || typeof profile.username !== "string" || typeof profile.profilePicture !== "string") {
                console.log("Request response violated protocol.");
                return false;
            }
            response = { profile, respondedAt };
            return true;
        });
        if (exportedChattingSession) {
            this.#waitingMessageRequests.delete(sessionId);
            return [response, exportedChattingSession];
        }
        return "Message Receipt Failed";
    }

    async oneTimeKeysAccessed(oneTimeIds: string[]) {
        const affected: string[] = [];
        for (const id of oneTimeIds) {
            const oneTimeKey = this.#currentOneTimeKeys.get(id);
            if (oneTimeKey) {
                affected.push(id);
                this.#usedOneTimeKeys.set(id, oneTimeKey);
                this.#currentOneTimeKeys.delete(id);
            }
        }
        if (affected.length > 0) {
            await this.regularProtocolRun();
        }
        return affected;
    }

    disposeOneTimeKey(oneTimeId: string) {
        this.#currentOneTimeKeys.delete(oneTimeId);
    }

    private async regularProtocolRun() {
        await this.regeneratePreKey();
        await this.generateOneTimeKeys();
    }

    private async regeneratePreKey() {
        if (this.#keyLastReplaced && (Date.now() - this.#keyLastReplaced) < this.#replaceKeyAtInMillis) {
            return;
        };
        this.#signedPreKeyPair = await crypto.generateSignedKeyPair(this.#identitySigningKey);
        this.#preKeyVersion += 1;
        this.#keyLastReplaced = Date.now();
    }

    private async generateOneTimeKeys(generateMinKeys = true) {
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
    #dhSendingRatchetNumber: number;
    #dhReceivingRatchetNumber: number;
    #sendingChainNumber = 0;
    #receivingChainNumber = 0;
    #previousSendingChainNumber = 0;
    #skippedKeys = new Map<[number, number], Buffer>();
    private lastActivityTimestamp: number;

    public get lastActivity() {
        return this.lastActivityTimestamp;
    }

    public get nextMessageId() {
        return `${this.#dhSendingRatchetNumber}.${this.#sendingChainNumber + 1}`;
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
            const amAcceptor = !dhRatcherMyPrivate;
            const chattingSession = new ChattingSession(encryptionBaseVector, now, now, sender, recipient, senderSign, recipientVerify, sharedRoot, maxSkip);
            chattingSession.#dhReceivingRatchetNumber = amAcceptor ? -1 : 0;
            chattingSession.#dhSendingRatchetNumber = amAcceptor ?-2 : -1;
            if (!amAcceptor) {
                chattingSession.#currentDHRatchetKey = dhRatcherMyPrivate;
                await chattingSession.advanceFirstHalfDHRatchet(dhRatchetOtherPublic);
            }
            await chattingSession.advanceSecondHalfDHRatchet(dhRatchetOtherPublic);
            return chattingSession;
    }

    static async importSession(encryptedSession: UserEncryptedData, encryptionBaseVector: CryptoKey) : Promise<ChattingSession> {
        const { hSalt } = encryptedSession;
        const decryptedSession = await crypto.decryptData(encryptedSession, encryptionBaseVector, "Export|Import Chatting Session");
        if (!decryptedSession) {
            return null;
        }
        try {
            const {
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
                dhSendingRatchetNumber,
                dhReceivingRatchetNumber,
                sendingChainNumber,
                receivingChainNumber,
                previousSendingChainNumber,
                skippedKeys }: ExportedChattingSession = deserialize(decryptedSession);
            const { publicKey, privateKey } = await crypto.importSigningKeyPair(senderSignRecipientVerifyKeys, encryptionBaseVector, hSalt, "Identity");
            const unwrappedRatchetKey = await crypto.deriveUnwrap(encryptionBaseVector, currentDHRatchetKey, hSalt, "ECDH", "DH Ratchet Key", true);
            const exportedSession = new ChattingSession(encryptionBaseVector, createdAt, lastActivity, sender, recipient, privateKey, publicKey, currentRootKey, maxSkip);
            exportedSession.#currentDHRatchetKey = unwrappedRatchetKey;
            exportedSession.#currentDHPublishKey = currentDHPublishKey;
            exportedSession.#currentSendingChainKey = currentSendingChainKey;
            exportedSession.#currentReceivingChainKey = currentReceivingChainKey;
            exportedSession.#dhSendingRatchetNumber = dhSendingRatchetNumber;
            exportedSession.#dhReceivingRatchetNumber = dhReceivingRatchetNumber;
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
        const dhSendingRatchetNumber = this.#dhSendingRatchetNumber;
        const dhReceivingRatchetNumber = this.#dhReceivingRatchetNumber;
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
            currentRootKey,
            currentDHRatchetKey,
            currentDHPublishKey,
            currentSendingChainKey,
            currentReceivingChainKey,
            dhSendingRatchetNumber,
            dhReceivingRatchetNumber,
            sendingChainNumber,
            receivingChainNumber,
            previousSendingChainNumber,
            skippedKeys };
        return await crypto.encryptData(exportedSession, this.#encryptionBaseVector, "Export|Import Chatting Session", hSalt);
    }

    private constructor(
        encryptionBaseVector: CryptoKey,
        createdAt: number,
        lastActivity: number,
        sender: string,
        recipient: string,
        senderSign: CryptoKey,
        recipientVerify: CryptoKey,
        sharedRoot: Buffer,
        maxSkip: number) {
            this.sessionId = sharedRoot.toString("base64").slice(0, 15);
            this.createdAt = createdAt;
            this.#encryptionBaseVector = encryptionBaseVector;
            this.#me = sender;
            this.#otherUser = recipient;
            this.#mySignKey = senderSign;
            this.#otherVerifyKey = recipientVerify;
            this.#currentRootKey = sharedRoot;
            this.#maxSkip = maxSkip;
            this.lastActivityTimestamp = lastActivity;
    }

    private async advanceFirstHalfDHRatchet(nextDHPublicKey: CryptoKey) {
        const dhReceivingChainInput = await crypto.deriveSymmetricBits(this.#currentDHRatchetKey, nextDHPublicKey, 256);
        const { nextRootKey, output: recvInput } = await this.rootChainKDFDerive(dhReceivingChainInput, this.#currentRootKey);
        this.#currentRootKey = nextRootKey;
        this.#currentReceivingChainKey = recvInput;
    }

    private async advanceSecondHalfDHRatchet(nextDHPublicKey: CryptoKey) {
        const nextRatchetKeyPair = await crypto.generateSignedKeyPair(this.#mySignKey);
        this.#currentDHRatchetKey = nextRatchetKeyPair.keyPair.privateKey;
        this.#currentDHPublishKey = crypto.exposeSignedKey(nextRatchetKeyPair);
        const dhSendingChainInput = await crypto.deriveSymmetricBits(this.#currentDHRatchetKey, nextDHPublicKey, 256); 
        const { nextRootKey, output: sendInput } = await this.rootChainKDFDerive(dhSendingChainInput, this.#currentRootKey);
        this.#currentRootKey = nextRootKey;
        this.#currentSendingChainKey = sendInput;
        this.#dhSendingRatchetNumber += 2;
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
        previousChainNumber: number,
        operation: (output: Buffer) => Promise<boolean>) {
            await this.advanceReversibly(async () => {
                let output: Buffer = null;
                const skippedKeys = new Map<[number, number], Buffer>();
                const ratchetDiff = sendingRatchetNumber - this.#dhReceivingRatchetNumber;
                const preChainDiff = previousChainNumber - this.#receivingChainNumber;
                const chainDiff = sendingChainNumber - this.#receivingChainNumber;
                if (ratchetDiff === 2) {
                    if (preChainDiff > 0) {
                        let moveChain = this.#receivingChainNumber;
                        while(moveChain < previousChainNumber) {
                            const output = await this.advanceSymmetricRatchet("Receiving");
                            moveChain += 1;
                            skippedKeys.set([sendingRatchetNumber - 2, moveChain], output);
                        }
                        this.#dhReceivingRatchetNumber += 2;
                        this.#receivingChainNumber = moveChain = 0;
                        await this.advanceDHRatchet(nextDHPublicKey);
                        while(moveChain < sendingChainNumber) {
                            output = await this.advanceSymmetricRatchet("Receiving");
                            moveChain += 1;
                            if (moveChain < sendingChainNumber) {
                                skippedKeys.set([sendingRatchetNumber, moveChain], output);
                            }
                        }
                    }
                }
                else if (ratchetDiff === 0) {
                    if (chainDiff > 0) {
                        let moveChain = this.#receivingChainNumber;
                        while(moveChain < sendingChainNumber) {
                            output = await this.advanceSymmetricRatchet("Receiving");
                            moveChain += 1;
                            if (moveChain < sendingChainNumber) {
                                skippedKeys.set([sendingRatchetNumber + 1, moveChain], output);
                            }
                        }
                    }
                }
                else {
                    const missedId: [number, number] = [sendingRatchetNumber, sendingChainNumber];
                    const missed = this.#skippedKeys.get(missedId);
                    if (!!missed) {
                        this.#skippedKeys.delete(missedId);
                        output = missed;
                    }
                }
                const success = await operation(output);
                if (success) {
                    for (const [key, value] of skippedKeys) {
                        this.#skippedKeys.set(key, value);
                    }
                }
                return success;
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

    private async rootChainKDFDerive(dhInput: Buffer, chainKey: Buffer): Promise<{ nextRootKey: Buffer, output: Buffer }> {
        const kdfOutput = await crypto.deriveHKDF(dhInput, chainKey, "Root Symmetric Ratchet", 512);
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

    private async advanceReversibly(advance: () => Promise<boolean>) {
        const currentRootKey = this.#currentRootKey;
        const currentDHRatchetKey = this.#currentDHRatchetKey;
        const currentDHPublishKey = this.#currentDHPublishKey;
        const currentSendingChainKey = this.#currentSendingChainKey;
        const currentReceivingChainKey = this.#currentReceivingChainKey;
        const dhSendingRatchetNumber = this.#dhSendingRatchetNumber;
        const dhReceivingRatchetNumber = this.#dhReceivingRatchetNumber;
        const sendingChainNumber = this.#sendingChainNumber;
        const receivingChainNumber = this.#receivingChainNumber;
        const previousSendingChainNumber = this.#previousSendingChainNumber;
        const success = await advance();
        if (!success) {
            this.#currentRootKey = currentRootKey;
            this.#currentDHRatchetKey = currentDHRatchetKey;
            this.#currentDHPublishKey = currentDHPublishKey;
            this.#currentSendingChainKey = currentSendingChainKey;
            this.#currentReceivingChainKey = currentReceivingChainKey;
            this.#dhSendingRatchetNumber = dhSendingRatchetNumber;
            this.#dhReceivingRatchetNumber = dhReceivingRatchetNumber;
            this.#sendingChainNumber = sendingChainNumber;
            this.#receivingChainNumber = receivingChainNumber;
            this.#previousSendingChainNumber = previousSendingChainNumber;
        }
    }

    private verifyMessageIntegrity(header: MessageHeader, body: MessageBody) {
        return header.timestamp === body.timestamp 
            && header.messageId === body.messageId
            && body.sender === this.#otherUser
            && body.recipient === this.#me;
    }

    async sendMessage(message: { content: string, timestamp: number, replyingTo?: string }, send: (messageHeader: MessageHeader) => Promise<boolean>): Promise<UserEncryptedData> {
        let success = false;
        await this.advanceReversibly(async () => {
            const { content, replyingTo, timestamp } = message;
            const messageKeyBits = await this.advanceSymmetricRatchet("Sending");
            const sender = this.#me;
            const recipient = this.#otherUser;
            const sessionId = this.sessionId;
            const receivingRatchetNumber = this.#dhReceivingRatchetNumber + 2;
            const sendingRatchetNumber = this.#dhSendingRatchetNumber;
            const sendingChainNumber = this.#sendingChainNumber;
            const previousChainNumber = this.#previousSendingChainNumber;
            const nextDHRatchetKey = this.#currentDHPublishKey;
            const messageId = `${sendingRatchetNumber}.${sendingChainNumber}`;
            let messageBody: MessageBody = { sender, recipient, messageId, timestamp, content };
            messageBody = replyingTo ? { ...messageBody, replyingTo } : messageBody;
            const { ciphertext, signature } = 
            await crypto.deriveSignEncrypt(messageKeyBits, serialize(messageBody), nullSalt(48), "Message Send|Receive", this.#mySignKey);
            const messageHeader = {
                addressedTo: recipient,
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
            success = await send(messageHeader);
            if (success) {
                this.lastActivityTimestamp = timestamp;
            }
            return success;
        });
        return success ? this.exportSession() : null;
    }

    async receiveMessage(messageHeader: MessageHeader, receive: (message: MessageBody | "Session Id Mismatch" | "Unverified Next Ratchet Key" | "Receving Ratchet Number Mismatch" | "Failed To Decrypt" | "Message Invalid") => Promise<boolean>): Promise<UserEncryptedData> {
        const {
            addressedTo,
            sessionId,
            sendingRatchetNumber,
            sendingChainNumber,
            previousChainNumber,
            nextDHRatchetKey,
            messageBody: { ciphertext, signature } } = messageHeader;
        if (sessionId !== this.sessionId || addressedTo !== this.#me ) {
            await receive("Session Id Mismatch");
            return null;
        }
        const nextDHPublicKey = await crypto.verifyKey(nextDHRatchetKey, this.#otherVerifyKey);
        if (!nextDHPublicKey) {
            await receive("Unverified Next Ratchet Key");
            return null;
        }
        let success = false;
        await this.ratchetToCurrentReceived(nextDHPublicKey, 
            sendingRatchetNumber, 
            sendingChainNumber, 
            previousChainNumber, 
            async (messageKeyBits) => {
                if (!messageKeyBits) {
                    await receive("Receving Ratchet Number Mismatch");
                    return false;
                }
                const plaintext = await crypto.deriveDecryptVerify(messageKeyBits, ciphertext, nullSalt(48), "Message Send|Receive", signature, this.#otherVerifyKey);
                let error = !plaintext ? "Decryption failed." : null;
                const message: MessageBody = !error ? deserialize(plaintext) : null;
                if (plaintext && !message) {
                    error = "Deserialization failed.";
                }
                if (error) {
                    console.log(error);
                    await receive("Failed To Decrypt");
                }
                else {
                    if (this.verifyMessageIntegrity(messageHeader, message)) {
                        success = await receive(message);
                    }
                    else {
                        await receive("Message Invalid");
                    }
                }
                if (success) {
                    this.lastActivityTimestamp = Date.now();
                }
                return success;
        });
        return success ? this.exportSession() : null;
    }
}