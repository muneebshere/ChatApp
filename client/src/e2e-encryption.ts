import { Buffer } from "./node_modules/buffer";
import BufferSerializer from "./custom_modules/buffer-serializer";
import * as crypto from "../../shared/cryptoOperator";
import { ExposedSignedPublicKey, SignedKeyPair, ExportedSignedKeyPair, ExportedSigningKeyPair, KeyBundle, EncryptedData, SignedEncryptedData, MessageHeader, Message, MessageRequestHeader, randomFunctions } from "../../shared/commonTypes";

const { getRandomVector, getRandomString } = randomFunctions();
const serializer = new BufferSerializer();
const serializeToB64 = (arg: any) => serialize(arg).toString("base64");
const deserializeFromB64 = (str: string) => deserialize(Buffer.from(str, "base64"));
const serializeMap = (map: Map<any, any>, bufferWriter: any) => {
    const entries = Array.from(map.entries())
        .map(([k, v]) => ({ key: serializeToB64(k), value: serializeToB64(v) }))
    serializer.toBufferInternal(serialize(entries), bufferWriter);
}
const deserializeMap = (bufferReader: any) => {
    const entries: Array<[any, any]> = deserialize(serializer.fromBufferInternal(bufferReader)).map(({ key, value }) => ([deserializeFromB64(key), deserializeFromB64(value)]));
    return new Map(entries);
}
serializer.register("Map", (value: any) => value instanceof Map, serializeMap, deserializeMap);
const serialize = serializer.toBuffer.bind(serializer);
const deserialize = serializer.fromBuffer.bind(serializer);

const nullSalt = (length: number) => Buffer.alloc(length);

type MessageRequestBody = { 
    readonly myKeySignature: string;
    readonly yourKeySignature: string;
    readonly myUsername: string;
    readonly yourUsername: string;
    readonly myDHRatchetInititalizer: ExposedSignedPublicKey;
    readonly timestamp: number;
    readonly firstMessage: string 
}

type MessageRequestInWaiting = {
    readonly timestamp: number;
    readonly sessionId: string;
    readonly recipient: string;
    readonly recipientVerifyKey: CryptoKey;
    readonly sharedRoot: Buffer;
    readonly myDHRatchetInitializer: CryptoKey;
}

type MessageBody = {
    readonly sender: string;
    readonly recipient: string;
    readonly messageId: string;
    readonly replyingTo?: string;
    readonly timestamp: number;
    readonly content: string;
}

type ExportedX3DHUser = {
    readonly username: string;
    readonly version: number;
    readonly minOneTimeKeys: number;
    readonly maxOneTimeKeys: number;
    readonly replaceKeyAtInMillis: number;
    readonly identitySigningKeyPair: ExportedSigningKeyPair;
    readonly identityDHKeyPair: ExportedSignedKeyPair;
    readonly signedPreKeyPair: ExportedSignedKeyPair;
    readonly signedOneTimeKeys: Map<string, [ExportedSignedKeyPair, number]>;
    readonly keyLastReplaced: number;
    readonly preKeyVersion: number
}

type ExportedChattingSession = {
    readonly sessionId: string;
    readonly createdAt: number;
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
    #identitySigningKeyPair: CryptoKeyPair;
    #identitySigningKey: CryptoKey;
    #identityDHKeyPair: SignedKeyPair;
    #signedPreKeyPair: SignedKeyPair;
    #signedOneTimeKeys = new Map<string, [SignedKeyPair, number]>();
    #waitingMessageRequests = new Map<string, MessageRequestInWaiting>();
    #keyLastReplaced: number = null;
    #preKeyVersion = 0;

    public get version() {
        return this.#version;
    }

    private constructor(username: string,
        version = 1,
        minOneTimeKeys = 10,
        maxOneTimeKeys = minOneTimeKeys,
        replaceKeyAtInDays = 7) {
            this.username = username;
            this.#version = version;
            this.#minOneTimeKeys = minOneTimeKeys;
            this.#maxOneTimeKeys = maxOneTimeKeys;
            this.#replaceKeyAtInMillis = replaceKeyAtInDays * 24 * 3600 * 1000;
    }

    async exportUser(encryptionKeyBits: Buffer): Promise<[EncryptedData, Buffer]> {
        await this.regularProtocolRun();
        const salt = getRandomVector(48);
        const username = this.username;
        const version = this.#version;
        const minOneTimeKeys = this.#minOneTimeKeys;
        const maxOneTimeKeys = this.#maxOneTimeKeys;
        const replaceKeyAtInMillis = this.#replaceKeyAtInMillis;
        const identitySigningKeyPair = await crypto.exportSigningKeyPair(this.#identitySigningKeyPair, encryptionKeyBits, salt, "X3DH User Identity");
        const identityDHKeyPair = await crypto.exportSignedKeyPair(this.#identityDHKeyPair, encryptionKeyBits, salt, "X3DH User Identity DH");
        const signedPreKeyPair = await crypto.exportSignedKeyPair(this.#signedPreKeyPair, encryptionKeyBits, salt, "X3DH User PreKey");
        const signedOneTimeKeys = new Map<string, [ExportedSignedKeyPair, number]>();
        for (const [id, [key, firstPublished]] of this.#signedOneTimeKeys.entries()) {
            signedOneTimeKeys.set(id, [await crypto.exportSignedKeyPair(key, encryptionKeyBits, salt, `X3DH User OneTimeKey ${id}`), firstPublished]);
        }
        const keyLastReplaced = this.#keyLastReplaced;
        const preKeyVersion = this.#preKeyVersion;
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
            keyLastReplaced,
            preKeyVersion };
        return [await crypto.deriveSignEncrypt(encryptionKeyBits, serialize(exportedUser), salt, "Export|Import X3DH User"), salt];
    }

    static async importUser(encryptedUser: EncryptedData, decryptionKeyBits: Buffer, salt: Buffer) : Promise<X3DHUser> {
        const { ciphertext } = encryptedUser
        const decryptedUser = await crypto.deriveDecryptVerify(decryptionKeyBits, ciphertext, salt, "Export|Import X3DH User");
        if (!decryptedUser) {
            return null;
        }
        try {
            const importedUser: ExportedX3DHUser = deserialize(decryptedUser);
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
                keyLastReplaced,
                preKeyVersion } = importedUser;
            const replaceKeyAtInDays = replaceKeyAtInMillis / (24 * 3600 * 1000);
            const user = new X3DHUser(username, version + 1, minOneTimeKeys, maxOneTimeKeys, replaceKeyAtInDays);
            user.#identitySigningKeyPair = await crypto.importSigningKeyPair(exportedidentityKeyPair, decryptionKeyBits, salt, "X3DH User Identity");
            user.#identityDHKeyPair = await crypto.importSignedKeyPair(exportedIdentityDHKeyPair, decryptionKeyBits, salt, "X3DH User Identity DH");
            user.#signedPreKeyPair = await crypto.importSignedKeyPair(exportedSignedPreKeyPair, decryptionKeyBits, salt, "X3DH User PreKey");
            const signedOneTimeKeys = new Map<string, [SignedKeyPair, number]>();
            for (const [id, [key, firstPublished]] of exportedSignedOneTimeKeys.entries()) {
                signedOneTimeKeys.set(id, [await crypto.importSignedKeyPair(key, decryptionKeyBits, salt, `X3DH User OneTimeKey ${id}`), firstPublished]);
            }
            user.#identitySigningKey = user.#identitySigningKeyPair.privateKey;
            user.#signedOneTimeKeys = signedOneTimeKeys;
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
        minOneTimeKeys = 10,
        maxOneTimeKeys = minOneTimeKeys,
        replaceKeyAtInDays = 7): Promise<X3DHUser> {
        const user = new X3DHUser(username, 1, minOneTimeKeys, maxOneTimeKeys, replaceKeyAtInDays);
        user.#identitySigningKeyPair = await crypto.generateKeyPair("ECDSA");
        user.#identitySigningKey = user.#identitySigningKeyPair.privateKey;
        user.#identityDHKeyPair = await crypto.generateSignedKeyPair(user.#identitySigningKey);
        await user.regularProtocolRun();
        return user;
    }

    async publishKeyBundles(forceClearEarly?: number): Promise<[{ defaultKeyBundle: KeyBundle, oneTimeKeyBundles: KeyBundle[] }, string[]]> {
        await this.regularProtocolRun();
        let clearedKeys: string[] = [];
        if (!!forceClearEarly && forceClearEarly > 0) {
            const toClear = Math.min(forceClearEarly, this.#signedOneTimeKeys.size);
            const firstPublishedMap = new Map(Array.from(this.#signedOneTimeKeys, ([id, [_, published]]) => [published, id] as [number, string]));
            const publishTimes = Array.from(firstPublishedMap.keys()).sort().slice(0, toClear);
            for (const publishTime of publishTimes) {
                const idToClear = firstPublishedMap.get(publishTime);
                clearedKeys.push(idToClear);
                this.#signedOneTimeKeys.delete(idToClear);
            }
        }
        const owner = this.username;
        const publicSigningIdentityKey = await crypto.exportKey(this.#identitySigningKeyPair.publicKey);
        const publicDHIdentityKey = await crypto.exposeSignedKey(this.#identityDHKeyPair);
        const publicSignedPreKey = await crypto.exposeSignedKey(this.#signedPreKeyPair);
        const preKeyVersion = this.#preKeyVersion;
        const oneTimeKeyBundles: KeyBundle[] = [];
        for (const [identifier, [oneTimeKey, published]] of this.#signedOneTimeKeys.entries()) {
            const publicOneTimeKey = await crypto.exposeSignedKey(oneTimeKey);
            if (!published) {
                this.#signedOneTimeKeys.set(identifier, [oneTimeKey, Date.now()]);
            }
            oneTimeKeyBundles.push({ identifier, owner, verifyingIdentityKey: publicSigningIdentityKey, publicDHIdentityKey, publicSignedPreKey, publicOneTimeKey, preKeyVersion });
        }
        const defaultKeyBundle = { identifier: `${preKeyVersion}`, owner, verifyingIdentityKey: publicSigningIdentityKey, publicDHIdentityKey, publicSignedPreKey, preKeyVersion };
        const bundles = { defaultKeyBundle, oneTimeKeyBundles };
        return [bundles, clearedKeys];
    }

    async generateMessageRequest(keyBundle: KeyBundle, firstMessage: string): Promise<MessageRequestHeader | "Invalid Identity Signature" | "Invalid PreKey Signature" | "Invalid OneTimeKey Signature"> {
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
        if (publicOneTimeKey !== undefined) {
            importedOneTimeKey = await crypto.verifyKey(publicOneTimeKey, importedVerifyingIdentityKey);
            if (!importedOneTimeKey) {
                return "Invalid OneTimeKey Signature";
            }
            yourOneTimeKeyIdentifier = identifier;
        }
        const ephemeralKeyPair = await crypto.generateSignedKeyPair(this.#identitySigningKey);
        const myPublicEphemeralKey = await crypto.exposeSignedKey(ephemeralKeyPair);
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
        const myDHRatchetInititalizer = await crypto.exposeSignedKey(dhRatchetInitializer);
        const timestamp = Date.now();
        const initialData: MessageRequestBody = { 
            myKeySignature, 
            yourKeySignature, 
            myUsername, 
            yourUsername, 
            myDHRatchetInititalizer,
            timestamp,
            firstMessage };
        const initialCiphertext = await crypto.deriveSignEncrypt(buffConcat, serialize(initialData), nullSalt(48), "Message Request", this.#identitySigningKey);
        const myPublicSigningIdentityKey = await crypto.exportKey(this.#identitySigningKeyPair.publicKey);
        const myPublicDHIdentityKey = await crypto.exposeSignedKey(this.#identityDHKeyPair);
        const initialMessage = {
            addressedTo: myUsername,
            myVerifyingIdentityKey: myPublicSigningIdentityKey,
            myPublicDHIdentityKey,
            myPublicEphemeralKey,
            yourSignedPreKeyVersion: preKeyVersion,
            yourOneTimeKeyIdentifier,
            initialMessage: initialCiphertext };
        const sessionId = getRandomString();
        const waitingRequest = {
            timestamp, 
            sessionId, 
            recipient: yourUsername, 
            recipientVerifyKey: importedVerifyingIdentityKey, 
            sharedRoot: buffConcat, 
            myDHRatchetInitializer: dhRatchetInitializer.keyPair.privateKey };
        this.#waitingMessageRequests.set(sessionId, waitingRequest);
        return initialMessage;
    }

    async acceptMessageRequest(initialMessage: MessageRequestHeader, maxSkip = 20)
        : Promise<[[number, string], ChattingSession] | "Incorrectly Addressed" | "PreKey Version Mismatch" | "OneTimeKey Not Found" | "Invalid Identity Signature" | "Invalid Ephemeral Signature" | "Failed To Decrypt Message" | "Problem With Decrypted Message" | "Unknown Error"> {
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
            if (!myOneTimeKeyIdentifier !== undefined) {
                const oneTime = this.#signedOneTimeKeys.get(myOneTimeKeyIdentifier);
                if (oneTime !== undefined) {
                    oneTimeKey = oneTime[0];
                }
                else {
                    return "OneTimeKey Not Found";
                }
            }
            if (oneTimeKey !== undefined) {
                this.#signedOneTimeKeys.delete(myOneTimeKeyIdentifier);
                await this.regularProtocolRun();
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
                const buffConcat = Buffer.concat(dh4 === undefined ? [dh1, dh2, dh3] : [dh1, dh2, dh3, dh4]);
                const plaintext = await crypto.deriveDecryptVerify(buffConcat, ciphertext, nullSalt(48), "Message Request", signature, importedVerifyingIdentityKey);
                if (!plaintext) {
                    return "Failed To Decrypt Message";
                }
                const message: MessageRequestBody = deserialize(plaintext);
                const { myKeySignature: yourKeySignature, 
                    yourKeySignature: myKeySignature, 
                    myUsername: otherUser, 
                    yourUsername: myUsername, 
                    timestamp,
                    firstMessage, 
                    myDHRatchetInititalizer: dhRatchetInitializer } = message;
                const importedDHInitializer = await crypto.verifyKey(dhRatchetInitializer, importedVerifyingIdentityKey);
                if ( (myKeySignature as string) !== this.#identityDHKeyPair.signature.toString("base64") 
                || (yourKeySignature as string) !== otherPublicDHIdentityKey.signature.toString("base64")
                || !otherUser
                || !importedDHInitializer
                || (myUsername as string) !== this.username) {
                    return "Problem With Decrypted Message";
                }
                return [[timestamp, firstMessage], 
                    await ChattingSession.new(timestamp,
                        myUsername, 
                        otherUser, 
                        this.#identitySigningKeyPair.privateKey,
                        importedVerifyingIdentityKey,
                        buffConcat,
                        maxSkip,
                        importedDHInitializer)];
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

    async receiveMessageRequestResponse(response: MessageHeader, maxSkip = 20): Promise<[ ChattingSession, MessageBody ]> {
        const { sessionId } = response;
        const waitingDetails = this.#waitingMessageRequests.get(sessionId);
        if (!waitingDetails) {
            return null;
        }
        const {
            timestamp,
            recipient,
            recipientVerifyKey,
            sharedRoot,
            myDHRatchetInitializer } = waitingDetails;
        const chattingSession = await ChattingSession.new(timestamp, 
            this.username, 
            recipient, 
            this.#identitySigningKey,
            recipientVerifyKey,
            sharedRoot,
            maxSkip,
            myDHRatchetInitializer);
        const messageBody = await chattingSession.receiveMessage(response);
        if (typeof messageBody !== "string") {
            return [chattingSession, messageBody];
        }
        return null;
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
        const currentKeys = this.#signedOneTimeKeys.size;
        if (currentKeys >= this.#maxOneTimeKeys) {
            return;
        }
        if (generateMinKeys && currentKeys >= this.#minOneTimeKeys) {
            return;
        }
        for (let k = 0; k < (this.#maxOneTimeKeys - currentKeys); k++) {
            const identifier = `${getRandomString()}-${Date.now()}`;
            const signedPair = await crypto.generateSignedKeyPair(this.#identitySigningKey);
            this.#signedOneTimeKeys.set(identifier, [signedPair, null]);
        }
    }

    private async importVerifyingKey(verifyingKey: Buffer) {
        return await crypto.importKey(verifyingKey, "ECDSA", "public", true);
    }
}

export class ChattingSession {
    readonly sessionId: string;
    readonly createdAt: number;
    readonly #sender: string;
    readonly #recipient: string;
    readonly #maxSkip: number;
    readonly #senderSignKey: CryptoKey;
    readonly #recipientVerifyKey: CryptoKey;
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

    async exportSession(encryptionKeyBits: Buffer): Promise<[EncryptedData, Buffer]> {
        const salt = getRandomVector(48);
        const sessionId = this.sessionId;
        const createdAt = this.createdAt;
        const sender = this.#sender;
        const recipient = this.#recipient;
        const maxSkip = this.#maxSkip;
        const signingKeyPair = {
            publicKey: this.#recipientVerifyKey,
            privateKey: this.#senderSignKey };
        const senderSignRecipientVerifyKeys = await crypto.exportSigningKeyPair(signingKeyPair, encryptionKeyBits, salt, "Identity");
        const currentRootKey = this.#currentRootKey;
        const currentDHRatchetKey = await crypto.deriveWrap(encryptionKeyBits, this.#currentDHRatchetKey, salt, "DH Ratchet Key");
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
        return [await crypto.deriveSignEncrypt(encryptionKeyBits, serialize(exportedSession), salt, "Export|Import Chatting Session"), salt];
    }

    static async importSession(encryptedSession: EncryptedData, decryptionKeyBits: Buffer, salt: Buffer) : Promise<ChattingSession> {
        const { ciphertext } = encryptedSession;
        const decryptedSession = await crypto.deriveDecryptVerify(decryptionKeyBits, ciphertext, salt, "Export|Import Chatting Session");
        if (!decryptedSession) {
            return null;
        }
        try {
            const {
                createdAt,
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
                skippedKeys }: ExportedChattingSession = deserialize(decryptedSession);
            const { publicKey, privateKey } = await crypto.importSigningKeyPair(senderSignRecipientVerifyKeys, decryptionKeyBits, salt, "Identity");
            const unwrappedRatchetKey = await crypto.deriveUnwrap(decryptionKeyBits, currentDHRatchetKey, salt, "ECDH", "DH Ratchet Key", true);
            const exportedSession = new ChattingSession(createdAt, sender, recipient, privateKey, publicKey, currentRootKey, maxSkip);
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

    private constructor(createdAt: number,
        sender: string,
        recipient: string,
        senderSign: CryptoKey,
        recipientVerify: CryptoKey,
        sharedRoot: Buffer,
        maxSkip: number) {
            this.sessionId = sharedRoot.toString("base64").slice(0, 15);
            this.createdAt = createdAt;
            this.#sender = sender;
            this.#recipient = recipient;
            this.#senderSignKey = senderSign;
            this.#recipientVerifyKey = recipientVerify;
            this.#currentRootKey = sharedRoot;
            this.#maxSkip = maxSkip;
    }
    
    static async new(createdAt: number,
        sender: string,
        recipient: string,
        senderSign: CryptoKey,
        recipientVerify: CryptoKey,
        sharedRoot: Buffer,
        maxSkip: number,
        dhRatchetOtherPublic: CryptoKey,
        dhRatcherMyPrivate: CryptoKey = null): Promise<ChattingSession> {
            const amAcceptor = !dhRatcherMyPrivate;
            const chattingSession = new ChattingSession(createdAt, sender, recipient, senderSign, recipientVerify, sharedRoot, maxSkip);
            chattingSession.#receivingChainNumber = amAcceptor ? -1 : 0;
            chattingSession.#sendingChainNumber = amAcceptor ?-2 : -1;
            if (!amAcceptor) {
                chattingSession.#currentDHRatchetKey = dhRatcherMyPrivate;
                chattingSession.advanceFirstHalfDHRatchet(dhRatchetOtherPublic);
            }
            chattingSession.advanceSecondHalfDHRatchet(dhRatchetOtherPublic);
            return chattingSession;
    }

    private async advanceFirstHalfDHRatchet(nextDHPublicKey: CryptoKey) {
        const dhReceivingChainInput = await crypto.deriveSymmetricBits(this.#currentDHRatchetKey, nextDHPublicKey, 256);
        const { nextRootKey, output: recvInput } = await this.rootChainKDFDerive(dhReceivingChainInput, this.#currentRootKey);
        this.#currentRootKey = nextRootKey;
        this.#currentReceivingChainKey = recvInput;
    }

    private async advanceSecondHalfDHRatchet(nextDHPublicKey: CryptoKey) {
        const nextRatchetKeyPair = await crypto.generateSignedKeyPair(this.#senderSignKey);
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

    async sendMessage(content: string, replyingTo?: string): Promise<[MessageHeader, string]> {
        const messageKeyBits = await this.advanceSymmetricRatchet("Sending");
        const sender = this.#sender;
        const recipient = this.#recipient;
        const sessionId = this.sessionId;
        const receivingRatchetNumber = this.#dhReceivingRatchetNumber + 2;
        const sendingRatchetNumber = this.#dhSendingRatchetNumber;
        const sendingChainNumber = this.#sendingChainNumber;
        const previousChainNumber = this.#previousSendingChainNumber;
        const nextDHRatchetKey = this.#currentDHPublishKey;
        const messageId = `${sendingRatchetNumber}|${sendingChainNumber}`;
        const timestamp = Date.now();
        let messageBody: MessageBody = { sender, recipient, messageId, timestamp, content };
        messageBody = replyingTo ? { ...messageBody, replyingTo } : messageBody;
        const { ciphertext, signature } = 
        await crypto.deriveSignEncrypt(messageKeyBits,serialize(messageBody), nullSalt(48), "Message Send|Receive", this.#senderSignKey);
        return [{
            addressedTo: recipient,
            sessionId,
            receivingRatchetNumber,
            sendingRatchetNumber,
            sendingChainNumber,
            previousChainNumber,
            nextDHRatchetKey,
            messageBody: {
                ciphertext,
                signature
            }
        }, messageId]
    }

    async receiveMessage(messageHeader: MessageHeader): 
    Promise<MessageBody | "Session Id Mismatch" | "Unverified Next Ratchet Key" | "Receving Ratchet Number Mismatch" | "Failed To Decrypt" | "Unknown Error"> {
        try {
            const {
                addressedTo,
                sessionId,
                sendingRatchetNumber,
                sendingChainNumber,
                previousChainNumber,
                nextDHRatchetKey,
                messageBody: { ciphertext, signature } } = messageHeader;
            if (sessionId !== this.sessionId || addressedTo !== this.#sender ) {
                return "Session Id Mismatch";
            }
            const nextDHPublicKey = await crypto.verifyKey(nextDHRatchetKey, this.#recipientVerifyKey);
            if (!nextDHPublicKey) {
                return "Unverified Next Ratchet Key";
            }
            const messageKeyBits = await this.ratchetToCurrentReceived(nextDHPublicKey, sendingRatchetNumber, sendingChainNumber, previousChainNumber);
            if (!messageKeyBits) {
                return "Receving Ratchet Number Mismatch";
            }
            const plaintext = await crypto.deriveDecryptVerify(messageKeyBits, ciphertext, nullSalt(48), "Message Send|Receive", signature, this.#recipientVerifyKey);
            if (!plaintext) {
                return "Failed To Decrypt";
            }
            const message: MessageBody = deserialize(plaintext);
            if (!message) {
                return "Failed To Decrypt";
            }
            return message;
        }
        catch(err) {
            console.log(`${err}`);
            return "Unknown Error";
        }
    }

    private async ratchetToCurrentReceived(nextDHPublicKey: CryptoKey, 
        sendingRatchetNumber: number, 
        sendingChainNumber: number, 
        previousChainNumber: number) {
        let output: Buffer = null;
        const ratchetDiff = sendingRatchetNumber - this.#dhReceivingRatchetNumber;
        const preChainDiff = previousChainNumber - this.#receivingChainNumber;
        const chainDiff = sendingChainNumber - this.#receivingChainNumber;
        const ratchetAhead = ratchetDiff === 2;
        const noRatchetAhead = ratchetDiff === 0;
        if (ratchetAhead) {
            if (preChainDiff > 0) {
                let moveChain = this.#receivingChainNumber;
                while(moveChain < previousChainNumber) {
                    const output = await this.advanceSymmetricRatchet("Receiving");
                    moveChain += 1;
                    this.#skippedKeys.set([sendingRatchetNumber - 2, moveChain], output);
                }
                this.#dhReceivingRatchetNumber += 2;
                this.#receivingChainNumber = moveChain = 0;
                await this.advanceDHRatchet(nextDHPublicKey);
                while(moveChain < sendingChainNumber) {
                    output = await this.advanceSymmetricRatchet("Receiving");
                    moveChain += 1;
                    if (moveChain < sendingChainNumber) {
                        this.#skippedKeys.set([sendingRatchetNumber, moveChain], output);
                    }
                }
            }
        }
        if (noRatchetAhead) {
            if (chainDiff > 0) {
                let moveChain = this.#receivingChainNumber;
                while(moveChain < sendingChainNumber) {
                    output = await this.advanceSymmetricRatchet("Receiving");
                    moveChain += 1;
                    if (moveChain < sendingChainNumber) {
                        this.#skippedKeys.set([sendingRatchetNumber + 1, moveChain], output);
                    }
                }
            }
        }
        if (!output) {
            const missedId: [number, number] = [sendingRatchetNumber, sendingChainNumber];
            const missed = this.#skippedKeys.get(missedId);
            if (!missed) {
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

}

export class Chat {
    readonly sessionId: string;
    readonly #chattingSession: ChattingSession;
    readonly #recentChat: Message[];
    
    private constructor(chattingSession: ChattingSession, chatHistory: Message[]) {
        this.#chattingSession = chattingSession;
        this.sessionId = chattingSession.sessionId;
        this.#recentChat = chatHistory;
    }

    static new(chattingSession: ChattingSession, firstMessage: Message, secondMessage: Message = null): Chat {
        const history = [firstMessage];
        if (secondMessage ) {
            history.push(secondMessage);
        }
        return new Chat(chattingSession, history);
    }

    static async importChat(encryptedSession: SignedEncryptedData, decryptionKeyBits: Buffer, hSalt: Buffer): Promise<Chat> {
        try {
            const chattingSession = await ChattingSession.importSession(encryptedSession, decryptionKeyBits, hSalt);
            if (!chattingSession) {
                return null;
            }
            return new Chat(chattingSession, []);
        }
        catch(err) {
            console.log(`${err}`);
            return null;
        }
    }

    async exportChat(encryptionKeyBits: Buffer): Promise<{ chattingSession: EncryptedData, sessionSalt: Buffer, chatBundle: { bundleId: string, messageIds: string[], chatBundle: EncryptedData }, chatSalt: Buffer }> {
        try {
            const [chattingSession, sessionSalt] = await this.#chattingSession.exportSession(encryptionKeyBits);
            if (!chattingSession) {
                return null;
            }
            const chatSalt = getRandomVector(32);
            const chatBundle = await crypto.deriveSignEncrypt(encryptionKeyBits, serialize(this.#recentChat), chatSalt, "Export|Import Chat History");
            const bundleId = Buffer.from(chatSalt.subarray(0, 10)).toString("base64");
            const messageIds = Array.from(this.#recentChat.map(m => m.messageId));
            return { chattingSession, sessionSalt, chatBundle: { bundleId, messageIds, chatBundle }, chatSalt };
        }
        catch(err) {
            console.log(`${err}`);
            return null;
        }
    }

    async sendMessage(content: string, replyingTo?: string): Promise<MessageHeader> {
        const [messageHeader, messageId] = await this.#chattingSession.sendMessage(content, replyingTo);
        let newMessage: Message = { sentByMe: true, timestamp: Date.now(), content, messageId, read: false, delivered: false };
        newMessage = replyingTo ? { ...newMessage, replyingTo } : newMessage;
        this.#recentChat.push(newMessage);
        return messageHeader;
    }

    async receiveMessage(messageHeader: MessageHeader): 
    Promise<Message | "Session Id Mismatch" | "Unverified Next Ratchet Key" | "Receving Ratchet Number Mismatch" | "Failed To Decrypt" | "Unknown Error"> {
        const receivedMessage = await this.#chattingSession.receiveMessage(messageHeader);
        if (typeof receivedMessage === "string") {
            return receivedMessage;
        }
        const { messageId,
            replyingTo,
            timestamp,
            content } = receivedMessage;
        let newMessage: Message = { sentByMe: false, timestamp, content, messageId, read: false, delivered: Date.now() };
        newMessage = replyingTo ? { ...newMessage, replyingTo } : newMessage;
        this.#recentChat.push(newMessage);
        return newMessage;
    }

    async exportMessages(encryptionKeyBits: Buffer): Promise<{ chatBundle: { bundleId: string, messageIds: string[], chatBundle: EncryptedData }, chatSalt: Buffer }> {
        try {
            const chatSalt = getRandomVector(32);
            const ciphertext = await crypto.deriveDecryptVerify(encryptionKeyBits, serialize(this.#recentChat), chatSalt, "Export|Import Chat History");
            const bundleId = getRandomString();
            const messageIds = Array.from(this.#recentChat.map(m => m.messageId));
            this.#recentChat.length = 0;
            return { chatBundle: { bundleId, messageIds, chatBundle: { ciphertext } }, chatSalt };
        }
        catch(err) {
            console.log(`${err}`);
            return null;
        }
    }
}
