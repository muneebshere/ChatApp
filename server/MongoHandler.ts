import _ from "lodash";
import { Binary, DeleteResult } from "mongodb";
import * as mongoose from "mongoose";
import { Schema } from "mongoose";
import { ChatData, KeyBundle, MessageHeader, ChatRequestHeader, PasswordEncryptedData, PublishKeyBundlesRequest, StoredMessage, RegisterNewUserRequest, NewUserData, UserEncryptedData, Receipt, Backup, ChatSessionDetails, Username } from "../shared/commonTypes";
import * as crypto from "../shared/cryptoOperator";
import { parseIpReadable } from "./backendserver";
import { allSettledResults, logError } from "../shared/commonFunctions";

const exposedSignedKey = {
    exportedPublicKey: {
        type: Schema.Types.Buffer,
        required: true
    },
    signature: {
        type: Schema.Types.Buffer,
        required: true
    }
};

const signedEncryptedData = {
    ciphertext: {
        type: Schema.Types.Buffer,
        required: true
    },
    signature: {
        type: Schema.Types.Buffer,
        required: true
    }
};

const userEncryptedData = {
    ciphertext: {
        type: Schema.Types.Buffer,
        required: true
    },
    hSalt: {
        type: Schema.Types.Buffer,
        required: true
    }
};

const passwordEncryptedData = {
    ciphertext: {
        type: Schema.Types.Buffer,
        required: true
    },
    hSalt: {
        type: Schema.Types.Buffer,
        required: true
    },
    pSalt: {
        type: Schema.Types.Buffer,
        required: true
    },
    iterSeed: {
        type: Schema.Types.Number,
        required: true
    }
};

export class MongoHandlerCentral {

    private static readonly keyBundleSchema = new Schema({
        owner: {
            type: Schema.Types.String,
            required: true
        },
        identifier: {
            type: Schema.Types.String,
            required: true
        },
        preKeyVersion: {
            type: Schema.Types.Number,
            required: true
        },
        verifyingIdentityKey: {
            type: Schema.Types.Buffer,
            required: true
        },
        publicDHIdentityKey: exposedSignedKey,
        publicSignedPreKey: exposedSignedKey,
        publicOneTimeKey: {
            exportedPublicKey: {
                type: Schema.Types.Buffer,
                required: false
            },
            signature: {
                type: Schema.Types.Buffer,
                required: false
            }
        }
    });

    private static readonly ServerData = mongoose.model("ServerData", new Schema({
        serverIdentitySigningKey: {
            type: Schema.Types.Buffer,
            required: true,
            immutable: true,
            unique: true
        },
        serverIdentityVerifyingKey: {
            type: Schema.Types.Buffer,
            required: true,
            immutable: true,
            unique: true
        }
    }), "server_data");

    private static readonly DatabaseAccessKey = mongoose.model("DatabaseAccessKey", new Schema({
        username: {
            type: Schema.Types.String,
            required: true,
            immutable: true,
            lowercase: true,
            trim: true,
            minLength: 3,
            maxLength: 15,
            match: /^[a-z0-9_]{3,15}$/
        },
        type: {
            type: Schema.Types.String,
            required: true,
            immutable: true,
            enum: ["root", "chat", "session"]
        },
        accessKey: {
            type: Schema.Types.Buffer,
            required: true,
            immutable: true
        }
    }).pre("validate", async function(next) {
        if (!this.isNew) next(new Error("Cannot modify record."));
        else {
            const previousKeys = await MongoHandlerCentral.DatabaseAccessKey.find({ username: this.username });
            if (previousKeys.length === 0 && this.type !== "root") next(new Error("First access key created must be of type 'root'."));
            else if (previousKeys.length > 0 && this.type === "root") next(new Error("Cannot create another root key."));
            else next();
        }
    }), "database_access_keys");

    private static readonly RegisteredSession = mongoose.model("RegisteredSession", new Schema({
        sessionId: {
            type: Schema.Types.String,
            required: true,
            immutable: true,
            unique: true
        },
        alias1: {
            type: Schema.Types.String,
            required: true,
            immutable: true
        },
        alias2: {
            type: Schema.Types.String,
            required: true,
            immutable: true
        },
        locked: {
            type: Schema.Types.Boolean,
            required: true,
            default: false
        }
    }).pre("validate", function(next) {
        if (this.alias1 === this.alias2) next(new Error("Both aliases cannot be the same."));
        else if (this.isNew && this.locked) next(new Error("Cannot create a registered session locked at the beginning."));
        else if (!this.isNew && !this.locked) next(new Error("Cannot unlock registered session."));
        else next();
    }), "registered_sessions");

    private static readonly RegistrationPendingSession = mongoose.model("RegistrationPendingSession", new Schema({
        sessionId: {
            type: Schema.Types.String,
            required: true,
            immutable: true,
            unique: true
        },
        toAlias: {
            type: Schema.Types.String,
            required: true,
            immutable: true
        },
        fromAlias: {
            type: Schema.Types.String,
            required: true,
            immutable: true
        },
        initiatorAccessKey: {
            type: Schema.Types.Buffer,
            required: true,
            immutable: true
        },
        acceptorAccessKey: {
            type: Schema.Types.Buffer,
            default: null
        },
        registeredAt: {
            type: Schema.Types.Date,
            default: new Date(),
            immutable: true,
            expires: 30 * 24 * 60 * 60
        }
    }).pre("validate", async function(next) {
        if (this.isNew) this.registeredAt = new Date();
        if (this.toAlias === this.fromAlias) next(new Error("Both aliases cannot be the same."));
        else if (this.isNew && this.acceptorAccessKey) next(new Error("Cannot add acceptorAccessKey to new record."));
        else if (!this.isNew) {
            const prevAcceptor = (await MongoHandlerCentral.RegistrationPendingSession.findOne({ sessionId: this.sessionId }).lean()).acceptorAccessKey;
            if (prevAcceptor) next(new Error("Cannot modify once acceptorAccessKey is set."));
            else if (!prevAcceptor && !this.acceptorAccessKey) next(new Error("Must add acceptorAccessKey on modify."));
            else next();
        }
        else next();
    }), "registration_pending_sessions");

    private static readonly SavedAuth = mongoose.model("SavedAuth", new Schema({
        saveToken: {
            type: Schema.Types.String,
            required: true,
            immutable: true,
            unique: true
        },
        ipRep: {
            type: Schema.Types.String,
            required: true,
            immutable: true,
            unique: true
        },
        ipRead: {
            type: Schema.Types.String,
            required: true,
            immutable: true,
            unique: true
        },
        savedAuthDetails: userEncryptedData,
        createdAt: {
            type: Schema.Types.Date,
            immutable: true,
            default: new Date(),
            expires: 10 * 24 * 60 * 60
        }
    }).pre("validate", function(next) { 
        if (this.isNew) this.ipRead = parseIpReadable(this.ipRep);
        this.createdAt = new Date();
        next(); 
    }), "saved_auth");

    private static readonly User = mongoose.model("User_", new Schema({
        username: {
            type: Schema.Types.String,
            required: true,
            immutable: true,
            unique: true,
            lowercase: true,
            trim: true,
            minLength: 3,
            maxLength: 15,
            match: /^[a-z0-9_]{3,15}$/
        },
        clientIdentityVerifyingKey: {
            type: Schema.Types.Buffer,
            required: true
        },
        verifierPointHex: {
            type: Schema.Types.String,
            required: true
        },
        verifierSalt: {
            type: Schema.Types.Buffer,
            required: true
        },
        userData: {
            encryptionBase: passwordEncryptedData,
            serverIdentityVerifyingKey: passwordEncryptedData,
            clientIdentitySigningKey: passwordEncryptedData,
            profileData: userEncryptedData,
            x3dhInfo: userEncryptedData,
            chatsData: userEncryptedData
        },
        databaseAuthKey: passwordEncryptedData,
        keyBundles: {
            defaultKeyBundle: {
                type: this.keyBundleSchema,
                required: true
            },
            oneTimeKeyBundles: {
                type: [this.keyBundleSchema],
                required: false,
                default: []
            },
        }
    }), "users");

    private static readonly UserRetries = mongoose.model("UserRetries", new Schema({
        username: {
            type: Schema.Types.String,
            required: true,
            immutable: true,
            lowercase: true,
            trim: true,
            minLength: 3,
            maxLength: 15,
            match: /^[a-z0-9_]{3,15}$/
        },
        tries: {
            type: Schema.Types.Number,
            required: true,
            min: 1
        },
        allowsAt: {
            type: Schema.Types.Number,
            required: true,
            default: null
        },
        ipRep: {
            type: Schema.Types.String,
            required: true,
            immutable: true,
        },
        ipRead: {
            type: Schema.Types.String,
            required: true,
            immutable: true,
        }
    }).index({ username: 1, ipRep: 1 }, { unique: true })
    .pre("validate", function(next) { 
        if (this.isNew) this.ipRead = parseIpReadable(this.ipRep);
        next(); 
    }), "user_retries");

    private static readonly ChatRequest = mongoose.model("ChatRequest", new Schema({
        addressedTo: {
            type: Schema.Types.String,
            required: true
        },
        headerId: {
            type: Schema.Types.String,
            required: true,
            unique: true
        },
        myVerifyingIdentityKey: {
            type: Schema.Types.Buffer,
            required: true
        },
        myPublicDHIdentityKey: exposedSignedKey,
        myPublicEphemeralKey: exposedSignedKey,
        yourOneTimeKeyIdentifier: {
            type: Schema.Types.String,
            required: false,
            unique: true
        },
        yourSignedPreKeyVersion: {
            type: Schema.Types.Number,
            required: true
        },
        initialMessage: signedEncryptedData
    }).index({ addressedTo: "hashed" }), "chat_requests");

    private static readonly MessageHeader = mongoose.model("MessageHeader", new Schema({
        sessionId: {
            type: Schema.Types.String,
            required: true
        },
        fromAlias: {
            type: Schema.Types.String,
            required: true
        },
        toAlias: {
            type: Schema.Types.String,
            required: true
        },
        headerId: {
            type: Schema.Types.String,
            required: true
        },
        receivingRatchetNumber: {
            type: Schema.Types.Number,
            required: true
        },
        sendingRatchetNumber: {
            type: Schema.Types.Number,
            required: true
        },
        sendingChainNumber: {
            type: Schema.Types.Number,
            required: true
        },
        previousChainNumber: {
            type: Schema.Types.Number,
            required: true
        },
        nextDHRatchetKey: exposedSignedKey,
        messageBody: signedEncryptedData
    }).index({ sessionId: 1, toAlias: 1 }).index({ sessionId: 1, headerId: 1 }, { unique: true }).index({ sendingRatchetNumber: 1, sendingChainNumber: 1 }, { unique: true }), "message_headers");

    private static readonly Receipt = mongoose.model("Receipt", new Schema({
        toAlias: {
            type: Schema.Types.String,
            required: true
        },
        sessionId: {
            type: Schema.Types.String,
            required: true
        },
        headerId: {
            type: Schema.Types.String,
            required: true
        },
        signature: {
            type: Schema.Types.String,
            required: true
        },
        bounced: {
            type: Schema.Types.Boolean,
            required: true
        }
    }).index({ sessionId: 1, toAlias: 1 }).index({ sessionId: 1, headerId: 1 }, { unique: true }), "receipts");

    private static readonly Chat = mongoose.model("Chat", new Schema({
        chatId: {
            type: Schema.Types.String,
            required: true,
            unique: true
        },
        chatDetails: userEncryptedData,
        exportedChattingSession: userEncryptedData
    }), "chats");

    private static readonly Message = mongoose.model("Message", new Schema({
        chatId: {
            type: Schema.Types.String,
            required: true
        },
        hashedId: {
            type: Schema.Types.String,
            required: true
        },
        timemark: {
            type: Schema.Types.Number,
            required: true
        },
        content: userEncryptedData
    }).index({ chatId: 1, timemark: -1 }).index({ chatId: 1, hashedId: 1 }, { unique: true }), "messages");

    private static readonly Backup =  mongoose.model("Backup", new Schema({
        byAlias: {
            type: Schema.Types.String,
            required: true
        },
        sessionId: {
            type: Schema.Types.String,
            required: true
        },
        headerId: {
            type: Schema.Types.String,
            required: true
        },
        content: userEncryptedData
    }).index({ byAlias: 1, sessionId: 1, headerId: 1 }, { unique: true }), "backups");

    static onError: () => void;

    static async connect(url: string, options?: mongoose.ConnectOptions) {
        const mong = await mongoose.connect(url, { ...options, keepAlive: true, keepAliveInitialDelay: 300000, serverSelectionTimeoutMS: 3000000, connectTimeoutMS: 3000000, socketTimeoutMS: 3000000, maxIdleTimeMS: 3000000 });
        if (!this.onError) {
            this.onError = () => {
                MongoHandlerCentral.connect(url, options);
            };
        }
        mong.connection.on("error", this.onError);
    }

    static async setupIdentity() {
        const serverData = await this.ServerData.find();
        if (serverData.length === 0) {
            const keyPair = await crypto.generateKeyPair("ECDSA");
            const serverIdentitySigningKey = await crypto.exportKey(keyPair.privateKey);
            const serverIdentityVerifyingKey = await crypto.exportKey(keyPair.publicKey);
            this.ServerData.create({ serverIdentitySigningKey, serverIdentityVerifyingKey });
            return keyPair;
        }
        else {
            const { serverIdentitySigningKey, serverIdentityVerifyingKey } = serverData[0];
            const privateKey = await crypto.importKey(serverIdentitySigningKey, "ECDSA", "private", false);
            const publicKey = await crypto.importKey(serverIdentityVerifyingKey, "ECDSA", "public", true);
            return { privateKey, publicKey };
        }
    }

    static async createNewUser(user: Omit<RegisterNewUserRequest, "clientEphemeralPublicHex"> & NewUserData, databaseAuthKey: CryptoKey) {
        try {
            const { username } = user;
            if ((await this.DatabaseAccessKey.find({ username, type: "root" })).length > 0) return false;
            const accessKey = (await crypto.deriveEncrypt({ username }, databaseAuthKey, "DatabaseRootAccessKey", Buffer.alloc(32))).ciphertext;
            const accessRoot = new this.DatabaseAccessKey({ username, type: "root", accessKey });
            if (accessRoot !== await accessRoot.save()) return false;
            const newUser = new this.User(user);
            if (newUser !== await newUser.save()) return false;
            else return true;
        }
        catch (err) {
            logError(err);
            return false;
        }
    }

    static async userExists(username: string) {
        return !!(await this.User.findOne({ username }));
    }

    static async getLeanUser(username: string): Promise<any> {
        const user = cleanLean(await this.User.findOne({ username }).lean());
        return user;
    }

    static async getKeyBundle(username: string): Promise<KeyBundle> {
        const otherUser = await MongoHandlerCentral.User.findOne({ username });
        if (!otherUser) return null;
        let keyBundle: KeyBundle;
        let saveRequired = false;
        const { oneTimeKeyBundles, defaultKeyBundle } = otherUser?.keyBundles;
        if ((oneTimeKeyBundles ?? []).length > 0) {
            keyBundle = getPOJO(oneTimeKeyBundles.pop());
            saveRequired = true;
        }
        else if (defaultKeyBundle) {
            keyBundle = getPOJO(defaultKeyBundle);
        }
        if (!keyBundle) return null;
        try {
            if (saveRequired && otherUser !== await otherUser.save()) return null;
            return keyBundle;
        }
        catch (err) {
            logError(err);
            return null;
        }
    }

    static async setSavedAuth(saveToken: string, ipRep: string, savedAuthDetails: UserEncryptedData) {
        try {
            if ((await this.SavedAuth.findOne({ ipRep }))) {
                await this.SavedAuth.deleteOne({ ipRep });
            }
            return !!(await this.SavedAuth.create({ saveToken, ipRep, savedAuthDetails }));
        }
        catch (err) {
            logError(err);
            return false;
        }
    }

    static async getSavedAuth(saveToken: string, ipRep: string) {
        return cleanLean(await this.SavedAuth.findOne({ saveToken, ipRep }).lean());
    }

    static async getUserRetries(username: string, ipRep: string): Promise<{ tries: number, allowsAt?: number }> {
        const retries = cleanLean(await this.UserRetries.findOne({ username, ipRep }).lean());
        return retries ?? {};
    }

    static async updateUserRetries(username: string, ipRep: string, allowsAt: number, tries: number = null) {
        const upd = tries !== null ? { tries, allowsAt } : { allowsAt };
        await this.UserRetries.updateOne({ username, ipRep }, upd, { upsert: true });
    }
    
    static async depositChatRequest(chatRequest: ChatRequestHeader) {
        try {
            const newChatRequest = new this.ChatRequest(chatRequest);
            return (newChatRequest === await newChatRequest.save());
        }
        catch (err) {
            logError(err);
            return false;
        }
    }

    private static toUserEncrypted = (ciphertext: Buffer) => ({ ciphertext, hSalt: Buffer.alloc(32) });

    static async instantiateUserHandler(username: string, databaseAuthKey: CryptoKey) {
        try {
            const accessRoot = cleanLean(await this.DatabaseAccessKey.findOne({ username, type: "root" }).lean());
            if (!accessRoot) return null;
            const { username: user } = await crypto.deriveDecrypt(this.toUserEncrypted(accessRoot.accessKey), databaseAuthKey, "DatabaseRootAccessKey");
            if (username !== user) return null;
            const chatsList = cleanLean(await this.DatabaseAccessKey.find({ username, type: "chat" }).lean());
            const chats: string[] = await allSettledResults(chatsList.map((c: any) => crypto.deriveDecrypt(this.toUserEncrypted(c.accessKey), databaseAuthKey, "DatabaseChatAccessKey").then((c) => c.chatId)));
            const sessionsList = cleanLean(await this.DatabaseAccessKey.find({ username, type: "session" }).lean());
            const sessions: ChatSessionDetails[] = await allSettledResults(sessionsList.map((c: any) => crypto.deriveDecrypt(this.toUserEncrypted(c.accessKey), databaseAuthKey, "DatabaseSessionAccessKey")));
            return new this.MongoUserHandler(username, databaseAuthKey, chats, sessions);
        }
        catch(err) {
            logError(err);
            return null;
        }
    }

    static readonly UserHandlerType: typeof this.MongoUserHandler.prototype = null;

    private static readonly MongoUserHandler = class {
        readonly #username: string;
        readonly #databaseAuthKey: CryptoKey;
        readonly #chats: string[];
        readonly #sessions: Map<string, ChatSessionDetails>;

        constructor (username: string, databaseAuthKey: CryptoKey, chats: string[], sessions: ChatSessionDetails[]) {
            this.#username = username;
            this.#databaseAuthKey = databaseAuthKey;
            this.#chats = chats;
            this.#sessions = new Map(sessions.map((s) => [s.sessionId, s]));
        }

        private matchUsername(username: string) {
            if (username === this.#username) return true;
            logError(`Unauthorized attempt by ${this.#username} to access records belonging to ${username}`);
            return false;
        }

        private matchChat(chatId: string) {
            if (this.#chats.includes(chatId)) return true;
            logError(`Unauthorized attempt by ${this.#username} to access chat resource #${chatId}`);
            return false;
        }

        private matchSessionMyAlias(sessionId: string, alias: string) {
            if (alias && this.#sessions.get(sessionId)?.myAlias === alias) return true;
            logError(`Unauthorized attempt by ${this.#username} to access session resource #${sessionId}%%myAlias:${alias}`);
            return false;
        }

        private matchSessionOtherAlias(sessionId: string, alias: string) {
            if (alias && this.#sessions.get(sessionId)?.otherAlias === alias) return true;
            logError(`Unauthorized attempt by ${this.#username} to access session resource #${sessionId}%%otherAlias:${alias}`);
            return false;
        }

        private validateKeyBundleOwner(keyBundles: PublishKeyBundlesRequest): boolean {
            let { defaultKeyBundle, oneTimeKeyBundles } = keyBundles;
            return [defaultKeyBundle.owner, ...oneTimeKeyBundles.map((kb) => kb.owner)].every((owner) => owner === this.#username);
        }

        private async addSessionKey(sessionId: string, myAlias: string, otherAlias: string) {
            if (this.#sessions.has(sessionId)) return false;
            const session = { sessionId, myAlias, otherAlias };
            const accessKey = (await crypto.deriveEncrypt(session, this.#databaseAuthKey, "DatabaseSessionAccessKey", Buffer.alloc(32))).ciphertext;
            if (await (new MongoHandlerCentral.DatabaseAccessKey({ username: this.#username, type: "session", accessKey })).save()) {
                this.#sessions.set(sessionId, session);
                return true;
            }
            else return false;
        }

        private async registerSession(sessionId: string, myAlias: string, otherAlias: string) {
            try {
                const pending = cleanLean(await MongoHandlerCentral.RegistrationPendingSession.findOne({ sessionId }).lean());
                if (!pending || !pending.acceptorAccessKey) return false;
                const existing = await MongoHandlerCentral.RegisteredSession.findOne({ sessionId });
                if (existing?.locked) return false;
                if (existing) {
                    const { username } = await crypto.deriveDecrypt(MongoHandlerCentral.toUserEncrypted(pending.initiatorAccessKey), this.#databaseAuthKey, "PendingSessionKey");
                    if (!this.matchUsername(username)) return false;
                    if (myAlias !== existing.alias2 || otherAlias !== existing.alias1) return false;
                    existing.locked = true;
                    if (existing === await existing.save()) {
                        await MongoHandlerCentral.RegistrationPendingSession.deleteOne({ sessionId });
                        return await this.addSessionKey(sessionId, myAlias, otherAlias);
                    }
                    else return false;
                }
                else {
                    const { username } = await crypto.deriveDecrypt(MongoHandlerCentral.toUserEncrypted(pending.acceptorAccessKey), this.#databaseAuthKey, "PendingSessionKey");
                    if (!this.matchUsername(username)) return false;
                    const newRegister = new MongoHandlerCentral.RegisteredSession({ sessionId, alias1: myAlias, alias2: otherAlias });
                    if (newRegister === await newRegister.save()) {
                        return await this.addSessionKey(sessionId, myAlias, otherAlias);
                    }
                    else return false;
                }
            }
            catch(err) {
                logError(err);
                return false;
            }
        }

        async registerPendingSession(sessionId: string, myAlias: string, otherAlias: string) {
            try {
                if (!!(await MongoHandlerCentral.RegisteredSession.findOne({ sessionId }))) return false;
                const prevPending = await MongoHandlerCentral.RegistrationPendingSession.findOne({ sessionId });
                const accessKey = (await crypto.deriveEncrypt({ username: this.#username }, this.#databaseAuthKey, "PendingSessionKey", Buffer.alloc(32))).ciphertext;
                if (!prevPending) {
                    const newPending = new MongoHandlerCentral.RegistrationPendingSession({ sessionId, toAlias: myAlias, fromAlias: otherAlias, initiatorAccessKey: accessKey });
                    return (newPending === await newPending.save());
                }
                else {
                    if (prevPending.acceptorAccessKey || myAlias !== prevPending.fromAlias || otherAlias !== prevPending.toAlias) return false;
                    prevPending.acceptorAccessKey = accessKey;
                    return (prevPending === await prevPending.save());
                }
            }
            catch (err) {
                logError(err);
                return false;
            }
        }

        async publishKeyBundles(keyBundles: PublishKeyBundlesRequest): Promise<boolean> {
            if (!this.validateKeyBundleOwner(keyBundles)) return false;
            const user = await MongoHandlerCentral.User.findOne({ username: this.#username });
            if (!user) return false;
            let { defaultKeyBundle, oneTimeKeyBundles } = keyBundles;
            user.keyBundles.defaultKeyBundle = defaultKeyBundle;
            oneTimeKeyBundles = Array.from(oneTimeKeyBundles.map((kb: any) => kb));
            const leanUser = await MongoHandlerCentral.getLeanUser(this.#username);
            const oldOneTimes = Array.from(leanUser.keyBundles.oneTimeKeyBundles ?? []).map((okb: any) => okb.identifier);
            const dontAdd = [...(leanUser.accessedKeyBundles ?? []), ...oldOneTimes];
            for (const oneTime of oneTimeKeyBundles) {
                if (!dontAdd.includes(oneTime.identifier)) {
                    user.keyBundles.oneTimeKeyBundles.push(oneTime);
                }
            }
            try {
                return (user === await user.save());
            }
            catch (err) {
                logError(err);
                return false;
            }
        }

        async updateUserData(userData: Username & { x3dhInfo?: UserEncryptedData, chatsData?: UserEncryptedData }) {
            const { username, x3dhInfo, chatsData } = userData;
            if (!this.matchUsername(username)) return false;
            const user = await MongoHandlerCentral.User.findOne( { username });
            if (!user) return false;
            if (x3dhInfo) {
                user.userData.x3dhInfo = x3dhInfo;
            }
            if (chatsData) {
                user.userData.chatsData = chatsData;
            }
            try {
                const savedUser = await user.save();
                return savedUser === user;
            }
            catch (err) {
                logError(err);
                return false;
            }
        }

        async depositMessage(message: MessageHeader) {
            const { toAlias, fromAlias, sessionId } = message;
            if (!this.matchSessionOtherAlias(sessionId, toAlias)) {
                if (!(await this.registerSession(sessionId, fromAlias, toAlias))) return false;
            }
            try {
                const newMessage = new MongoHandlerCentral.MessageHeader(message);
                return (newMessage === await newMessage.save());
            }
            catch (err) {
                logError(err);
                return false;
            }
        }
    
        async depositReceipt(receipt: Receipt) {
            const { toAlias, sessionId } = receipt;
            if (!this.matchSessionOtherAlias(sessionId, toAlias)) return false;
            try {
                const newReceipt = new MongoHandlerCentral.Receipt(receipt);
                return (newReceipt === await newReceipt.save());
            }
            catch (err) {
                logError(err);
                return false;
            }
        }
    
        async getChats(chatIds: string[]): Promise<ChatData[]> {
            if (chatIds.some((id) => !this.matchChat(id))) return undefined;
            return cleanLean(await MongoHandlerCentral.Chat.find({ chatId: { $in: chatIds } }).lean().exec());
        }
    
        async getAllRequests(addressedTo: string): Promise<ChatRequestHeader[]> {
            if (!this.matchUsername(addressedTo)) return undefined;
            return cleanLean(await MongoHandlerCentral.ChatRequest.find({ addressedTo }).lean().exec());
        }
    
        async getMessageHeaders(sessionId: string, toAlias: string, fromAlias: string): Promise<MessageHeader[]> {
            if (!this.matchSessionMyAlias(sessionId, toAlias)) {
                if (!(await this.registerSession(sessionId, toAlias, fromAlias))) return undefined;               
            }
            return cleanLean(await MongoHandlerCentral.MessageHeader.find({ sessionId, toAlias }).lean().exec());
        }
    
        async getMessagesByNumber(chatId: string, limit: number, olderThanTimemark: number): Promise<StoredMessage[]> {
            if (!this.matchChat(chatId)) return undefined;
            return cleanLean(await MongoHandlerCentral.Message.find({ chatId }).lt("timemark", olderThanTimemark).sort({ timemark: -1 }).limit(limit).lean().exec());
        }
    
        async getMessagesUptoTimestamp(chatId: string, newerThanTimemark: number, olderThanTimemark: number): Promise<StoredMessage[]> {
            if (!this.matchChat(chatId)) return undefined;
            return cleanLean(await MongoHandlerCentral.Message.find({ chatId }).lt("timemark", olderThanTimemark).gt("timemark", newerThanTimemark).sort({ timemark: -1 }).lean().exec());
        }
    
        async getMessagesUptoId(chatId: string, hashedId: string, olderThanTimemark: number): Promise<StoredMessage[]> {
            if (!this.matchChat(chatId)) return undefined;
            const message = await MongoHandlerCentral.Message.findOne({ chatId, hashedId }).exec();
            if (!message) return null;
            const { timemark } = message;
            return this.getMessagesUptoTimestamp(chatId, timemark, olderThanTimemark);
        }
    
        async getMessageById(chatId: string, hashedId: string): Promise<StoredMessage> {
            if (!this.matchChat(chatId)) return undefined;
            return cleanLean(await MongoHandlerCentral.Message.findOne({ chatId, hashedId }).lean().exec());
        }
    
        async deleteChatRequest(headerId: string) {
            const chatRequest = await MongoHandlerCentral.ChatRequest.findOne({ headerId });
            if (!this.matchUsername(chatRequest.addressedTo)) return false;
            try {
                return (await chatRequest.deleteOne()).deletedCount === 1
            }
            catch (err) {
                logError(err);
                return false;
            }
        }
    
        async storeMessage(message: StoredMessage) {
            try {
                const { chatId, hashedId } = message;
                if (!this.matchChat(chatId)) return false;
                const upsert = await MongoHandlerCentral.Message.updateOne({ chatId, hashedId }, message, { upsert: true });
                return (upsert.modifiedCount + upsert.upsertedCount) === 1;
            }
            catch (err) {
                logError(err);
                return false;
            }
        }
    
        async storeBackup(backup: Backup) {
            const { byAlias, sessionId } = backup;
            if (!this.matchSessionMyAlias(sessionId, byAlias)) return false;
            try {
                const newBackup = new MongoHandlerCentral.Backup(backup);
                if (newBackup === await newBackup.save()) {
                    return true;
                }
                return false;
            }
            catch (err) {
                logError(err);
                return false;
            }
        }
    
        async getBackupById(byAlias: string, sessionId: string, headerId: string): Promise<Backup> {
            if (!this.matchSessionMyAlias(sessionId, byAlias)) return undefined;
            return cleanLean(await MongoHandlerCentral.Backup.findOne({ byAlias, sessionId, headerId }).lean().exec());
        }
    
        async getAllReceipts(toAlias: string, sessionId: string): Promise<Receipt[]> {
            if (!this.matchSessionMyAlias(sessionId, toAlias)) return undefined;
            return await MongoHandlerCentral.Receipt.find({ sessionId, toAlias }).lean().exec();
        }
    
        async clearAllReceipts(toAlias: string, sessionId: string) {
            if (!this.matchSessionMyAlias(sessionId, toAlias)) return false;
            return (await MongoHandlerCentral.Receipt.deleteMany({ toAlias, sessionId })).deletedCount > 1;
        }
    
        async backupProcessed(byAlias: string, sessionId: string, headerId: string) {
            if (!this.matchSessionMyAlias(sessionId, byAlias)) return false;
            try {
                return (await MongoHandlerCentral.Backup.deleteOne({ byAlias, sessionId, headerId })).deletedCount === 1
            }
            catch (err) {
                logError(err);
                return false;
            }
        }
    
        async messageHeaderProcessed(toAlias: string, sessionId: string, headerId: string) {
            if (!this.matchSessionMyAlias(sessionId, toAlias)) return false;
            return (await MongoHandlerCentral.MessageHeader.deleteOne({ toAlias, sessionId, headerId })).deletedCount === 1;
        }
    
        async createChat(chat: ChatData) {
            try {
                const newChat = new MongoHandlerCentral.Chat(chat);
                if (newChat === await newChat.save()) {
                    const { chatId } = chat;
                    const accessKey = (await crypto.deriveEncrypt({ chatId }, this.#databaseAuthKey, "DatabaseChatAccessKey", Buffer.alloc(32))).ciphertext;
                    await (new MongoHandlerCentral.DatabaseAccessKey({ username: this.#username, type: "chat", accessKey })).save();
                    this.#chats.push(chatId);
                    return true;
                }
                return false;
            }
            catch (err) {
                logError(err);
                return false;
            }
        }
    
        async updateChat({ chatId, ...chat }: Omit<ChatData, "chatDetails" | "exportedChattingSession"> & Partial<ChatData>) {
            if (!this.#chats.includes(chatId)) return false;
            try {
                return !!(await MongoHandlerCentral.Chat.findOneAndUpdate({ chatId }, chat).exec());
            }
            catch (err) {
                logError(err);
                return false;
            }
        }
    }
}

function cleanLean(obj: any): any {
    if (!obj || typeof obj !== "object") {
        return obj;
    }
    if (Object.getPrototypeOf(obj).constructor.name === "Binary") {
        return (obj as Binary).buffer;
    }
    if (obj instanceof Array) {
        return Array.from(obj.map(v => cleanLean(v)));
    }
    for (const [key, value] of Object.entries(obj)) {
        if (key.startsWith("$") || key.startsWith("_")) {
            delete obj[key];
        }
        else {
            obj[key] = cleanLean(value);
        }
    }
    return obj;
}

function getPOJO(mongObj: any): any {
    if (!mongObj) {
        return null;
    }
    if (!isDoc(mongObj)) {
        return mongObj;
    }
    if (typeof mongObj === "object") {
        mongObj = "_doc" in mongObj ? mongObj._doc : mongObj;
        if (Object.getPrototypeOf(mongObj).constructor.name === "Buffer" || ArrayBuffer.isView(mongObj)) {
            return mongObj;
        }
        if (mongObj instanceof Array) {
            return mongObj.map(o => getPOJO(o));
        }
        type Keyed = { [key: string]: any };
        const newObj: Keyed = {};
        for (const [key, value] of Object.entries(mongObj)) {
            if (!key.startsWith("$") && !key.startsWith("_")) {
                if (!value) {
                    newObj[key] = value;
                }
                else if (isDoc(value)) {
                    newObj[key] = getPOJO(value);
                }
                else {
                    newObj[key] = value;
                }
            }
        }
        mongObj = newObj;
    }
    return mongObj;
}

function isDoc(docObj: any): boolean {
    if (!docObj) {
        return false;
    }
    if (typeof docObj === "object") {
        if ("_doc" in docObj) {
            return true;
        }
        if (Object.getPrototypeOf(docObj).constructor.name === "Buffer" || ArrayBuffer.isView(docObj)) {
            return false;
        }
        if (docObj instanceof Array) {
            return docObj.some(v => isDoc(v));
        }
        return Object.entries(docObj).some(([_, v]) => isDoc(v));
    }
    return false;
}