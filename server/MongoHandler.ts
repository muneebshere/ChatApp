import _, { isError } from "lodash";
import { Binary } from "mongodb";
import * as mongoose from "mongoose";
import { Schema } from "mongoose";
import { ChatData, KeyBundle, MessageHeader, ChatRequestHeader, StoredMessage, NewUserData, UserEncryptedData, Receipt, Backup, ChatSessionDetails, Username, NewAuthData, KeyBundleId, ExposedSignedPublicKey, PasswordDeriveInfo, PasswordEntangleInfo, PublicIdentity, UserData, SignedEncryptedData, RequestIssueNewKeysResponse, ServerMemo } from "../shared/commonTypes";
import * as crypto from "../shared/cryptoOperator";
import { defaultServerConfig, parseIpReadable } from "./backendserver";
import { Notify } from "./SocketHandler";
import { allSettledResults, logError, randomFunctions } from "../shared/commonFunctions";

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

const immutableExposedSignedKey = {
    exportedPublicKey: {
        type: Schema.Types.Buffer,
        required: true,
        immutable: true
    },
    signature: {
        type: Schema.Types.Buffer,
        required: true,
        immutable: true
    }
};

const signedEncryptedData = {
    ciphertext: {
        type: Schema.Types.Buffer,
        required: true,
        immutable: true
    },
    signature: {
        type: Schema.Types.Buffer,
        required: true,
        immutable: true
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

const immutableUserEncryptedData = {
    ciphertext: {
        ...userEncryptedData.ciphertext,
        immutable: true
    },
    hSalt: {
        ...userEncryptedData.hSalt,
        immutable: true
    }
};

const passwordDeriveInfo = {
    pSalt: {
        type: Schema.Types.Buffer,
        required: true
    },
    iterSeed: {
        type: Schema.Types.Number,
        required: true
    }
};

const passwordEntangleInfo = {
    passwordEntangledPoint: {
        type: Schema.Types.Buffer,
        required: true
    },
    ...passwordDeriveInfo
}

const ip = {
    ipRep: {
        type: Schema.Types.String,
        required: true,
        immutable: true
    },
    ipRead: {
        type: Schema.Types.String,
        required: true,
        immutable: true
    }
}

const { getRandomVector, getRandomString } = randomFunctions();

export type ServerConfig = Readonly<{
    minOneTimeKeys: number,
    maxOneTimeKeys: number,
    replaceKeyAtMillis: number }>;

type ServerData = Readonly<{
    signingKey: CryptoKey,
    verifyingKey: Buffer,
    cookieSign: string,
    serverConfig: ServerConfig
}>;

type User = {
    username: string,
    verifierPoint: Buffer,
    verifierDerive: PasswordDeriveInfo,
    databaseAuthKeyDerive: PasswordEntangleInfo,
    publicIdentity: PublicIdentity,
    userData: {
        encryptionBaseDerive: PasswordEntangleInfo,
        serverIdentityVerifying: UserEncryptedData,
        x3dhIdentity: UserEncryptedData,
        x3dhInfo: UserEncryptedData,
        profileData: UserEncryptedData
    },
    keyData: {
        preKey: {
            version: number,
            lastReplacedAt: number,
            publicPreKey: ExposedSignedPublicKey
        },
        oneTimeKeys: {
            oneTimeKeyIdentifier: string,
            publicOneTimeKey: ExposedSignedPublicKey
        }[],
    },
    serverMemos: ServerMemo[]
};

export default class MongoHandlerCentral {

    private static serverConfig: ServerConfig;

    private static signingKey: CryptoKey;

    private static sessionHooks = new Map<string, (notify: Notify) => void>();

    private static subscribeChange(id: string, callback: (notify: Notify) => void) {
        if (callback) MongoHandlerCentral.sessionHooks.set(id, callback);
        else MongoHandlerCentral.sessionHooks.delete(id);
    }

    //#region Schema

    private static readonly oneTimeKeySchema = new Schema({
        oneTimeKeyIdentifier: {
            type: Schema.Types.String,
            required: true,
            immutable: true,
            unique: true
        },
        publicOneTimeKey: immutableExposedSignedKey
    });

    private static readonly preKeySchema = new Schema({
        version: {
            type: Schema.Types.Number,
            required: true
        },
        lastReplacedAt: {
            type: Schema.Types.Number,
            required: true
        },
        publicPreKey: {
            type: exposedSignedKey,
            required: true
        }
    });

    private static readonly serverMemoSchema = new Schema({
        memoId: {
            type: Schema.Types.String,
            required: true,
            immutable: true
        },
        encryptionPublicKey: {
            type: Schema.Types.Buffer,
            required: true,
            immutable: true
        },
        memoData: { 
            signature: {
                type: Schema.Types.Buffer,
                required: true,
                immutable: true
            },
            ...immutableUserEncryptedData,
        }
    }).index({ memoId: 1 }, { unique: true, partialFilterExpression: { "memoId": { $exists: true, $gt: "" } } });

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
        },
        cookieSign: {
            type: Schema.Types.String,
            required: true,
            immutable: true,
            unique: true
        },
        serverConfig: {
            minOneTimeKeys: {
                type: Schema.Types.Number,
                required: true
            },
            maxOneTimeKeys: {
                type: Schema.Types.Number,
                required: true
            },
            replaceKeyAtMillis: {
                type: Schema.Types.Number,
                required: true
            }
        }
    }), "server_data");

    private static readonly RunningClientSession = mongoose.model("RunningClientSession", new Schema({
        sessionReference: {
            type: Schema.Types.String,
            required: true,
            immutable: true,
            unique: true
        },
        record: immutableUserEncryptedData,
        lastFreshAt: {
            type: Schema.Types.Date,
            required: true,
            default: new Date(),
            expires: 5 * 60
        }
    }), "running_client_sessions");

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
            enum: ["root", "chat", "session", "keyBundle"]
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
            const prevAcceptor = (await MongoHandlerCentral.RegistrationPendingSession.findOne({ sessionId: this.sessionId }).lean())?.acceptorAccessKey;
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
        ...ip,
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
        verifierPoint: {
            type: Schema.Types.Buffer,
            required: true
        },
        verifierDerive: passwordDeriveInfo,
        databaseAuthKeyDerive: passwordEntangleInfo,
        publicIdentity: { 
            publicIdentityVerifyingKey: { 
                type: Schema.Types.Buffer,
                required: true,
                immutable: true
            },
            publicDHIdentityKey: immutableExposedSignedKey
         },
        userData: {
            encryptionBaseDerive: passwordEntangleInfo,
            serverIdentityVerifying: immutableUserEncryptedData,
            profileData: userEncryptedData,
            x3dhIdentity: immutableUserEncryptedData,
            x3dhInfo: userEncryptedData
        },
        keyData: {
            preKey: {
                type: this.preKeySchema,
                required: false,
                default: null
            },
            oneTimeKeys: {
                type: [this.oneTimeKeySchema],
                required: true,
                default: []
            },
        },
        serverMemos: [this.serverMemoSchema]
    }).post("save", (doc, next) => {
        if (doc.serverMemos.length > 0) {
            const serverMemos: ServerMemo[] = getPOJO(doc.serverMemos);
            MongoHandlerCentral.sessionHooks.get(`$user${doc.username}`)?.({ type: "ServerMemo", serverMemos });
        }
        next();
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
        ...ip
    }).index({ username: 1, ipRep: 1 }, { unique: true })
    .pre("validate", function(next) { 
        if (this.isNew) this.ipRead = parseIpReadable(this.ipRep);
        next(); 
    }), "user_retries");

    private static readonly ChatRequest = mongoose.model("ChatRequest", new Schema({
        addressedTo: {
            type: Schema.Types.String,
            required: true,
            immutable: true
        },
        headerId: {
            type: Schema.Types.String,
            required: true,
            unique: true,
            immutable: true
        },
        myVerifyingIdentityKey: {
            type: Schema.Types.Buffer,
            required: true,
            immutable: true
        },
        myPublicDHIdentityKey: immutableExposedSignedKey,
        myPublicEphemeralKey: immutableExposedSignedKey,
        yourBundleId: {
            type: Schema.Types.String,
            required: false,
            unique: true,
            immutable: true
        },
        initialMessage: signedEncryptedData
    }).index({ addressedTo: "hashed" }).post("save", (doc, next) => {
        MongoHandlerCentral.sessionHooks.get(`$user${doc.addressedTo}`)?.({ type: "Request" });
        next();
    }), "chat_requests");

    private static readonly MessageHeader = mongoose.model("MessageHeader", new Schema({
        sessionId: {
            type: Schema.Types.String,
            required: true,
            immutable: true
        },
        fromAlias: {
            type: Schema.Types.String,
            required: true,
            immutable: true
        },
        toAlias: {
            type: Schema.Types.String,
            required: true,
            immutable: true
        },
        headerId: {
            type: Schema.Types.String,
            required: true,
            immutable: true
        },
        receivingRatchetNumber: {
            type: Schema.Types.Number,
            required: true,
            immutable: true
        },
        sendingRatchetNumber: {
            type: Schema.Types.Number,
            required: true,
            immutable: true
        },
        sendingChainNumber: {
            type: Schema.Types.Number,
            required: true,
            immutable: true
        },
        previousChainNumber: {
            type: Schema.Types.Number,
            required: true,
            immutable: true
        },
        nextDHRatchetKey: immutableExposedSignedKey,
        messageBody: signedEncryptedData
    }).index({ sessionId: 1, toAlias: 1 }).index({ sessionId: 1, headerId: 1 }, { unique: true }).index({ sendingRatchetNumber: 1, sendingChainNumber: 1 }, { unique: true }).post("save", (doc, next) => {
        MongoHandlerCentral.sessionHooks.get(`${doc.sessionId}@${doc.toAlias}`)?.({ type: "Message", ..._.pick(doc, "sessionId") });
        next();
    }), "message_headers");

    private static readonly Receipt = mongoose.model("Receipt", new Schema({
        toAlias: {
            type: Schema.Types.String,
            required: true,
            immutable: true
        },
        sessionId: {
            type: Schema.Types.String,
            required: true,
            immutable: true
        },
        headerId: {
            type: Schema.Types.String,
            required: true,
            immutable: true
        },
        signature: {
            type: Schema.Types.String,
            required: true,
            immutable: true
        },
        bounced: {
            type: Schema.Types.Boolean,
            required: true,
            immutable: true
        }
    }).index({ sessionId: 1, toAlias: 1 }).index({ sessionId: 1, headerId: 1 }, { unique: true }).post("save", (doc, next) => {
        MongoHandlerCentral.sessionHooks.get(`${doc.sessionId}@${doc.toAlias}`)?.({ type: "Receipt", ..._.pick(doc, "sessionId") });
        next();
    }), "receipts");

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

    //#endregion

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

    static async setupServer(): Promise<ServerData> {
        const serverData = cleanLean(await this.ServerData.find().lean());
        if (serverData.length === 0) {
            const keyPair = await crypto.generateKeyPair("ECDSA");
            const serverIdentitySigningKey = await crypto.exportKey(keyPair.privateKey);
            const serverIdentityVerifyingKey = await crypto.exportKey(keyPair.publicKey);
            const cookieSign = randomFunctions().getRandomString(20, "base64");
            const serverConfig = defaultServerConfig;
            this.ServerData.create({ serverIdentitySigningKey, serverIdentityVerifyingKey, cookieSign, serverConfig });
            this.serverConfig = serverConfig;
            this.signingKey = keyPair.privateKey;
            return { signingKey: keyPair.privateKey, verifyingKey: serverIdentityVerifyingKey, cookieSign, serverConfig };
        }
        else {
            const { serverIdentitySigningKey, serverIdentityVerifyingKey, cookieSign, serverConfig } = serverData[0];
            const signingKey = await crypto.importKey(serverIdentitySigningKey, "ECDSA", "private", false);
            const verifyingKey: Buffer = serverIdentityVerifyingKey;
            this.serverConfig = serverConfig;
            this.signingKey = signingKey;
            return { signingKey, verifyingKey, cookieSign, serverConfig };
        }
    }

    static async createRunningClientSession(sessionReference: string, record: UserEncryptedData) {
        try {
            return !!(await this.RunningClientSession.create({ sessionReference, record }));
        }
        catch(err) {
            logError(err);
            return false;
        }
    }

    static async refreshRunningClientSessions(sessionReferences: string[]) {
        const lastFreshAt = new Date();
        return (await this.RunningClientSession.updateMany({ sessionReference: { $in: sessionReferences } }, { lastFreshAt })).modifiedCount > 0;
    }

    static async runningClientSessionExists(sessionReference: string): Promise<boolean> {
        return !!(await this.RunningClientSession.exists({ sessionReference }))?._id;
    }

    static async getRunningClientSession(sessionReference: string): Promise<UserEncryptedData> {
        return cleanLean(await this.RunningClientSession.findOne({ sessionReference }).lean()).record;
    }

    static async clearRunningClientSession(sessionReference: string) {
        return (await this.RunningClientSession.deleteOne({ sessionReference })).deletedCount === 1;
    }

    static async createNewUser(user: Username & NewAuthData & NewUserData, databaseAuthKey: CryptoKey, onFail: Promise<{ failed: boolean }>) {
        try {
            const { username } = user;
            if ((await this.DatabaseAccessKey.find({ username, type: "root" })).length > 0) return false;
            const { publicIdentityVerifyingKey, publicDHIdentityKey } = user.publicIdentity;
            if (!(await crypto.verifyKey(publicDHIdentityKey, publicIdentityVerifyingKey))) return false;
            const accessKey = (await crypto.deriveEncrypt({ username }, databaseAuthKey, "DatabaseRootAccessKey", Buffer.alloc(32))).ciphertext;
            const accessRoot = new this.DatabaseAccessKey({ username, type: "root", accessKey });
            if (accessRoot !== await accessRoot.save()) return false;
            onFail.then(({ failed }) => {
                if (failed === true) {
                    this.DatabaseAccessKey.deleteMany({ username }).exec();
                    this.User.deleteOne({ username }).exec();
                }
            });
            const newUser = new this.User(user);
            return (newUser === await newUser.save());
        }
        catch (err) {
            logError(err);
            return false;
        }
    }

    static async userExists(username: string) {
        return !!(await this.User.exists({ username }))?._id;
    }

    static async getUserAuth(username: string): Promise<Pick<User, "publicIdentity" | "verifierDerive" | "verifierPoint" | "databaseAuthKeyDerive">> {
        const user = cleanLean(await this.User.findOne({ username }).lean());
        return _.pick(user, "publicIdentity", "verifierDerive", "verifierPoint", "databaseAuthKeyDerive");
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

    static async clearSavedAuth(saveToken: string) {
        return (await this.SavedAuth.deleteOne({ saveToken })).deletedCount === 1;
    }

    static async savedAuthExists(saveToken: string, ipRep?: string) {
        return !!(await this.SavedAuth.exists({ saveToken, ...(ipRep ? { ipRep } : {}) }))?._id;
    }

    static async getUserRetries(username: string, ipRep: string): Promise<{ tries?: number, allowsAt?: number }> {
        const retries = cleanLean(await this.UserRetries.findOne({ username, ipRep }).lean());
        return retries || {};
    }

    static async updateUserRetries(username: string, ipRep: string, allowsAt: number, tries: number = null) {
        tries ??= 1;
        await this.UserRetries.updateOne({ username, ipRep }, { tries, allowsAt }, { upsert: true });
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

    private static async getKeyBundle(username: string): Promise<KeyBundle> {
        const otherUser = await this.User.findOne({ username });
        if (!otherUser) return null;
        const { 
            publicIdentity: { 
                publicDHIdentityKey, 
                publicIdentityVerifyingKey: verifyingIdentityKey 
            }, 
            keyData: { 
                preKey: { 
                    version: preKeyVersion, 
                    publicPreKey: publicSignedPreKey 
                } 
            } 
        } = cleanLean(await this.User.findOne({ username }).lean());
        let oneTimeKey: Pick<KeyBundle, "publicOneTimeKey"> & { readonly oneTimeKeyIdentifier: string };
        if ((otherUser.keyData?.oneTimeKeys || []).length > 0) {
            oneTimeKey = getPOJO(otherUser.keyData.oneTimeKeys.pop());
        }
        const bundleId = getRandomString(15, "base64");
        let keyBundleId: KeyBundleId, keyBundle: KeyBundle;
        if (oneTimeKey) {
            const { oneTimeKeyIdentifier, publicOneTimeKey } = oneTimeKey;
            keyBundleId = { bundleId, preKeyVersion, oneTimeKeyIdentifier };
            keyBundle = { bundleId, owner: username, verifyingIdentityKey, publicDHIdentityKey, publicOneTimeKey, publicSignedPreKey };
        }
        else {
            keyBundleId = { bundleId, preKeyVersion };
            keyBundle = { bundleId, owner: username, verifyingIdentityKey, publicDHIdentityKey, publicSignedPreKey };
        }
        try {
            const memo = await MongoHandlerCentral.generateMemo(username, { memoType: "KeyBundleIssued", keyBundleId });
            if (!memo) return null;
            otherUser.serverMemos.push(memo);
            if (otherUser !== await otherUser.save()) return null;
            return keyBundle;
        }
        catch (err) {
            logError(err);
            return null;
        }
    }

    private static async generateMemo(username: string, memo: any): Promise<ServerMemo> {
        const user = await this.User.findOne({ username });
        if (!user) return null;
        const { exportedPublicKey } = user.publicIdentity.publicDHIdentityKey;
        const memoId = randomFunctions().getRandomString(20, "base64");
        const keyPair = await crypto.generateKeyPair("ECDH");
        const encryptionPublicKey = await crypto.exportKey(keyPair.publicKey);
        const clientPublicKey = await crypto.importKey(exportedPublicKey, "ECDH", "public", false);
        const sharedBits = await crypto.deriveSymmetricBits(keyPair.privateKey, clientPublicKey, 512);
        const hSalt = getRandomVector(48);
        const data = await crypto.deriveSignEncrypt(sharedBits, memo, hSalt, `ServerMemo for ${username}: ${memoId}`, this.signingKey);
        const memoData = { ...data, hSalt };
        return { memoId, encryptionPublicKey, memoData };
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
            const keyBundlesList = cleanLean(await this.DatabaseAccessKey.find({ username, type: "keyBundles" }).lean());
            const keyBundles: KeyBundle[] = (await allSettledResults<any>(keyBundlesList.map((c: any) => crypto.deriveDecrypt(this.toUserEncrypted(c.accessKey), databaseAuthKey, "DatabaseKeyBundleAccessKey")))).map((ak) => ak.keyBundle);
            const userDocument = await MongoHandlerCentral.User.findOne({ username });
            return new this.MongoUserHandler(username, userDocument, databaseAuthKey, chats, sessions, keyBundles, this.subscribeChange);
        }
        catch(err) {
            logError(err);
            return null;
        }
    }

    static readonly UserHandlerType: typeof this.MongoUserHandler.prototype = null;

    static readonly UserDocumentType: Awaited<ReturnType<(typeof this.UserHandlerType)["getUserDocument"]>> = null;

    private static readonly MongoUserHandler = class {
        #userDocument: typeof MongoHandlerCentral.UserDocumentType;
        readonly #username: string;
        readonly #databaseAuthKey: CryptoKey;
        readonly #chats: string[];
        readonly #sessions: Map<string, ChatSessionDetails>;
        readonly #keyBundles: Map<string, KeyBundle>;
        private notify: (notify: Notify) => void;
        private readonly subscribeChange: (id: string, callback: (notify: Notify) => void) => void;

        constructor (username: string, userDocument: typeof MongoHandlerCentral.UserDocumentType, databaseAuthKey: CryptoKey, chats: string[], sessions: ChatSessionDetails[], keyBundles: KeyBundle[], subscribeChange: typeof MongoHandlerCentral.UserHandlerType.subscribeChange) {
            this.#username = username;
            this.#userDocument = userDocument;
            this.#databaseAuthKey = databaseAuthKey;
            this.#chats = chats;
            this.#sessions = new Map(sessions.map((s) => [s.sessionId, s]));
            this.#keyBundles = new Map(keyBundles.map((b) => [b.owner, b]));
            this.subscribeChange = subscribeChange;
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

        private async getUserDocument() {
            const username = this.#username;
            const userDocument = await MongoHandlerCentral.User.findOne({ username });
            this.#userDocument = userDocument;
            return userDocument;
        }

        private async validateKeys(keys: ExposedSignedPublicKey[]): Promise<boolean> {
            if (!this.#userDocument) return false;
            const { publicIdentity } = this.#userDocument;
            const verifyingKey = await crypto.importKey(publicIdentity.publicIdentityVerifyingKey, "ECDSA", "public", false);
            for (const { exportedPublicKey, signature } of keys) {
                if (!(await crypto.verify(exportedPublicKey, signature, verifyingKey))) return false;
            }
            return true;
        }

        private async addSessionKey(sessionId: string, myAlias: string, otherAlias: string) {
            if (this.#sessions.has(sessionId)) return false;
            const session = { sessionId, myAlias, otherAlias };
            const accessKey = (await crypto.deriveEncrypt(session, this.#databaseAuthKey, "DatabaseSessionAccessKey", Buffer.alloc(32))).ciphertext;
            if (await (new MongoHandlerCentral.DatabaseAccessKey({ username: this.#username, type: "session", accessKey })).save()) {
                this.#sessions.set(sessionId, session);
                if (this.notify) this.subscribeChange(`${sessionId}@${myAlias}`, this.notify);
                return true;
            }
            else return false;
        }

        private async registerSession(sessionId: string, myAlias: string, otherAlias: string) {
            try {
                const pending = cleanLean(await MongoHandlerCentral.RegistrationPendingSession.findOne({ sessionId }).lean());
                if (!pending) return false;
                const existing = await MongoHandlerCentral.RegisteredSession.findOne({ sessionId });
                if (existing?.locked) return false;
                if (existing) {
                    const { username } = await crypto.deriveDecrypt(MongoHandlerCentral.toUserEncrypted(pending.initiatorAccessKey), this.#databaseAuthKey, "PendingSessionKey");
                    if (!this.matchUsername(username) || myAlias !== existing.alias2 || otherAlias !== existing.alias1) return false;
                    existing.locked = true;
                    if (existing === await existing.save()) {
                        await MongoHandlerCentral.RegistrationPendingSession.deleteOne({ sessionId });
                        return await this.addSessionKey(sessionId, myAlias, otherAlias);
                    }
                    else return false;
                }
                else {
                    if (pending.acceptorAccessKey) {
                        const { username } = await crypto.deriveDecrypt(MongoHandlerCentral.toUserEncrypted(pending.acceptorAccessKey), this.#databaseAuthKey, "PendingSessionKey");
                        if (!this.matchUsername(username)) return false;
                        const newRegister = new MongoHandlerCentral.RegisteredSession({ sessionId, alias1: myAlias, alias2: otherAlias });
                        if (newRegister === await newRegister.save()) {
                            return await this.addSessionKey(sessionId, myAlias, otherAlias);
                        }
                        else return false;
                    }
                    else if (this.notify) {
                        const { username } = await crypto.deriveDecrypt(MongoHandlerCentral.toUserEncrypted(pending.initiatorAccessKey), this.#databaseAuthKey, "PendingSessionKey");
                        if (this.matchUsername(username)) this.subscribeChange(`${sessionId}@${myAlias}`, this.notify);
                        return false;
                    }
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
                    if (newPending === await newPending.save()) {
                        if (this.notify) this.subscribeChange(`${sessionId}@${myAlias}`, this.notify);
                        return true;
                    }
                    else return false;
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

        getUserData(): User["userData"] {
            return cleanLean(this.#userDocument.toObject().userData);
        }

        getKeyStats() {
            const { preKey, oneTimeKeys } = this.#userDocument.keyData;
            const preKeyLastReplacedAt = preKey?.lastReplacedAt || 0; 
            return { preKeyLastReplacedAt, currentOneTimeKeysNumber: oneTimeKeys.length };
        }

        async updateX3dhInfo(userData: { x3dhInfo: UserEncryptedData }) {
            const user = this.#userDocument;
            if (!user) return false;
            if (!userData?.x3dhInfo) return false;
            try {
                user.userData.x3dhInfo = userData.x3dhInfo;
                const saveSuccess = (await user.save()) === user;
                if (!saveSuccess) await this.getUserDocument();
                return saveSuccess;
            }
            catch (err) {
                logError(err); 
                await this.getUserDocument();
                return false;
            }
        }

        async rotateKeys(keys: RequestIssueNewKeysResponse) {
            const { x3dhInfo } = keys;
            const user = this.#userDocument;
            try {
                if ("preKey" in keys) {
                    const { preKey } = keys;
                    if (!(await this.validateKeys([preKey[1]]))) return false;
                    const [version, publicPreKey] = preKey;
                    const lastVersion = this.#userDocument.keyData?.preKey?.version || 0; 
                    if ((version - lastVersion) !== 1) return false;
                    const lastReplacedAt = Date.now();
                    user.keyData.preKey = { version, lastReplacedAt: Date.now(), publicPreKey };
                    user.userData.x3dhInfo = x3dhInfo;
                    const saveSuccess = (await user.save()) === user;
                    if (!saveSuccess) await this.getUserDocument();
                    return saveSuccess;
                }
                else {
                    const { oneTimeKeys } = keys;
                    if (!(await this.validateKeys(oneTimeKeys.map(([, k]) => k)))) return false;
                    for (const [oneTimeKeyIdentifier, publicOneTimeKey] of oneTimeKeys) {
                        user.keyData.oneTimeKeys.push({ oneTimeKeyIdentifier, publicOneTimeKey });
                    }
                    user.userData.x3dhInfo = x3dhInfo;
                    const saveSuccess = (await user.save()) === user;
                    if (!saveSuccess) await this.getUserDocument();
                    return saveSuccess;
                }
            }
            catch(err) {
                await this.getUserDocument();
                logError(err);
                return false;
            }
        }

        async getKeyBundle(username: string): Promise<KeyBundle> {
            let keyBundle = this.#keyBundles.get(username);
            if (keyBundle) return keyBundle;
            keyBundle = await MongoHandlerCentral.getKeyBundle(username);
            if (!keyBundle) return null;
            const accessKey = (await crypto.deriveEncrypt({ keyBundle }, this.#databaseAuthKey, "DatabaseKeyBundleKey", Buffer.alloc(32))).ciphertext;
            if (await (new MongoHandlerCentral.DatabaseAccessKey({ username: this.#username, type: "keyBundle", accessKey })).save()) {
                this.#keyBundles.set(username, keyBundle);
                return keyBundle;
            }
            else return null;
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
    
        async getAllChats(): Promise<ChatData[]> {
            return cleanLean(await MongoHandlerCentral.Chat.find({ chatId: { $in: this.#chats } }).lean().exec());
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
            return cleanLean(await MongoHandlerCentral.Message.find({ chatId }).lte("timemark", olderThanTimemark).sort({ timemark: -1 }).limit(limit).lean().exec());
        }
    
        async getMessagesUptoTimestamp(chatId: string, newerThanTimemark: number, olderThanTimemark: number): Promise<StoredMessage[]> {
            if (!this.matchChat(chatId)) return undefined;
            return cleanLean(await MongoHandlerCentral.Message.find({ chatId }).lte("timemark", olderThanTimemark).gte("timemark", newerThanTimemark).sort({ timemark: -1 }).lean().exec());
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
                return !!(await chatRequest.deleteOne());
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

        async discardMemos(processed: string[], x3dhInfo: UserEncryptedData) {
            const user = this.#userDocument;
            try {
                processed.forEach(memoId => {
                    const id = user.serverMemos.find(memo => memo.memoId === memoId)?.id;
                    if (id) user.serverMemos.pull(id);
                });
                user.userData.x3dhInfo = x3dhInfo;
                const saveSuccess = (await user.save()) === user;
                if (!saveSuccess) await this.getUserDocument();
                return saveSuccess;
            }
            catch (err) {
                await this.getUserDocument();
                logError(err);
                return false;
            }
        }

        subscribe(notify: typeof this.notify) {
            this.notify = notify;
            this.subscribeChange(`$user${this.#username}`, notify);
            for (const [sessionId, { myAlias }] of this.#sessions) this.subscribeChange(`${sessionId}@${myAlias}`, notify);
        }

        unsubscribe() {
            this.subscribeChange(`$user${this.#username}`, null);
            for (const [sessionId, { myAlias }] of this.#sessions) this.subscribeChange(`${sessionId}@${myAlias}`, null);
            this.notify = null;
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