import _ from "lodash";
import { Binary, DeleteResult } from "mongodb";
import * as mongoose from "mongoose";
import { Schema } from "mongoose";
import { Buffer } from "./node_modules/buffer/";
import { Buffer as NodeBuffer } from "node:buffer";
import { ChatData, KeyBundle, MessageHeader, ChatRequestHeader, PasswordEncryptedData, PublishKeyBundlesRequest, StoredMessage, RegisterNewUserRequest, NewUserData, UserEncryptedData, Receipt, Backup } from "../shared/commonTypes";
import * as crypto from "../shared/cryptoOperator";
import { parseIpReadable } from "./backendserver";
import { logError } from "../shared/commonFunctions";

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

const ipSchema = {
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
    }
}

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

    private static readonly SavedAuth = mongoose.model("SavedAuth", new Schema({
        saveToken: {
            type: Schema.Types.String,
            required: true,
            immutable: true,
            unique: true
        },
        ...ipSchema,
        savedAuthDetails: userEncryptedData,
        createdAt: {
            type: Schema.Types.Date,
            default: new Date(),
            expires: 10 * 24 * 60 * 60
        }
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
        },
        accessedKeyBundles: {
            type: [Schema.Types.String],
            required: false,
            default: []
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
    }).index({ username: 1, ipRep: 1, ipRead: 1 }, { unique: true }), "user_retries");

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
        addressedTo: {
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
    }).index({ addressedTo: 1, sessionId: 1, headerId: 1 }, { unique: true }).index({ sendingRatchetNumber: 1, sendingChainNumber: 1 }, { unique: true }), "message_headers");

    private static readonly Receipt = mongoose.model("Receipt", new Schema({
        addressedTo: {
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
    }).index({ sessionId: 1, headerId: 1 }, { unique: true }), "receipts");

    private static readonly Chat = mongoose.model("Chat", new Schema({
        chatId: {
            type: Schema.Types.String,
            required: true,
            unique: true
        },
        chatDetails: userEncryptedData,
        exportedChattingSession: userEncryptedData
    }).index({ chatId: "hashed" }), "chats");

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
    }).index({ chatId: "hashed", timemark: -1 }).index({ chatId: 1, hashedId: 1 }, { unique: true }), "messages");

    private static readonly Backup =  mongoose.model("Backup", new Schema({
        sessionId: {
            type: Schema.Types.String,
            required: true
        },
        headerId: {
            type: Schema.Types.String,
            required: true
        },
        content: userEncryptedData
    }).index({ sessionId: 1, headerId: 1 }, { unique: true }), "backups");

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
            this.ServerData.create(bufferReplaceForMongo({ serverIdentitySigningKey, serverIdentityVerifyingKey }));
            return keyPair;
        }
        else {
            const { serverIdentitySigningKey, serverIdentityVerifyingKey } = serverData[0];
            const privateKey = await crypto.importKey(serverIdentitySigningKey, "ECDSA", "private", false);
            const publicKey = await crypto.importKey(serverIdentityVerifyingKey, "ECDSA", "public", true);
            return { privateKey, publicKey };
        }
    }

    static async createNewUser(user: Omit<RegisterNewUserRequest, "clientEphemeralPublicHex"> & NewUserData) {
        try {
            const newUser = new this.User(bufferReplaceForMongo(user));
            return (newUser === await newUser.save());
        }
        catch (err) {
            logError(err);
            return false;
        }
    }

    static async getUser(username: string) {
        const user = await this.User.findOne({ username });
        return user;
    }

    static async getLeanUser(username: string): Promise<any> {
        const user = bufferReplaceFromLean(await this.User.findOne({ username }).lean());
        return user;
    }

    static async setSavedAuth(saveToken: string, ipRep: string, savedAuthDetails: UserEncryptedData) {
        try {
            if ((await this.SavedAuth.findOne({ ipRep }))) {
                await this.SavedAuth.deleteOne({ ipRep });
            }
            const ipRead = parseIpReadable(ipRep);
            return !!(await this.SavedAuth.create(bufferReplaceForMongo({ saveToken, ipRep, ipRead, savedAuthDetails })));
        }
        catch (err) {
            logError(err);
            return false;
        }
    }

    static async getSavedAuth(saveToken: string, ipRep: string) {
        return bufferReplaceFromLean(await this.SavedAuth.findOne({ saveToken, ipRep }).lean());
    }

    static async getUserRetries(username: string, ipRep: string): Promise<{ tries: number, allowsAt?: number }> {
        const retries = bufferReplaceFromLean(await this.UserRetries.findOne({ username, ipRep }).lean());
        return retries ?? {};
    }

    static async updateUserRetries(username: string, ipRep: string, allowsAt: number, tries: number = null) {
        const ipRead = parseIpReadable(ipRep);
        const upd = tries !== null ? { tries, allowsAt } : { allowsAt };
        await this.UserRetries.updateOne({ username, ipRep, ipRead }, upd, { upsert: true });
    }

    static async depositMessage(message: MessageHeader) {
        try {
            const newMessage = new this.MessageHeader(bufferReplaceForMongo(message));
            return (newMessage === await newMessage.save());
        }
        catch (err) {
            logError(err);
            return false;
        }
    }

    static async depositChatRequest(chatRequest: ChatRequestHeader) {
        try {
            const newChatRequest = new this.ChatRequest(bufferReplaceForMongo(chatRequest));
            return (newChatRequest === await newChatRequest.save());
        }
        catch (err) {
            logError(err);
            return false;
        }
    }

    static async depositReceipt(receipt: Receipt) {
        try {
            const newReceipt = new this.Receipt(bufferReplaceForMongo(receipt));
            return (newReceipt === await newReceipt.save());
        }
        catch (err) {
            logError(err);
            return false;
        }
    }

    static async getChats(chatIds: string[]): Promise<ChatData[]> {
        return bufferReplaceFromLean(await this.Chat.find({ chatId: { $in: chatIds } }).lean().exec());
    }

    static async getAllRequests(addressedTo: string): Promise<ChatRequestHeader[]> {
        return bufferReplaceFromLean(await this.ChatRequest.find({ addressedTo }).lean().exec());
    }

    static async getUnprocessedMessages(sessionId: string, addressedTo: string): Promise<MessageHeader[]> {
        return bufferReplaceFromLean(await this.MessageHeader.find({ sessionId, addressedTo }).lean().exec());
    }

    static async getMessagesByNumber(chatId: string, limit: number, olderThanTimemark: number): Promise<StoredMessage[]> {
        return bufferReplaceFromLean(await this.Message.find({ chatId }).lt("timemark", olderThanTimemark).sort({ timemark: -1 }).limit(limit).lean().exec());
    }

    static async getMessagesUptoTimestamp(chatId: string, newerThanTimemark: number, olderThanTimemark: number): Promise<StoredMessage[]> {
        return bufferReplaceFromLean(await this.Message.find({ chatId }).lt("timemark", olderThanTimemark).gt("timemark", newerThanTimemark).sort({ timemark: -1 }).lean().exec());
    }

    static async getMessagesUptoId(chatId: string, hashedId: string, olderThanTimemark: number): Promise<StoredMessage[]> {
        const message = await this.Message.findOne({ chatId, hashedId }).exec();
        if (!message) return null;
        const { timemark } = message;
        return this.getMessagesUptoTimestamp(chatId, timemark, olderThanTimemark);
    }

    static async getMessageById(chatId: string, hashedId: string): Promise<StoredMessage> {
        return bufferReplaceFromLean(await this.Message.findOne({ chatId, hashedId }).lean().exec());
    }

    static async deleteChatRequest(headerId: string) {
        try {
            return (await this.ChatRequest.deleteOne({ headerId })).deletedCount === 1
        }
        catch (err) {
            logError(err);
            return false;
        }
    }

    static async storeMessage(message: StoredMessage) {
        try {
            const { chatId, hashedId } = message;
            const upsert = await this.Message.updateOne({ chatId, hashedId }, bufferReplaceForMongo(message), { upsert: true });
            return (upsert.modifiedCount + upsert.upsertedCount) === 1;
        }
        catch (err) {
            logError(err);
            return false;
        }
    }

    static async storeBackup(backup: Backup) {
        try {
            const newBackup = new this.Backup(bufferReplaceForMongo(backup));
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

    static async getBackupById(sessionId: string, headerId: string): Promise<Backup> {
        return bufferReplaceFromLean(await this.Backup.findOne({ sessionId, headerId }).lean().exec());
    }

    static async getAllReceipts(addressedTo: string, sessionId: string): Promise<Receipt[]> {
        return bufferReplaceFromLean(await this.Receipt.find({ sessionId, addressedTo }).lean().exec());
    }

    static async clearAllReceipts(addressedTo: string, sessionId: string) {
        return (await this.Receipt.deleteMany({ addressedTo, sessionId })).deletedCount > 1;
    }

    static async backupProcessed(sessionId: string, headerId: string) {
        try {
            return (await this.Backup.deleteOne({ sessionId, headerId })).deletedCount === 1
        }
        catch (err) {
            logError(err);
            return false;
        }
    }

    static async messageProcessed(sessionId: string, headerId: string) {
        return (await this.MessageHeader.deleteOne({ sessionId, headerId })).deletedCount === 1;
    }

    static async createChat(chat: ChatData) {
        try {
            const newChat = new this.Chat(bufferReplaceForMongo(chat));
            if (newChat === await newChat.save()) {
                return true;
            }
            return false;
        }
        catch (err) {
            logError(err);
            return false;
        }
    }

    static async updateChat({ chatId, ...chat }: Omit<ChatData, "chatDetails" | "exportedChattingSession"> & Partial<ChatData>) {
        try {
            return !!(await this.Chat.findOneAndUpdate({ chatId }, bufferReplaceForMongo(chat)).exec());
        }
        catch (err) {
            logError(err);
            return false;
        }
    }
}

export function bufferReplaceForMongo(obj: any): any {
    if (!obj || typeof obj !== "object") {
        return obj;
    }
    else {
        const name = Object.getPrototypeOf(obj).constructor.name;
        if (name === "Buffer" || ArrayBuffer.isView(obj)) {
            return NodeBuffer.from(obj);
        }
        else if (name === "Array") {
            const newArray = [];
            for (const elem of obj) {
                newArray.push(bufferReplaceForMongo(elem));
            }
            return newArray;
        }
        else {
            const newObj: { [key: string]: any } = {};
            for (const [key, value] of Object.entries(obj)) {
                newObj[key] = bufferReplaceForMongo(value);
            }
            return newObj;
        }
    }
}

export function bufferReplaceFromLean(obj: any): any {
    if (!obj || typeof obj !== "object") {
        return obj;
    }
    if (obj instanceof Array) {
        return Array.from(obj.map(v => bufferReplaceFromLean(v)));
    }
    const newObj: any = {};
    for (const [key, value] of Object.entries(obj)) {
        if (!key.startsWith("$") && !key.startsWith("_")) {
            if (!value) {
                newObj[key] = value;
            }
            else if (Object.getPrototypeOf(value).constructor.name === "Binary") {
                newObj[key] = Buffer.from((value as Binary).buffer);
            }
            else {
                newObj[key] = bufferReplaceFromLean(value);
            }
        }
    }
    return newObj;
}

export function cleanLean(obj: any): any {
    if (!obj || typeof obj !== "object") {
        return obj;
    }
    if (Object.getPrototypeOf(obj).constructor.name === "Binary") {
        return obj;
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