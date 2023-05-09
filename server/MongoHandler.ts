import _ from "lodash";
import { Binary } from "mongodb";
import * as mongoose from "mongoose";
import { Schema } from "mongoose";
import { Buffer } from "./node_modules/buffer/";
import { Buffer as NodeBuffer } from "node:buffer";
import { ChatData, KeyBundle, MessageHeader, ChatRequestHeader, PasswordEncryptedData, PublishKeyBundlesRequest, SavedDetails, StoredMessage, UserAuthInfo, UserEncryptedData } from "../shared/commonTypes";

export type RunningSession = {
  sessionId: string;
  sessionReference: string;
  sessionKeyBits: Buffer,
  sessionSigningKeyEx: Buffer,
  sessionVerifyingKeyEx: Buffer,
  lastRefreshedAt?: Date,
  accessedBundles?: Map<string, KeyBundle>
}

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
  
const chatRequestHeaderSchema = new Schema({
  sessionId: {
    type: Schema.Types.String,
    required: true,
    unique: true,
  },
  timestamp: {
    type: Schema.Types.Number,
    required: true
  },
  addressedTo: {
    type: Schema.Types.String,
    required: true
  },
  myVerifyingIdentityKey: {
    type: Schema.Types.Buffer,
    required: true
  },
  myPublicDHIdentityKey: exposedSignedKey,
  myPublicEphemeralKey: exposedSignedKey,
  yourOneTimeKeyIdentifier: {
    type: Schema.Types.String,
    required: false
  },
  yourSignedPreKeyVersion: {
    type: Schema.Types.Number,
    required: true
  },
  initialMessage: signedEncryptedData
});

const messageHeaderSchema = new Schema({
  addressedTo: {
    type: Schema.Types.String,
    required: true
  },
  sessionId: {
    type: Schema.Types.String,
    required: true
  },
  messageId: {
    type: Schema.Types.String,
    required: true
  },
  timestamp: {
    type: Schema.Types.Number,
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
});

const messageSchema = new Schema({
  sessionId: {
    type: Schema.Types.String,
    required: true
  },
  messageId: {
    type: Schema.Types.String,
    required: true
  },
  timestamp: {
    type: Schema.Types.Number,
    required: true
  },
  content: userEncryptedData
});

const chatSchema = new Schema({
  sessionId: {
    type: Schema.Types.String,
    required: true,
    unique: true
  },
  lastActivity: {
    type: Schema.Types.Number,
    required: true
  },
  chatDetails: userEncryptedData,
  exportedChattingSession: userEncryptedData
});

export class MongoHandlerCentral {
  private static readonly timeouts = new Map<string, NodeJS.Timeout>();

  private static readonly userHandlers = new Map<string, MongoUserHandler>();

  private static readonly passwordDeriveInfo = {
    pSalt: {
      type: Schema.Types.Buffer,
      required: true
    },
    iterSeed: {
      type: Schema.Types.Number,
      required: true
    }
  };
  
  private static readonly passwordEncryptedData = {
    ciphertext: {
      type: Schema.Types.Buffer,
      required: true
    },
    hSalt: {
      type: Schema.Types.Buffer,
      required: true
    },
    ...this.passwordDeriveInfo
  };
  
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

  private static readonly SavedDetails = mongoose.model("SavedDetails", new Schema({
    saveToken: {
      type: Schema.Types.String,
      required: true,
      immutable: true,
      unique: true
    },
    url: {
      type: Schema.Types.String,
      required: true,
      immutable: true,
    },
    keyBits: {
      type: Schema.Types.Buffer,
      required: true,
      immutable: true
    }, 
    hSalt:  {
      type: Schema.Types.Buffer,
      required: true,
      immutable: true
    },
    createdAt: {
      type: Schema.Types.Date,
      default: new Date(),
      expires: 10*24*60*60
    }
  }), "saved_details");

  private static readonly User = mongoose.model("User", new Schema({
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
    userDetails: userEncryptedData,
    authInfo: {
      originalData: {
        type: Schema.Types.Buffer,
        required: true
      },
      signedData: {
        type: Schema.Types.Buffer,
        required: true
      },
      serverProof: this.passwordEncryptedData,  
      encryptionBase: this.passwordEncryptedData,
      dInfo: {
        ...this.passwordDeriveInfo,
        hSalt: {
          type: Schema.Types.Buffer,
          required: true
        }
      }
    },
    x3dhInfo: userEncryptedData,
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
      unique: true,
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
  }), "user_retries");

  private static readonly RunningSessions = mongoose.model("RunningSessions", new Schema({
    sessionId: {
      type: Schema.Types.String,
      required: true,
      immutable: true,
      unique: true
    },
    sessionReference: {
      type: Schema.Types.String,
      required: true,
      immutable: true
    },
    sessionKeyBits: {
      type: Schema.Types.Buffer,
      required: true,
      immutable: true,
      unique: true
    },
    sessionSigningKeyEx: {
      type: Schema.Types.Buffer,
      required: true,
      immutable: true,
      unique: true
    },
    sessionVerifyingKeyEx: {
      type: Schema.Types.Buffer,
      required: true,
      immutable: true,
      unique: true
    },
    lastRefreshedAt: {
      type: Schema.Types.Date,
      required: true,
      default: new Date(),
      expires: 60*60
    },
    accessedBundles: {
      type: Map,
      of: this.keyBundleSchema,
      required: false,
      default: new Map()
    }
  }), "running_sessions");

  private static readonly ChatRequestDeposit = mongoose.model("ChatRequestDeposit", chatRequestHeaderSchema.index({ addressedTo: "hashed" }).index({ addressedTo: 1, sessionId: 1 }, { unique: true }), "chat_request_deposit");

  private static readonly MessageDeposit = mongoose.model("MessageDeposit", messageHeaderSchema.index({ addressedTo: "hashed", sessionId: "hashed" }).index({ addressedTo: 1, sessionId: 1, messageId: 1 }, { unique: true }), "message_deposit");

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

  static async createNewUser(user: { username: string, userDetails: UserEncryptedData, authInfo: UserAuthInfo, x3dhInfo: UserEncryptedData, keyBundles: PublishKeyBundlesRequest }) {
    try {
      const newUser = new this.User(bufferReplaceForMongo(user));
      return (newUser === await newUser.save());
    }
    catch(err) {
      logError(err);
      return false;
    }
  }

  static async setSavedDetails(details: SavedDetails) {
    try {
      const { saveToken } = details;
      await this.SavedDetails.findOneAndDelete({ saveToken });
      return !!(await this.SavedDetails.create(bufferReplaceForMongo(details)));
    }
    catch(err) {
      logError(err);
      return false;
    }
  }

  static async getSavedDetails(saveToken: string) {
    const details = bufferReplaceFromLean(await this.SavedDetails.findOne({ saveToken }).lean());
    await this.SavedDetails.deleteOne({ saveToken });
    return details;
  }

  static async getUser(username: string) {
    const user = await this.User.findOne({ username }); 
    return user;
  }
  
  static async getLeanUser(username: string): Promise<any> {
    const user = bufferReplaceFromLean(await this.User.findOne({ username }).lean()); 
    return user;
  }

  static async getUserRetries(username: string) : Promise< { tries: number, allowsAt?: number }> {
    const retries = bufferReplaceFromLean(await this.UserRetries.findOne({ username }).lean()); 
    return retries ?? {};
  }

  static async updateUserRetries(username: string, allowsAt: number, tries: number = null) {
    const upd = tries !== null ? { tries, allowsAt } : { allowsAt };
    await this.UserRetries.updateOne({ username }, upd, { upsert: true });
  }

  static async addSession(session: RunningSession): Promise<boolean> {
    try { 
      const newSession = await this.RunningSessions.create(bufferReplaceForMongo(session));
      if (newSession) {
        const refresh = async (sessionId: string) => {
          await this.RunningSessions.updateOne({ sessionId }, { lastRefreshedAt: new Date() });
          this.timeouts.set(sessionId, setTimeout(() => refresh(sessionId), 30*1000));
        }
        await refresh(session.sessionId);
        return true;
      }
      return false;
    }
    catch(err) {
      logError(err);
      return false;
    }
  }

  static async addAccessedBundle(sessionId: string, username: string, bundle: KeyBundle): Promise<boolean> {
    const session = await this.RunningSessions.findOne({ sessionId });
    if (!session) return false;
    session.accessedBundles.set(username, bufferReplaceForMongo(bundle));
    session.lastRefreshedAt = new Date();
    await session.save();
    return true;
  }

  static async deleteSession(sessionId: string): Promise<boolean> {
    const timeout = this.timeouts.get(sessionId);
    if (timeout) {
      clearTimeout(timeout);
      this.timeouts.delete(sessionId);
    }
    return (await this.RunningSessions.deleteOne({ sessionId })).deletedCount === 1;
  }

  static async getSession(sessionId: string): Promise<RunningSession> {
    return bufferReplaceFromLean(await this.RunningSessions.findOne({ sessionId }).lean());
  }

  static async depositMessage(message: MessageHeader) {
    try {
      const userHandler = this.userHandlers.get(message.addressedTo);
      if (await userHandler?.depositMessage(message)) return true;
      const newMessage = new this.MessageDeposit(bufferReplaceForMongo(message));
      return (newMessage === await newMessage.save());
    }
    catch(err) {
      logError(err);
      return false;
    }
  }

  static async depositChatRequest(chatRequest: ChatRequestHeader) {
    try {
      const userHandler = this.userHandlers.get(chatRequest.addressedTo);
      if (await userHandler.depositChatRequest(chatRequest)) return true;
      const newChatRequest = new this.ChatRequestDeposit(bufferReplaceForMongo(chatRequest));
      return (newChatRequest === await newChatRequest.save());
    }
    catch(err) {
      logError(err);
      return false;
    }
  }

  static async retrieveMessages(addressedTo: string, then: (messages: any[]) => Promise<boolean>) {
    try {
      const messages = await this.MessageDeposit.find({ addressedTo }).lean().exec();
      if (await then(cleanLean(messages))) {
        return (await this.MessageDeposit.deleteMany({ addressedTo })).deletedCount === messages.length;
      }
      return false;
    }
    catch(err) {
      logError(err);
      return false;
    }
  }

  static async retrieveChatRequests(addressedTo: string, then: (messages: any[]) => Promise<boolean>) {
    try {
      const chatRequests = await this.MessageDeposit.find({ addressedTo }).lean().exec();
      if (await then(cleanLean(chatRequests))) {
        return (await this.ChatRequestDeposit.deleteMany({ addressedTo })).deletedCount === chatRequests.length;
      }
      return false;
    }
    catch(err) {
      logError(err);
      return false;
    }
  }

  static registerUserHandler(username: string, userHandler: MongoUserHandler) {
    this.userHandlers.set(username, userHandler);
  }

  static deregisterUserHandler(username: string) {
    this.userHandlers.delete(username);
  }
}

export class MongoUserHandler {
  private readonly username: string;
  private readonly ChatRequest: mongoose.Model<any>;
  private readonly UnprocessedMessage: mongoose.Model<any>;
  private readonly Message: mongoose.Model<any>;
  private readonly Chat: mongoose.Model<any>;
  private readonly notifyMessage: (message: MessageHeader | ChatRequestHeader) => void;

  private constructor(username: string, notifyMessage: (message: MessageHeader | ChatRequestHeader) => void) {
    this.username = username;
    this.ChatRequest = mongoose.model(`${username}ChatRequests`, chatRequestHeaderSchema.index({ timestamp: -1 }).index({ sessionId: 1 }, { unique: true }), `${username}_chat_requests`);
    this.UnprocessedMessage = mongoose.model(`${username}UnprocessedMessages`, messageHeaderSchema.index({ sessionId: "hashed", timestamp: -1 }).index({ sessionId: 1, messageId: 1 }, { unique: true }), `${username}_unprocessed_messages`);
    this.Message = mongoose.model(`${username}Messages`, messageSchema.index({ sessionId: "hashed", timestamp: -1 }).index({ sessionId: 1, messageId: 1 }, { unique: true }), `${username}_messages`);
    this.Chat = mongoose.model(`${username}Chats`, chatSchema.index({ lastActivity: -1 }), `${username}_chats`);
    this.notifyMessage = notifyMessage;
  }

  static async createHandler(username: string, notifyMessage: (message: MessageHeader | ChatRequestHeader) => void) {
    const userHandler = new MongoUserHandler(username, notifyMessage);
    MongoHandlerCentral.registerUserHandler(username, userHandler);
    await userHandler.retrieve();
    return userHandler;
  }

  private async retrieve() {
    MongoHandlerCentral.retrieveChatRequests(this.username, async (chatRequests) => {
      try {
        const inserted = await this.ChatRequest.insertMany(chatRequests, { lean: true });
        return (inserted.length === chatRequests.length); 
      }
      catch(err) {
        logError(err);
        return false;
      }
    });
    MongoHandlerCentral.retrieveMessages(this.username, async (messages) => {
      try {
        const inserted = await this.UnprocessedMessage.insertMany(messages, { lean: true });
        return (inserted.length === messages.length); 
      }
      catch(err) {
        logError(err);
        return false;
      }
    });
  }

  async depositMessage(message: MessageHeader) {
    try {
      if (message.addressedTo !== this.username) return false;
      const newMessage = new this.UnprocessedMessage(bufferReplaceForMongo(message));
      if (newMessage === await newMessage.save()) {
        this.notifyMessage?.(message);
        return true;
      }
      return false;
    }
    catch(err) {
      logError(err);
      return false;
    }
  }

  async depositChatRequest(chatRequest: ChatRequestHeader) {
    try {
      if (chatRequest.addressedTo !== this.username) return false;
      const newChatRequest = new this.ChatRequest(bufferReplaceForMongo(chatRequest));
      if (newChatRequest === await newChatRequest.save()) {
        this.notifyMessage?.(chatRequest);
        return true;
      }
      return false;
    }
    catch(err) {
      logError(err);
      return false;
    }
  }

  async getAllChats(): Promise<ChatData[]> {
    return bufferReplaceFromLean(await this.Chat.find().lean().exec());
  }

  async getAllRequests(): Promise<ChatRequestHeader[]> {
    return bufferReplaceFromLean(await this.ChatRequest.find().lean().exec());
  }

  async getUnprocessedMessages(sessionId: string): Promise<MessageHeader[]> {
    return bufferReplaceFromLean(await this.UnprocessedMessage.find({ sessionId }).lean().exec());
  }

  async getMessagesByNumber(sessionId: string, limit: number, olderThan = Date.now()): Promise<StoredMessage[]> {
    return bufferReplaceFromLean(await this.Message.find({ sessionId }).lt("timestamp", olderThan).sort( { timestamp: -1 }).limit(limit).lean().exec());
  }

  async getMessagesUptoTimestamp(sessionId: string, newerThan: number, olderThan = Date.now()): Promise<StoredMessage[]> {
    return bufferReplaceFromLean(await this.Message.find({ sessionId }).lt("timestamp", olderThan).gt("timestamp", newerThan).sort( { timestamp: -1 }).lean().exec());
  }

  async getMessagesUptoId(sessionId: string, messageId: string, olderThan = Date.now()): Promise<StoredMessage[]> {
    const message = await this.Message.findOne({ sessionId, messageId }).exec();
    if (!message) return null;
    const { timestamp } = message;
    return this.getMessagesUptoTimestamp(sessionId, timestamp, olderThan);
  }

  async getMessageById(sessionId: string, messageId: string): Promise<StoredMessage> {
    return await this.Message.findOne({ sessionId, messageId }).exec();
  }

  async deleteChatRequest(sessionId: string) {
    try {
      return (await this.ChatRequest.deleteOne({ sessionId })).deletedCount === 1
    }
    catch(err) {
      logError(err);
      return false;
    }
  }

  async storeMessage(message: StoredMessage) {
    try {
      const { sessionId } = message;
      await this.Message.deleteOne({ sessionId });
      const newMessage = new this.Message(bufferReplaceForMongo(message));
      if (newMessage === await newMessage.save()) {
        const { sessionId, messageId } = message;
        await this.UnprocessedMessage.deleteOne({ sessionId, messageId });
        return true;
      }
      return false;
    }
    catch(err) {
      logError(err);
      return false;
    }
  }

  async createChat(chat: { sessionId: string, lastActivity: number, chatDetails: UserEncryptedData, chattingSession: UserEncryptedData }) {
    try {
      const newChat = new this.Chat(bufferReplaceForMongo(chat));
      if (newChat === await newChat.save()) {
        const { sessionId } = chat;
        await this.ChatRequest.deleteOne({ sessionId });
        await this.UnprocessedMessage.deleteOne({ sessionId, messageId: "0" });
        return true;
      }
      return false;
    }
    catch(err) {
      logError(err);
      return false;
    }
  }

  async updateChat({ sessionId, ...chat }: { sessionId: string, lastActivity: number, chatDetails: UserEncryptedData, chattingSession: UserEncryptedData }) {
    try {
      return !!(await this.Chat.findOneAndUpdate({ sessionId }, bufferReplaceForMongo(chat)).exec());
    }
    catch(err) {
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

function logError(err: any): void {
  const message = err.message;
  const stack = err.stack;
  if (message || stack) {
    console.log(`${message}${stack}`);
  }
  else {
    console.log(`${err}`);
  }
}