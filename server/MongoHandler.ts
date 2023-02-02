import _ from "lodash";
import { Binary } from "mongodb";
import * as mongoose from "mongoose";
import { Schema } from "mongoose";
import { Buffer } from "./node_modules/buffer/";
import { Buffer as NodeBuffer } from "node:buffer";
import { SavedDetails } from "../shared/commonTypes";

export type RunningSession = {
  sessionId: string;
  sessionReference: string;
  sessionKeyBits: Buffer,
  sessionSigningKeyEx: Buffer,
  sessionVerifyingKeyEx: Buffer,
  lastRefreshedAt?: Date
}

export class MongoHandler {

  private readonly timeouts = new Map<string, NodeJS.Timeout>();

  private readonly exposedSignedKey = {
    exportedPublicKey: {
      type: Schema.Types.Buffer,
      required: true
    },
    signature: {
      type: Schema.Types.Buffer,
      required: true
    }
  };
  
  private readonly signedEncryptedData = {
    ciphertext: {
      type: Schema.Types.Buffer,
      required: true
    },
    signature: {
      type: Schema.Types.Buffer,
      required: true
    }
  };
  
  private readonly keyBundleSchema = new Schema({
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
    publicDHIdentityKey: this.exposedSignedKey,
    publicSignedPreKey: this.exposedSignedKey,
    publicOneTimeKey: this.exposedSignedKey
  });
  
  private readonly messageHeaderSchema = new Schema({
    addressedTo: {
      type: Schema.Types.String,
      required: true
    },
    sessionId: {
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
    nextDHRatchetKey: this.exposedSignedKey,
    messageBody: this.signedEncryptedData
  });
  
  private readonly messageRequestHeaderSchema = new Schema({
    addressedTo: {
      type: Schema.Types.String,
      required: true
    },
    myVerifyingIdentityKey: {
      type: Schema.Types.Buffer,
      required: true
    },
    myPublicDHIdentityKey: this.exposedSignedKey,
    myPublicEphemeralKey: this.exposedSignedKey,
    yourOneTimeKeyIdentifier: {
      type: Schema.Types.Number,
      required: false
    },
    yourSignedPreKeyVersion: {
      type: Schema.Types.String,
      required: true
    },
    initialMessage: this.signedEncryptedData
  });

  private readonly passwordDeriveInfo = {
    pSalt: {
      type: Schema.Types.Buffer,
      required: true
    },
    iterSeed: {
      type: Schema.Types.Number,
      required: true
    }
  }
  
  private readonly userEncryptedData = {
    ciphertext: {
      type: Schema.Types.Buffer,
      required: true
    },
    hSalt: {
      type: Schema.Types.Buffer,
      required: true
    }
  };
  
  private readonly passwordEncryptedData = {
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
  
  private readonly chatBundleSchema = new Schema({
    bundleId: {
      type: Schema.Types.String,
      required: true
    },
    messageIds: {
      type: [Schema.Types.String],
      required: true
    },
    chatBundle: this.userEncryptedData
  });
  
  private readonly chatSchema = new Schema({
    chattingSession: this.userEncryptedData,
    chatHistory: {
      type: [this.chatBundleSchema],
      required: true
    }
  });

  private readonly SavedDetails = mongoose.model("SavedDetails", new Schema({
    saveToken: {
      type: Schema.Types.String,
      required: true,
      immutable: true,
      unique: true
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

  readonly User = mongoose.model("User", new Schema({
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
    displayName: {
      type: Schema.Types.String,
      required: true,
      default: function() { return this.username; },
      index: true,
      trim: true,
      minLength: 1
    },
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
    x3dhInfo: this.userEncryptedData,
    keyBundles: {
      defaultKeyBundle: {
        type: this.keyBundleSchema,
        required: false,
        default: null
      },
      oneTimeKeyBundles: {
        type: [this.keyBundleSchema],
        required: false
      },
    },
    accessedKeyBundles: {
      type: [Schema.Types.String],
      required: false,
      default: []
    },
    chats: {
      type: [this.chatSchema],
      required: true,
      default: []
    },
    unprocessedRequests: {
      type: [this.messageRequestHeaderSchema],
      required: true,
      default: []
    },
    unprocessedMessages: {
      type: [this.messageHeaderSchema],
      required: true,
      default: []
    }
  }), "users");

  private readonly UserRetries = mongoose.model("UserRetries", new Schema({
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

  private readonly RunningSessions = mongoose.model("RunningSessions", new Schema({
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
    }
  }), "running_sessions");

  constructor(mongoDb: string) {
    mongoose.connect(mongoDb);
  }

  async setSavedDetails(details: SavedDetails) {
    try { 
      return !!(await this.SavedDetails.create(bufferReplaceForMongo(details)));
    }
    catch(err) {
      logError(err);
      return false;
    }
  }

  async getSavedDetails(saveToken: string) {
    const details = bufferReplaceFromLean(await this.SavedDetails.findOne({ saveToken }).lean());
    await this.SavedDetails.deleteOne({ saveToken });
    return details;
  }

  async getUser(username: string) {
    const user = await this.User.findOne({ username }); 
    return user;
  }
  
  async getLeanUser(username: string): Promise<any> {
    const user = bufferReplaceFromLean(await this.User.findOne({ username }).lean()); 
    return user;
  }

  async getUserRetries(username: string) : Promise< { tries: number, allowsAt?: number }> {
    const retries = bufferReplaceFromLean(await this.UserRetries.findOne({ username }).lean()); 
    return retries ?? {};
  }

  async updateUserRetries(username: string, allowsAt: number, tries: number = null) {
    const upd = tries !== null ? { tries, allowsAt } : { allowsAt };
    await this.UserRetries.updateOne({ username }, upd, { upsert: true });
  }

  async addSession(session: RunningSession): Promise<boolean> {
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

  async deleteSession(sessionId: string): Promise<boolean> {
    const timeout = this.timeouts.get(sessionId);
    if (timeout) {
      clearTimeout(timeout);
      this.timeouts.delete(sessionId);
    }
    return (await this.RunningSessions.deleteOne({ sessionId })).deletedCount === 1;
  }

  async getSession(sessionId: string): Promise<RunningSession> {
    return bufferReplaceFromLean(await this.RunningSessions.findOne({ sessionId }).lean());
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
    return Array.from(obj.map(v => this.bufferReplaceFromLean(v)));
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