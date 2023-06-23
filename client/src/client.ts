import _ from "lodash";
import { match } from "ts-pattern";
import axios from "axios";
import { io, Socket } from "socket.io-client";
import { SessionCrypto } from "../../shared/sessionCrypto";
import {  X3DHUser } from "./e2e-encryption";
import * as crypto from "../../shared/cryptoOperator";
import { serialize, deserialize } from "../../shared/cryptoOperator";
import * as esrp from "../../shared/ellipticSRP";
import { allSettledResults, awaitCallback, failure, fromBase64, logError, randomFunctions } from "../../shared/commonFunctions";
import { ErrorStrings, Failure, Username, SocketClientSideEvents, MessageHeader, ChatRequestHeader, StoredMessage, ChatData, SocketClientSideEventsKey, SocketServerSideEventsKey, SocketServerSideEvents, SocketClientRequestParameters, SocketClientRequestReturn, SignUpRequest, NewUserData, Profile, SignUpChallengeResponse, LogInRequest, LogInChallengeResponse, UserEncryptedData, SessionIdentifier, HeaderIdentifier, Backup, PasswordDeriveInfo, PasswordEntangleInfo  } from "../../shared/commonTypes";
import { noProfilePictureImage } from "./noProfilePictureImage";
import { AwaitedRequest, Chat, ChatDetails, ChatRequest } from "./chatClasses";
import AuthClient from "./AuthClient";

const { getRandomVector, getRandomString } = randomFunctions();
axios.defaults.withCredentials = true;

const chatMethods = ["SendMessage", "GetMessageHeaders", "GetMessagesByNumber", "GetMessagesUptoTimestamp", "GetMessagesUptoId", "GetMessageById", "StoreMessage", "MessageHeaderProcessed", "UpdateChat", "StoreBackup", "GetBackupById", "BackupProcessed", "SendReceipt", "GetAllReceipts", "ClearAllReceipts"] as const;

type ChatMethods = typeof chatMethods[number];

export enum ClientEvent {
    Disconnected,
    Connecting,
    Reconnecting,
    FailedToConnect,
    Connected,
    ServerUnavailable,
    SigningIn,
    FailedSignIn,
    ReAuthenticating,
    FailedReAuthentication,
    CreatingNewUser,
    FailedCreateNewUser,
    CreatedNewUser,
    SignedIn,
    SigningOut,
    SignedOut
}

export type ClientChatInterface = Pick<RequestMap, ChatMethods> & Readonly<{ isConnected: () => boolean, notifyClient: (chat: Chat) => void }>

export type ClientChatRequestInterface = Readonly<{
    rejectRequest: (otherUser: string, sessionId: string, oneTimeKeyId: string) => Promise<boolean>,
    acceptRequest: (request: ChatRequestHeader, respondingAt: number) => Promise<boolean>
}>;

type RequestMap = Readonly<{
    [E in SocketClientSideEventsKey]: (arg: SocketClientRequestParameters[E], timeout?: number) => Promise<SocketClientRequestReturn[E] | Failure>
}>

function SocketHandler(socket: () => Socket, sessionCrypto: () => SessionCrypto, isConnected: () => boolean): RequestMap {

    async function request(event: SocketClientSideEventsKey, data: any, timeout = 0): Promise<any | Failure> {
        if (!isConnected()) {
            return {};
        }
        const { payload } = await awaitCallback<any>(async (resolve) => {
            socket().emit(event, (await sessionCrypto().signEncryptToBase64(data, event)),
                async (response: string) => resolve(response ? await sessionCrypto().decryptVerifyFromBase64(response, event) : {}));
            if (timeout > 0) {
                window.setTimeout(() => resolve(failure(ErrorStrings.NoConnectivity)), timeout);
            }
        });
        return payload || failure(ErrorStrings.DecryptFailure);
    }

    function makeRequest(event: SocketClientSideEventsKey) {
        return (data: any, timeout = 0) => request(event, data, timeout);
    }

    const requestMap: any = {};
    let event: SocketClientSideEventsKey;
    for (event in SocketClientSideEvents) {
        requestMap[event] = makeRequest(event);
    }
    return requestMap as RequestMap;
}

export default class Client {
    private readonly responseMap: Map<SocketServerSideEventsKey, any> = new Map([
        [SocketServerSideEvents.RoomRequested, this.roomRequested] as [SocketServerSideEventsKey, any],
        [SocketServerSideEvents.MessageReceived, this.messageReceived],
        [SocketServerSideEvents.ChatRequestReceived, this.chatRequestReceived],
        [SocketServerSideEvents.ReceiptReceived, this.receiptReceived]
    ]);
    private readonly url: string;
    private notifyChange: () => void;
    #socket: Socket;
    #profile: Profile;
    #username: string;
    #x3dhUser: X3DHUser;
    #sessionCrypto: SessionCrypto
    #socketHandler: RequestMap;
    #encryptionBaseVector: CryptoKey;
    private readonly chatList = new Set<string>();
    private readonly chatSessionIdsList = new Map<string, Chat | ChatRequest | AwaitedRequest>();
    private readonly chatUsernamesList = new Map<string, Chat | ChatRequest | AwaitedRequest>();
    private chatInterface: ClientChatInterface;

    private static client: Client;
    
    static get isSignedIn() {
        return !!this.client;
    }

    static async initiate(url: string, encryptionBaseVector: CryptoKey, username: string, profile: Profile, x3dhUser: X3DHUser, sessionCrypto: SessionCrypto) {
        if (!this.client) {
            this.client = new Client(url, encryptionBaseVector, username, profile, x3dhUser, sessionCrypto);
            const connected = await this.client.connectSocket();
            if (connected) await this.client.loadUser(); 
        }
        return this.client;
    }

    static dispose() {
        this.client.dispose();
        this.client = null;
    }

    private constructor(url: string, encryptionBaseVector: CryptoKey, username: string, profile: Profile, x3dhUser: X3DHUser, sessionCrypto: SessionCrypto) {
        this.url = url;
        this.#encryptionBaseVector = encryptionBaseVector;
        this.#username = username;
        this.#profile = profile;
        this.#x3dhUser = x3dhUser;
        this.#sessionCrypto = sessionCrypto;
    }

    private dispose() {
        this.notifyChange = null;
        this.#socket.disconnect();
        this.#socket = null;
        this.#profile = null;
        this.#username = null;
        this.#x3dhUser = null;
        this.#sessionCrypto = null;
        this.#socketHandler = null;
        this.#encryptionBaseVector = null;
        this.chatList.clear();
        this.chatSessionIdsList.forEach((chat) => {
            if (chat.type === "Chat") {} // Dispose chat
        });
        this.chatSessionIdsList.clear();
        this.chatUsernamesList.clear();
        this.chatInterface = null;
    }

    private constructChatInterface() {
        const chatInterface: any = {};
        for (const method of chatMethods) {
            chatInterface[method] = this.#socketHandler[method];
        }
        chatInterface["isConnected"] = () => this.isConnected;
        chatInterface["notifyClient"] = (chat: Chat) => {
            if (this.notifyChange && this.getChatByUser(chat.otherUser) === chat) {
                this.notifyChange();
            }
        }
        return chatInterface as ClientChatInterface;
    }

    private addChat(chat: Chat | ChatRequest | AwaitedRequest) {
        this.chatSessionIdsList.set(chat.sessionId, chat);
        this.chatUsernamesList.set(chat.otherUser, chat);
        this.chatList.add(chat.otherUser);
        this.notifyChange?.();
    }

    private removeChat(key: string, keyType: "username" | "sessionId", dontNotify = false) {
        const chat = keyType === "username" ? this.chatUsernamesList.get(key) : this.chatSessionIdsList.get(key);
        this.chatSessionIdsList.delete(chat.sessionId);
        this.chatUsernamesList.delete(chat.otherUser);
        this.chatList.delete(chat.otherUser);
        if (chat.type === "Chat") {
            chat.disconnectRoom();
        }
        dontNotify || this.notifyChange?.();
    }

    public getChatByUser(otherUser: string): Chat | ChatRequest | AwaitedRequest {
        return this.chatUsernamesList.get(otherUser);
    }

    public get chatsList() {
        return _.orderBy(Array.from(this.chatList).map((user) => this.getChatByUser(user)), [(chat) => chat.lastActive], ["desc"]);
    }

    public get username(): string {
        return this.#username;
    }

    public get profile(): Profile {
        return { ...this.#profile };
    }

    public get isConnected(): boolean {
        return this.#socket?.connected ?? false;
    }

    subscribeChange(notifyCallback?: () => void) {
        if (notifyCallback) this.notifyChange = notifyCallback;
    }

    private async connectSocket() {
        try {
            if (!window.navigator.onLine) return false;
            if (!(await AuthClient.isLoggedIn())) return false;
            const response = await axios.get(`${this.url}/authNonce`);
            if (response?.status !== 200) return false;
            const { authNonce } = response.data;
            const username = this.#username;
            const authToken = await this.#sessionCrypto.signEncryptToBase64({ username, authNonce }, "Socket Auth");
            const auth = { authToken };
            this.#socket = io(this.url, { auth, withCredentials: true });
            this.#socket.on("disconnect", (err) => {});
            const success = await awaitCallback<boolean>(async (resolve) => {
                this.#socket.io.once("error", (error) => {
                    logError(error);
                    if ((error as any).type === "TransportError") console.log("Server unavailable.");
                    resolve(false);
                });
                this.#socket.once("connect_error", (error) => {
                    logError(error);
                    resolve(false);
                });
                this.#socket.once("connect", () => resolve(true));
                this.#socket.connect();
            }, 5000, false);
            if (success && this.#socket.connected) {
                this.#socketHandler = SocketHandler(() => this.#socket, () => this.#sessionCrypto, () => this.isConnected);
                this.chatInterface = this.constructChatInterface();
                for (const [event, response] of this.responseMap.entries()) {
                    this.#socket.on(event, async (data: string, respond) => await this.respond(event, data, response.bind(this), respond));
                }
            }
            return success;
        }
        catch(err) {
            logError(err);
            return;
        }
    }

    async checkUsernameExists(username: string) {
        const result = await this.#socketHandler.UsernameExists({ username });
        if ("reason" in result) {
            throw "Can't determine if username exists.";
        }
        return result.exists;
    }

    async sendChatRequest(otherUser: string, firstMessage: string, madeAt: number): Promise<Failure> {
        if (!this.isConnected) return failure(ErrorStrings.NoConnectivity);
        if (!(await this.checkUsernameExists(otherUser))) return failure(ErrorStrings.InvalidRequest);
        const keyBundleResponse = await this.#socketHandler.RequestKeyBundle({ username: otherUser });
        if ("reason" in keyBundleResponse) {
            logError(keyBundleResponse);
            return keyBundleResponse;
        }
        const { keyBundle } = keyBundleResponse;
        const { profile } = this;
        const messageId = getRandomString(15, "hex");
        const result = await this.#x3dhUser.generateChatRequest(keyBundle, messageId, firstMessage, madeAt, profile);
        if (typeof result === "string") {
            logError(result);
            return failure(ErrorStrings.ProcessFailed, result);
        }
        const [chatRequest, { sessionId, timestamp, myAlias, otherAlias }, x3dhInfo] = result;
        const result2 = await this.#socketHandler.RegisterPendingSession({ sessionId, otherAlias, myAlias });
        if (result2?.reason) {
            logError(result2);
            return failure(ErrorStrings.ProcessFailed);
        }
        const result3 = await this.#socketHandler.SendChatRequest(chatRequest);
        if (result3?.reason) {
            logError(result3);
            return failure(ErrorStrings.ProcessFailed);
        }
        const result4 = await this.#socketHandler.UpdateUserData({ x3dhInfo, username: this.username });
        if (result4?.reason) {
            logError(result4);
            return failure(ErrorStrings.ProcessFailed);
        }
        this.addChat(new AwaitedRequest(otherUser, sessionId, messageId, timestamp, firstMessage));
        return { reason: null };
    }

    private async loadUser() {
        for (const { sessionId, myAlias, otherAlias, messageId, timestamp, otherUser, text } of this.#x3dhUser.pendingChatRequests) {
            if (!(await this.processAwaitedRequest(sessionId, myAlias, otherAlias))) {
                const awaited = new AwaitedRequest(otherUser, sessionId, messageId, timestamp, text );
                this.addChat(awaited);
            }
        }
        await this.loadChats();
        await this.loadRequests();
    }

    private async processAwaitedRequest(sessionId: string, toAlias?: string, fromAlias?: string) {
        if (!toAlias) {
            const pending = this.#x3dhUser.pendingChatRequests.find((r) => r.sessionId === sessionId);
            if (!pending) return false;
            const { myAlias, otherAlias } = pending;
            toAlias = myAlias;
            fromAlias = otherAlias;
        }
        const result = await this.#socketHandler.GetMessageHeaders({ sessionId, toAlias, fromAlias });
        if ("reason" in result) {
            logError(result.reason);
            return false;
        }
        const firstResponse = _.orderBy(result, ["sendingRatchetNumber", "sendingChainNumber"], ["asc"])[0];
        if (firstResponse) return await this.receiveRequestResponse(firstResponse);
        else return false;
    }

    private async loadChats() {
        const chatsData = await this.#socketHandler.GetAllChats([]);
        if ("reason" in chatsData) return;
        const chats = await Promise.all(chatsData.map((chatData) => Chat.instantiate(this.#encryptionBaseVector, this.chatInterface, chatData)));
        for (const chat of chats) {
            this.addChat(chat);
        }
        Promise.all(chats.map((chat) => this.requestRoom(chat)));
    }

    private async loadRequest(request: ChatRequestHeader) {
        const result = await this.#x3dhUser.viewChatRequest(request);
        if (typeof result === "string") {
            logError(result);
            return false;
        }
        if (this.chatUsernamesList.get(result.profile.username)?.type === "ChatRequest") {
            logError("Duplicate request.");
            this.rejectRequest(result.sessionId, request.headerId, request.yourOneTimeKeyIdentifier);
            return false;
        }
        const chatRequest = new ChatRequest(request, {
            acceptRequest: (request: ChatRequestHeader, respondingAt: number) => this.acceptRequest(request, respondingAt),
            rejectRequest: (sessionId: string, headerId: string, oneTimeKeyId: string) => this.rejectRequest(sessionId, headerId, oneTimeKeyId)
        }, result);
        this.addChat(chatRequest);
        return true;
    }

    private async loadRequests() {
        const requests = await this.#socketHandler.GetAllRequests([]);
        if ("reason" in requests) {
            logError(requests);
            return false;
        }
        const successes = await allSettledResults(requests.map((r) => this.loadRequest(r)));
        return successes.every((s) => s);
    }

    private async acceptRequest(request: ChatRequestHeader, respondingAt: number) {
        const { headerId } = request;
        const { profile: myProfile } = this;
        const viewChatRequest = await this.#x3dhUser.viewChatRequest(request);
        let exportedChattingSession: UserEncryptedData;
        const response = await this.#x3dhUser.acceptChatRequest(request, respondingAt, myProfile, async (exported) => {
            exportedChattingSession = exported;
            return true;
        });
        if (typeof response === "string" || typeof viewChatRequest === "string") {
            logError(response);
            return false;
        }
        const { sessionId, profile, text, messageId, timestamp } = viewChatRequest;
        const { fromAlias, toAlias } = response;
        const registered = await this.#socketHandler.RegisterPendingSession({ sessionId, myAlias: fromAlias, otherAlias: toAlias });
        if (registered?.reason) {
            logError(registered);
            return false;
        }
        const sent = await this.#socketHandler.SendMessage(response);
        if (sent?.reason) {
            logError(sent);
            return false;
        }
        const chatId = getRandomString(15, "base64");
        const details = { chatId, contactDetails: profile, timeRatio: _.random(1, 999) };
        const chatDetails = await crypto.deriveEncrypt(details, this.#encryptionBaseVector, "ChatDetails");
        const chatData: ChatData = { chatId, chatDetails, exportedChattingSession };
        await this.#socketHandler.CreateChat(chatData);
        await this.#socketHandler.DeleteChatRequest({ headerId });
        await this.#socketHandler.UpdateUserData({ username: this.username });
        const newChat = await Chat.instantiate(this.#encryptionBaseVector, this.chatInterface, chatData, { text, messageId, sentByMe: false, timestamp, respondedAt: respondingAt });
        this.removeChat(sessionId, "sessionId", true);
        this.addChat(newChat);
        return true;
    }

    private async rejectRequest(sessionId: string, headerId: string, oneTimeKeyId: string) {
        const result = await this.#socketHandler.DeleteChatRequest({ headerId });
        if (result.reason) {
            logError(result);
            return false;
        }
        this.#x3dhUser.disposeOneTimeKey(oneTimeKeyId);
        this.removeChat(sessionId, "sessionId");
        return true;
    }

    private async receiveRequestResponse(message: MessageHeader) {
        const { sessionId, headerId, toAlias, fromAlias } = message;
        const awaitedRequest = this.chatSessionIdsList.get(sessionId);
        if (!awaitedRequest || awaitedRequest.type !== "AwaitedRequest") {
            return false;
        }
        let exportedChattingSession: UserEncryptedData;
        const profileResponse = await this.#x3dhUser.receiveChatRequestResponse(message, async (exported) => {
            exportedChattingSession = exported;
            return true;
        });
        if (typeof profileResponse === "string") {
            logError(profileResponse);
            return false;
        }
        await this.#socketHandler.GetMessageHeaders({ sessionId, toAlias, fromAlias });
        const { messageId, text, timestamp } = awaitedRequest.chatMessage.displayMessage;
        const { profile, respondedAt } = profileResponse;
        const chatId = getRandomString(15, "base64");
        const details = { chatId, contactDetails: profile, timeRatio: _.random(1, 999) };
        const chatDetails = await crypto.deriveEncrypt(details, this.#encryptionBaseVector, "ChatDetails");
        const chatData: ChatData = { chatId, chatDetails, exportedChattingSession };
        const { reason } = await this.#socketHandler.CreateChat(chatData);
        if (reason) {
            logError(reason);
            return false;
        }
        const x3dhInfo = await this.#x3dhUser.deleteWaitingRequest(sessionId);
        const { reason: r2 } = await this.#socketHandler.UpdateUserData({ x3dhInfo, username: this.username });
        if (r2) {
            logError(r2);
        }
        await this.#socketHandler.MessageHeaderProcessed({ sessionId, headerId, toAlias });
        const newChat = await Chat.instantiate(this.#encryptionBaseVector, this.chatInterface, chatData, { messageId, text, timestamp, sentByMe: true, respondedAt });
        this.removeChat(sessionId, "sessionId", true);
        this.addChat(newChat);
        await this.requestRoom(newChat);
        return true;
    }

    private async respond(event: string, data: string, responseBy: (arg0: any) => any, respondAt: (arg0: string) => void) {
        const respond = async (response: any) => {
            respondAt(await this.#sessionCrypto.signEncryptToBase64(response, event));
        }
        try {
            const decryptedData = await this.#sessionCrypto.decryptVerifyFromBase64(data, event);
            if (!decryptedData) await respond(failure(ErrorStrings.DecryptFailure));
            else {
                const response = await responseBy(decryptedData);
                if (!response) await respond(failure(ErrorStrings.ProcessFailed));
                else {
                    respond(response);
                }
            }
        }
        catch (err) {
            logError(err)
            respond(failure(ErrorStrings.ProcessFailed, err));
        }
    }

    private awaitServerRoomReady(otherUsername: string) {
        return new Promise<boolean>((resolve) => {
            const response = (withUser: string) => {
                if (withUser === otherUsername) {
                    this.#socket.off(SocketServerSideEvents.ServerRoomReady, response);
                    resolve(true);
                }
            };
            this.#socket.on(SocketServerSideEvents.ServerRoomReady, response);
            setTimeout(() => {
                this.#socket.off(SocketServerSideEvents.ServerRoomReady, response);
                resolve(false);
            }, 1000);
        });
    }

    private async roomRequested({ username }: Username) {
        if (username === this.#username) return failure(ErrorStrings.InvalidRequest);
        const chat = this.chatUsernamesList.get(username);
        if (!chat || chat.type !== "Chat") return failure(ErrorStrings.InvalidRequest);
        this.awaitServerRoomReady(username).then((ready) => {
            if (ready) {
                chat.establishRoom(this.#sessionCrypto, this.#socket);
            }
        })
        return { reason: null };
    }

    private async requestRoom(chat: Chat) {
        const waitReady = this.awaitServerRoomReady(chat.otherUser);
        const response = await this.#socketHandler.RequestRoom({ username: chat.otherUser }, 2000);
        if (response.reason) {
            return response;
        }

        const confirmed = await waitReady.then(async (ready) => {
            return ready ? await chat.establishRoom(this.#sessionCrypto, this.#socket) : false;
        });
        if (!confirmed) return failure(ErrorStrings.ProcessFailed);
        return { reason: null };
    }

    private async messageReceived({ sessionId }: { sessionId: string }) {
        return await match(this.chatSessionIdsList.get(sessionId)?.type)
            .with("Chat", () => (this.chatSessionIdsList.get(sessionId) as Chat)?.loadUnprocessedMessages())
            .with("AwaitedRequest", () => this.processAwaitedRequest(sessionId))
            .otherwise(async () => false);
    }

    private async receiptReceived({ sessionId }: { sessionId: string }) {
        const chat = this.chatSessionIdsList.get(sessionId);
        if (chat?.type === "Chat") {
            await chat.loadAndProcessReceipts();
        }
    }

    private async chatRequestReceived() {
        return await this.loadRequests();
    }
}