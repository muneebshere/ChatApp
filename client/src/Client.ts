import _ from "lodash";
import { match } from "ts-pattern";
import axios from "axios";
import { io, Socket } from "socket.io-client";
import { SessionCrypto } from "../../shared/sessionCrypto";
import {  ChattingSession, ViewReceivedRequest, X3DHManager } from "./e2e-encryption";
import * as crypto from "../../shared/cryptoOperator";
import { allSettledResults, awaitCallback, failure, fromBase64, logError, randomFunctions } from "../../shared/commonFunctions";
import { ErrorStrings, Failure, Username, SocketClientSideEvents, MessageHeader, ChatRequestHeader, ChatData, SocketClientSideEventsKey, SocketServerSideEventsKey, SocketServerSideEvents, SocketClientRequestParameters, SocketClientRequestReturn, Profile, EncryptedData, SocketServerRequestParameters, SocketServerRequestReturn, ServerMemo, KeyBundleId, SignedEncryptedData, X3DHKeysData, X3DHData  } from "../../shared/commonTypes";
import { SentChatRequest, Chat, ReceivedChatRequest } from "./ChatClasses";
import AuthClient, { isClientOnline } from "./AuthClient";

const { getRandomString } = randomFunctions();
axios.defaults.withCredentials = true;

const chatMethods = ["SendMessage", "GetMessageHeaders", "GetMessagesByNumber", "GetMessagesUptoTimestamp", "GetMessagesUptoId", "GetMessageById", "StoreMessage", "MessageHeaderProcessed", "UpdateChat", "StoreBackup", "GetBackupById", "BackupProcessed", "SendReceipt", "GetAllReceipts", "ClearAllReceipts"] as const;

type ChatMethods = typeof chatMethods[number];

export type ConnectionStatus = "NotLoaded" | "NotLoggedIn" | "ClientOffline" | "ServerUnreachable" | "Unauthenticated" | "UnknownConnectivityError" | "Online" | "LoggingOut";

export type ClientChatInterface = Pick<RequestMap, ChatMethods> & Readonly<{
    isConnected: () => boolean, 
    notifyClient: (chat: Chat) => void,
    importChattingSession: (encryptedSession: EncryptedData) => Promise<ChattingSession> }>

export type ClientReceivedChatRequestInterface = Readonly<{
    rejectReceivedRequest: (sessionId: string) => Promise<boolean>,
    acceptReceivedRequest: (sessionId: string, respondingAt: number) => Promise<boolean>
}>;

type RequestMap = Readonly<{
    [E in SocketClientSideEventsKey]: (arg: SocketClientRequestParameters[E], timeout?: number) => Promise<SocketClientRequestReturn[E] | Failure>
}>

function SocketHandler(socket: () => Socket, sessionCrypto: () => SessionCrypto, isConnected: () => boolean): RequestMap {

    async function request<E extends SocketClientSideEventsKey>(event: E, data: SocketClientRequestParameters[E], timeout = 0): Promise<SocketClientRequestReturn[E] | Failure> {
        if (!isConnected()) {
            return failure(ErrorStrings.NoConnectivity);
        }
        const { payload } = await awaitCallback<any>(async (resolve) => {
            socket().emit(event, (await sessionCrypto()?.signEncryptToBase64({ payload: data }, event)),
                async (response: string) => resolve((response && await sessionCrypto()?.decryptVerifyFromBase64(response, event)) || {}));
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
        [SocketServerSideEvents.RequestIssueNewKeys, this.issueNewKeys],
        [SocketServerSideEvents.PollConnection, this.indicateConnectionAlive],
        [SocketServerSideEvents.ServerMemoDeposited, this.receiveServerMemos],
        [SocketServerSideEvents.MessageReceived, this.messageReceived],
        [SocketServerSideEvents.ChatRequestReceived, this.chatRequestReceived],
        [SocketServerSideEvents.ReceiptReceived, this.receiptReceived],
        [SocketServerSideEvents.ServerDisconnecting, this.setDisconnectReason]
    ]);
    private readonly url: string;
    private notifyStatus: (status: ConnectionStatus) => void;
    private notifyChange: () => void;
    private countdownTick: (tryingAgainIn: number) => void;
    private countdownTimer = 0;
    private countdownTimeout = null;
    private connecting = false;
    private reconnecting = false;
    private initiated = false;
    private disconnectReason = "";

    #socket: Socket;
    #profile: Profile;
    #username: string;
    #x3dhManager: X3DHManager;
    #sessionCrypto: SessionCrypto
    #socketHandler: RequestMap;
    #encryptionBaseVector: CryptoKey;
    #sessionRecordKey: Buffer;
    #serverVerifyingKey: CryptoKey;
    private readonly chatList = new Set<string>();
    private readonly chatSessionIdsList = new Map<string, Chat | ReceivedChatRequest | SentChatRequest>();
    private readonly chatUsernamesList = new Map<string, Chat | ReceivedChatRequest | SentChatRequest>();
    private chatInterface: ClientChatInterface;
    private receivedChatRequestInterface: ClientReceivedChatRequestInterface;

    private static client: Client;
    private static loadedClient: Promise<Client>;
    private static resolveClient: () => void;

    private set tryingAgainIn(value: number) {
        if (value <= 0) {
            this.countdownTimer = 0;
            if (this.countdownTimeout) {
                window.clearInterval(this.countdownTimeout);
                console.log("Interval cleared");
                this.countdownTimeout = null;
            }
            this.reconnect();
        }
        else this.countdownTimer = value;
        this.countdownTick?.(this.countdownTimer);
    }

    private get tryingAgainIn() {
        return this.countdownTimer;
    }
    
    static get isLoggedIn() {
        return !!this.client;
    }

    static async connectionStatus(): Promise<ConnectionStatus> {
        if (!this.client) return "NotLoggedIn";
        if (this.client.isConnected) return "Online";
        if (!(await isClientOnline())) return "ClientOffline";
        if (!(await AuthClient.isServerReachable())) return "ServerUnreachable";
        const authenticated = await this.client.confirmAuthenticated();
        if (authenticated === false) return "Unauthenticated";
        else return "UnknownConnectivityError";
    }

    static async initiate(url: string, encryptionBaseVector: CryptoKey, sessionRecordKey: Buffer, username: string, profile: Profile, x3dhManager: X3DHManager, sessionCrypto: SessionCrypto, serverVerifyingKey: CryptoKey) {
        if (!this.client) {
            this.client = new Client(url, encryptionBaseVector, sessionRecordKey, username, profile, x3dhManager, sessionCrypto, serverVerifyingKey);
            Client.loadedClient = new Promise<Client>((resolve) => this.resolveClient = () => {
                resolve(this.client);
                this.resolveClient = null;
            });
            const connected = await this.client.connectSocket(true);
            if (connected) await this.client.loadUser();
        }
        return await this.loadedClient;
    }

    static dispose(loggingOut?: "logging-out") {
        this.client.dispose(loggingOut);
        this.client = null;
    }

    private constructor(url: string, encryptionBaseVector: CryptoKey, sessionRecordKey: Buffer, username: string, profile: Profile, x3dhManager: X3DHManager, sessionCrypto: SessionCrypto, serverVerifyingKey: CryptoKey) {
        this.url = url;
        this.#encryptionBaseVector = encryptionBaseVector;
        this.#sessionRecordKey = sessionRecordKey;
        this.#username = username;
        this.#profile = profile;
        this.#x3dhManager = x3dhManager;
        this.#sessionCrypto = sessionCrypto;
        this.#serverVerifyingKey = serverVerifyingKey;
    }

    private async getAuthToken() {
        const { nonceId, authNonce } = await AuthClient.getAuthNonce();
        if (!authNonce) return {};
        const username = this.#username;
        const authToken = await this.#sessionCrypto?.signEncryptToBase64({ username, authNonce }, "Socket Auth");
        return { nonceId, authToken };
    }

    private async confirmAuthenticated() {
        const authenticated = await AuthClient.isAuthenticated();
        if (authenticated === false) return false;
        const { authToken } = await this.getAuthToken();
        if (!authToken) return null;
        return await AuthClient.verifyAuthentication(fromBase64(authToken).toString("hex"), this.#sessionRecordKey.toString("hex"));
    }

    private async connectSocket(first = false) {
        try {
            this.connecting = true;
            const status = await Client.connectionStatus();
            this.notifyStatus?.(status);
            if (status === "ClientOffline" || status === "ServerUnreachable" || status === "Unauthenticated") return this.connecting = false;
            const { nonceId, authToken } = await this.getAuthToken();
            if (!authToken) return this.connecting = false;
            const sessionRecordKey = this.#sessionRecordKey.toString("base64");
            const auth = { authToken, nonceId, sessionRecordKey };
            this.#socket = io(this.url, { auth, withCredentials: true });
            this.#socket.on("disconnect", (err) => {
                console.log("Socket disconnected.");
                console.log(this.disconnectReason);
                logError(err);
                if (this.disconnectReason) AuthClient.terminateCurrentSession("logging-out");
                else this.reconnect();
            });
            const success = (await awaitCallback<boolean>(async (resolve) => {
                this.#socket.io.once("error", (err) => {
                    logError(err);
                    if ((err as any).type === "TransportError") console.log("Server unavailable.");
                    resolve(false);
                });
                this.#socket.once("connect_error", (err) => {
                    console.log("Server rejected socket connection.");
                    logError(err);
                    resolve(false);
                });
                this.#socket.once("connect", () => resolve(true));
                this.#socket.connect();
            }, 5000, false)) && this.isConnected;
            if (success) {
                this.#socketHandler = SocketHandler(() => this.#socket, () => this.#sessionCrypto, () => this.isConnected);
                this.constructChatInterface();
                for (const [event, response] of this.responseMap.entries()) {
                    this.#socket.on(event, async (data: string, respond) => await this.respond(event, data, response.bind(this), respond));
                }
            }
            await AuthClient.clearNonce();
            this.connecting = false;
            if (!success && !this.reconnecting) this.reconnect();
            if (!first && !this.initiated) this.loadUser();
            return success;
        }
        catch(err) {
            logError(err);
            return this.connecting = false;
        }
    }

    private async reconnect() {
        if (this.isConnected || this.connecting || this.tryingAgainIn > 0) return;
        this.reconnecting = true;
        this.notifyStatus?.(await Client.connectionStatus());
        const success = await this.connectSocket();
        this.reconnecting = false;
        this.notifyStatus?.(await Client.connectionStatus());
        if (success) {
            _.map(Array.from(this.chatSessionIdsList.values())
                .map((chat) => chat.type === "Chat" ? chat : null)
                .filter((chat) => !!chat),
                    async (chat) => {
                        await chat.checkNew();
                        await this.requestRoom(chat); 
            })
            _.map(this.#x3dhManager.allPendingSentRequests,
                    async ({ sessionId, myAlias, otherAlias }) => {
                        await this.processSentRequest(sessionId, myAlias, otherAlias);
            });
        }
        else {
            this.tryingAgainIn = 5000;
            this.countdownTimeout = window.setInterval(() => this.tryingAgainIn -= 20, 20);
            console.log("Interval set");
        }
    }

    private dispose(loggingOut?: "logging-out") {
        this.notifyChange?.();
        this.notifyStatus?.("LoggingOut");
        this.#socket.removeAllListeners();
        this.#socket.disconnect();
        this.#socket = null;
        this.#profile = null;
        this.#username = null;
        this.#x3dhManager = null;
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
        this.receivedChatRequestInterface = null;
        if (loggingOut) this.notifyStatus?.("NotLoggedIn");
        this.notifyChange = null;
        this.notifyStatus = null;
    }

    private setDisconnectReason({ reason }: { reason: string }) {
        this.disconnectReason = reason;
        return {};
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
        chatInterface["importChattingSession"] = async (encryptedSession: EncryptedData) => this.#x3dhManager.importChattingSession(encryptedSession);
        this.chatInterface = chatInterface;
        this.receivedChatRequestInterface = {
            acceptReceivedRequest: (sessionId: string, respondingAt: number) => this.acceptReceivedRequest(sessionId, respondingAt),
            rejectReceivedRequest: (sessionId: string) => this.rejectReceivedRequest(sessionId)
        }
    }

    private addChat(chat: Chat | ReceivedChatRequest | SentChatRequest) {
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

    public getChatByUser(otherUser: string): Chat | ReceivedChatRequest | SentChatRequest {
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
        return this.#socket?.connected || false;
    }

    subscribeChange(notifyCallback?: () => void) {
        this.notifyChange = notifyCallback;
        notifyCallback?.();
    }

    subscribeStatus(notifyCallback?: (status: ConnectionStatus) => void) {
        this.notifyStatus = notifyCallback;
        Client.connectionStatus().then((status) => notifyCallback?.(status));
    }

    subscribeCountdownTick(tickCallback?: (tryingAgainIn: number) => void) {
        this.countdownTick = tickCallback;
        tickCallback?.(this.countdownTimer);
    }

    forceReconnect() {
        this.tryingAgainIn = -1;
    }

    pauseCountdownTick() {
        if (this.countdownTimeout) {
            window.clearInterval(this.countdownTimeout);
            console.log("Interval cleared");
            this.countdownTimeout = null;
        }
    }

    resumeCountdownTick() {
        if (!this.countdownTimeout) {
            this.countdownTimeout = window.setInterval(() => this.tryingAgainIn -= 20, 20);
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
        const messageId = `f${getRandomString(14, "hex")}`;
        const result = await this.#x3dhManager.generateChatRequest(keyBundle, messageId, firstMessage, madeAt, profile);
        if (typeof result === "string") {
            logError(result);
            return failure(ErrorStrings.ProcessFailed, result);
        }
        const [x3dhData, chatRequest, { sessionId, timestamp, myAlias, otherAlias }] = result;
        const result2 = await this.#socketHandler.RegisterPendingSession({ sessionId, otherAlias, myAlias });
        if (result2?.reason !== false) {
            logError(result2);
            return failure(ErrorStrings.ProcessFailed);
        }
        const result3 = await this.#socketHandler.SendChatRequest(chatRequest);
        if (result3?.reason !== false) {
            logError(result3);
            return failure(ErrorStrings.ProcessFailed);
        }
        const result4 = await this.#socketHandler.UpdateX3DHData({ x3dhData });
        if (result4?.reason !== false) {
            logError(result4);
            return failure(ErrorStrings.ProcessFailed);
        }
        this.addChat(new SentChatRequest(otherUser, sessionId, messageId, timestamp, firstMessage));
        return { reason: false };
    }

    private async instantiateChat(chatData: ChatData, removePrevious: string, firstMessage?: { messageId: string, text: string, timestamp: number, sentByMe: boolean, respondedAt: number }) {
        const chat = await Chat.instantiate(this.#encryptionBaseVector, this.chatInterface, chatData, firstMessage);
        return await awaitCallback(async (resolve) => {
            chat.subscribeActivity(() => {
                if (chat.details?.lastActivity?.messageId) {
                    chat.unsubscribeActivity();
                    if (removePrevious) this.removeChat(removePrevious, "sessionId", true);
                    this.addChat(chat);
                    this.requestRoom(chat);
                    resolve(true);
                }
            });
        });
    }

    private async loadUser() {
        const result = await this.#socketHandler.FetchX3DHData([]);
        if (!("reason" in result)) {
            const { x3dhIdentity, x3dhData } = result;
            this.#x3dhManager = await X3DHManager.import(this.username, x3dhIdentity, x3dhData, this.#encryptionBaseVector);
        }
        await Promise.all([this.loadChats(), this.fetchNewReceivedRequests().then(() => this.loadReceivedRequests()), this.loadSentRequests()]);
        this.initiated = true;
        Client.resolveClient?.();
        this.#socketHandler.ClientLoaded([], 100);
    }

    private async loadChats() {
        const chatsData = await this.#socketHandler.GetAllChats([]);
        if ("reason" in chatsData) return;
        await Promise.all(_.map(chatsData, async (chatData) => this.instantiateChat(chatData, "")));
    }

    private async loadReceivedRequests() {
        const successes = await Promise.all(_.map(this.#x3dhManager.allPendingReceivedRequests, 
            async (receivedRequest) => {
                this.addChat(new ReceivedChatRequest(this.receivedChatRequestInterface, receivedRequest));
        }));
        return successes.every((s) => s);
    }

    private async loadSentRequests() {
        const successes = await Promise.all(_.map(this.#x3dhManager.allPendingSentRequests, 
            async ({ sessionId, myAlias, otherAlias, messageId, timestamp, otherUser, text }) => {
                if (!(await this.processSentRequest(sessionId, myAlias, otherAlias)))
                    this.addChat(new SentChatRequest(otherUser, sessionId, messageId, timestamp, text ));
        }));
        return successes.every((s) => s);
    }

    private async processSentRequest(sessionId: string, toAlias?: string, fromAlias?: string) {
        if (!toAlias) {
            const pending = this.#x3dhManager.getPendingSentRequest(sessionId);
            if (!pending) return false;
            const { myAlias, otherAlias } = pending;
            toAlias = myAlias;
            fromAlias = otherAlias;
        }
        const result = await this.#socketHandler.GetMessageHeaders({ sessionId, toAlias, fromAlias });
        if ("reason" in result) {
            logError(result);
            return false;
        }
        const firstResponse = _.orderBy(result, ["sendingRatchetNumber", "sendingChainNumber"], ["asc"])[0];
        if (firstResponse) return await this.receiveSentRequestResponse(firstResponse);
        else return false;
    }

    private async receiveSentRequestResponse(message: MessageHeader) {
        const { sessionId, headerId, toAlias, fromAlias } = message;
        const sentRequest = this.chatSessionIdsList.get(sessionId);
        if (!sentRequest || sentRequest.type !== "SentRequest") {
            return false;
        }
        let exportedChattingSession: EncryptedData;
        const profileResponse = await this.#x3dhManager.receiveChatRequestResponse(message, async (exported) => {
            exportedChattingSession = exported;
            return true;
        });
        if (typeof profileResponse === "string") {
            logError(profileResponse);
            return false;
        }
        const [x3dhData, { profile, respondedAt }] = profileResponse;
        await this.#socketHandler.GetMessageHeaders({ sessionId, toAlias, fromAlias });
        const { messageId, text, timestamp } = sentRequest.chatMessage.displayMessage;
        const chatId = getRandomString(15, "base64");
        const details = { chatId, contactDetails: profile, timeRatio: _.random(1, 999) };
        const chatDetails = await crypto.deriveEncrypt(details, this.#encryptionBaseVector, "ChatDetails");
        const chatData: ChatData = { chatId, chatDetails, exportedChattingSession };
        const x3dhInfo = await this.#x3dhManager.deleteSentRequest(sessionId);
        const { reason: r1 } = await this.#socketHandler.UpdateX3DHData({ x3dhData });
        if (r1) {
            logError(r1);
            return false;
        }
        const { username: otherUser } = profile;
        const { reason: r2 } = await this.#socketHandler.CreateChat({ ...chatData, otherUser });
        if (r2) {
            logError(r2);
            return false;
        }
        await this.#socketHandler.MessageHeaderProcessed({ sessionId, headerId, toAlias });
        await this.instantiateChat(chatData, sessionId, { messageId, text, timestamp, sentByMe: true, respondedAt });
        return true;
    }

    private async fetchNewReceivedRequests() {
        const requests = await this.#socketHandler.GetAllRequests([]);
        if ("reason" in requests) {
            logError(requests);
            return false;
        }
        const successes = await allSettledResults(requests.map((r) => this.processNewReceivedRequest(r)));
        return successes.every((s) => s);
    }

    private async processNewReceivedRequest(request: ChatRequestHeader) {
        let deleteFromServer = true;
        let success = false;
        const result = await this.#x3dhManager.processReceivedChatRequest(request);
        if (typeof result === "string") {
            logError(result);
            if (result === "Unknown Error") deleteFromServer = false;
        }
        else {
            const [x3dhData, receivedRequest] = result;
            if ((await this.#socketHandler.UpdateX3DHData({ x3dhData }))?.reason !== false) {
                logError(result);
                deleteFromServer = false;
            }
            else success = !!receivedRequest;
        }
        if (deleteFromServer && (await this.#socketHandler.DeleteChatRequest({ headerId: request.headerId }))?.reason !== false) {
            logError(result);
            return false;
        }
        else return success;
    }

    private async acceptReceivedRequest(sessionId: string, respondingAt: number) {
        const { profile: myProfile } = this;
        const viewChatRequest = this.#x3dhManager.getPendingReceivedRequest(sessionId);
        let exportedChattingSession: EncryptedData;
        const response = await this.#x3dhManager.acceptChatRequest(sessionId, respondingAt, myProfile, async (exported) => {
            exportedChattingSession = exported;
            return true;
        });
        if (typeof response === "string") {
            logError(response);
            return false;
        }
        const { profile, text, messageId, timestamp, myAlias, otherAlias } = viewChatRequest;
        const registered = await this.#socketHandler.RegisterPendingSession({ sessionId, myAlias, otherAlias });
        if (registered?.reason !== false) {
            logError(registered);
            return false;
        }
        const [x3dhData, messageHeader] = response;
        const result = await this.#socketHandler.UpdateX3DHData({ x3dhData });
        if (result?.reason !== false) {
            logError(result);
            return false;
        }
        const sent = await this.#socketHandler.SendMessage(messageHeader);
        if (sent?.reason !== false) {
            logError(sent);
            return false;
        }
        const chatId = getRandomString(15, "base64");
        const details = { chatId, contactDetails: profile, timeRatio: _.random(1, 999) };
        const chatDetails = await crypto.deriveEncrypt(details, this.#encryptionBaseVector, "ChatDetails");
        const chatData: ChatData = { chatId, chatDetails, exportedChattingSession };
        const { username: otherUser } = profile;
        await this.#socketHandler.CreateChat({ ...chatData, otherUser });
        await this.instantiateChat(chatData, sessionId, { text, messageId, sentByMe: false, timestamp, respondedAt: respondingAt });
        return true;
    }

    private async rejectReceivedRequest(sessionId: string) {
        const x3dhData = await this.#x3dhManager.rejectReceivedRequest(sessionId);
        const result = await this.#socketHandler.UpdateX3DHData({ x3dhData });
        if (result?.reason !== false) {
            logError(result);
            return false;
        }
        this.removeChat(sessionId, "sessionId");
        return true;
    }

    private async respond<E extends SocketServerSideEventsKey>(event: E, data: string, responseBy: (arg0: SocketServerRequestParameters[E]) => SocketServerRequestReturn[E], resolve: (arg0: string) => void) {
        const encryptResolve = async (response: SocketServerRequestReturn[E] | Failure) => {
            if (!this.#sessionCrypto) resolve(null);
            else resolve(await this.#sessionCrypto?.signEncryptToBase64({ payload: response }, event));
        }
        try {
            const decryptedData = await this.#sessionCrypto?.decryptVerifyFromBase64(data, event);
            if (!decryptedData) await encryptResolve(failure(ErrorStrings.DecryptFailure));
            else {
                const response = await responseBy(decryptedData.payload);
                if (!response) await encryptResolve(failure(ErrorStrings.ProcessFailed));
                else {
                    encryptResolve(response);
                }
            }
        }
        catch (err) {
            logError(err)
            encryptResolve(failure(ErrorStrings.ProcessFailed, err));
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
        return { reason: false };
    }

    private async requestRoom(chat: Chat) {
        const waitReady = this.awaitServerRoomReady(chat.otherUser);
        const response = await this.#socketHandler.RequestRoom({ username: chat.otherUser }, 2000);
        if (response?.reason !== false) {
            return response;
        }
        const confirmed = await waitReady.then(async (ready) => {
            return ready ? await chat.establishRoom(this.#sessionCrypto, this.#socket) : false;
        });
        if (!confirmed) return failure(ErrorStrings.ProcessFailed);
        return { reason: false };
    }

    private async messageReceived({ sessionId }: { sessionId: string }) {
        return await match(this.chatSessionIdsList.get(sessionId)?.type)
            .with("Chat", () => (this.chatSessionIdsList.get(sessionId) as Chat)?.loadUnprocessedMessages())
            .with("SentRequest", () => this.processSentRequest(sessionId))
            .otherwise(async () => false);
    }

    private async receiptReceived({ sessionId }: { sessionId: string }) {
        const chat = this.chatSessionIdsList.get(sessionId);
        if (chat?.type === "Chat") {
            await chat.loadAndProcessReceipts();
        }
    }

    private async chatRequestReceived() {
        await this.fetchNewReceivedRequests();
        return await this.loadReceivedRequests();
    }

    private async issueNewKeys({ n }: { n: number }) {
        if (n === 0) return await this.#x3dhManager.replacePreKey();
        else return await this.#x3dhManager.issueOneTimeKeys(n);
    }

    private async receiveServerMemos({ serverMemos }: { serverMemos: ServerMemo[] }) {
        new Promise(async (resolve) => {
            let x3dhData: X3DHKeysData;
            const processed: string[] = [];
            for (const serverMemo of serverMemos) {
                const result = await this.processServerMemo(serverMemo);
                if ("memoId" in result) {
                    ({ x3dhData } = result);
                    processed.push(result.memoId);
                }
            }
            await this.#socketHandler.ServerMemosProcessed({ processed, x3dhData });
            resolve(null);
        });
        return { reason: false };
    }

    private async processServerMemo(serverMemo: ServerMemo): Promise<{} | { memoId: string, x3dhData: X3DHKeysData }> {
        const { memoId, memoData } = (await this.#x3dhManager.unpackServerMemo<{ memoType: "KeyBundleIssued", keyBundleId: KeyBundleId }>(serverMemo, this.#serverVerifyingKey)) || {};
        if (!memoId) return {};
        const x3dhData = await this.#x3dhManager.registerBundle(memoData.keyBundleId);
        return { memoId, x3dhData };
    }

    private async indicateConnectionAlive(): Promise<Failure> {
        if (this.isConnected && this.chatInterface) return { reason: false, details: { alive: "aliveHere" } };
        else return failure(ErrorStrings.NoConnectivity);
    }
}