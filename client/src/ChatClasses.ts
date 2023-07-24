import _ from "lodash";
import { Socket } from "socket.io-client";
import { SessionCrypto } from "../../shared/sessionCrypto";
import { ChattingSession, SendingMessage, ViewChatRequest } from "./e2e-encryption";
import * as crypto from "../../shared/cryptoOperator";
import { MessageHeader, ChatRequestHeader, StoredMessage, ChatData, DisplayMessage, Contact, ReplyingToInfo, SocketServerSideEvents, DeliveryInfo, Receipt, Backup  } from "../../shared/commonTypes";
import { DateTime } from "luxon";
import { allSettledResults, awaitCallback, logError, randomFunctions, truncateText } from "../../shared/commonFunctions";
import { ClientChatInterface, ClientChatRequestInterface } from "./Client";
import { noProfilePictureImage } from "./noProfilePictureImage";

const { getRandomString } = randomFunctions();

export type ChatDetails = Readonly<{
    otherUser: string, 
    displayName: string, 
    contactName?: string, 
    profilePicture: string, 
    lastActivity: DisplayMessage,
    isOnline: boolean,
    isOtherTyping: boolean,
    unreadMessages: number,
    draft: string
}>;
export abstract class AbstractChat {
    abstract get sessionId(): string;
    abstract get details(): ChatDetails;
    abstract get type(): "Chat" | "ChatRequest" | "AwaitedRequest";
    abstract get lastActive(): number;
    abstract subscribeActivity(notifyActivity: () => void): void;
    abstract unsubscribeActivity(): void;

    matchesName(search: string) {
        const searchLowerCase = search.toLowerCase();
        const { otherUser, displayName, contactName } = this.details;
        return otherUser.includes(searchLowerCase) 
                || displayName.toLowerCase().includes(searchLowerCase)
                || (contactName && contactName.toLowerCase().includes(searchLowerCase));
    }
}

export class AwaitedRequest extends AbstractChat {
    readonly sessionId: string;
    readonly otherUser: string;
    readonly chatMessage: ChatMessage;
    readonly lastActive: number;
    readonly type = "AwaitedRequest";
    readonly details: ChatDetails;

    constructor(otherUser: string, sessionId: string, messageId: string, timestamp: number, text: string) {
        super();
        this.otherUser = otherUser;
        this.sessionId = sessionId;
        this.lastActive = timestamp;
        this.chatMessage = ChatMessage.new({ 
            messageId, 
            text, 
            timestamp,
            sentByMe: true,
            delivery: {
                delivered: false, 
                seen: false 
            } 
        }, true)[0];
        const displayName = otherUser;
        const profilePicture = noProfilePictureImage;
        const lastActivity = this.chatMessage.displayMessage;
        const isOnline = false;
        const isOtherTyping = false;
        const unreadMessages = 0
        this.details = { otherUser, displayName, profilePicture, lastActivity, isOnline, isOtherTyping, unreadMessages, draft: null };
    }

    subscribeActivity() {
    }

    unsubscribeActivity() { 
    }
}

export class ChatRequest extends AbstractChat {
    readonly type = "ChatRequest";
    readonly otherUser: string;
    readonly chatMessage: ChatMessage;
    readonly sessionId: string;
    readonly lastActive: number;
    private readonly contactDetails: Omit<Contact, "username">;
    private readonly chatRequestHeader: ChatRequestHeader;
    private readonly clientInterface: ClientChatRequestInterface;
    private readonly isOnline = false;
    private readonly isOtherTyping = false;
    private unreadMessages = 1;
    private notifyActivity: () => void;

    get details(): ChatDetails {
        const { otherUser, contactDetails: { displayName, profilePicture, contactName }, isOnline, isOtherTyping, unreadMessages } = this;
        const lastActivity = this.chatMessage.displayMessage;
        return { otherUser, displayName, contactName, profilePicture, lastActivity, isOnline, isOtherTyping, unreadMessages, draft: null };
    }

    constructor(chatRequestHeader: ChatRequestHeader, clientInterface: ClientChatRequestInterface, viewRequest: ViewChatRequest) {
        super();
        const { text, messageId, sessionId, timestamp, profile: { username: otherUser, ...contactDetails } } = viewRequest;
        this.sessionId = sessionId;
        this.otherUser = otherUser;
        this.lastActive = timestamp;
        this.contactDetails = contactDetails;
        this.chatMessage = ChatMessage.new({ messageId, text, timestamp, sentByMe: false }, true)[0];
        this.chatRequestHeader = chatRequestHeader;
        this.clientInterface = clientInterface;
    }

    async rejectRequest() {
        return await this.clientInterface.rejectRequest(this.otherUser, this.sessionId, this.chatRequestHeader.yourOneTimeKeyIdentifier);
    }

    async respondToRequest(respondingAt: number) {
        return await this.clientInterface.acceptRequest(this.chatRequestHeader, respondingAt);
    }

    markVisited() {
        this.unreadMessages = 0;
        this.notifyActivity?.();
    }

    subscribeActivity(notifyActivity: () => void) {
        this.notifyActivity = notifyActivity;
    }

    unsubscribeActivity() {
        this.notifyActivity = null;
    }
}

export class Chat extends AbstractChat {
    readonly type = "Chat";
    readonly chatId: string;
    readonly sessionId: string;
    readonly me: string;
    readonly otherUser: string;
    readonly myAlias: string;
    readonly otherAlias: string;
    private disposed = false;
    private isLoading = false;
    private loadedUpto: number;
    private lastActivity: DisplayMessage;
    private otherTyping: boolean;
    private typingTimeout: number;
    private draft: string = null;
    private notify: (event: ChatEvent) => void;
    private notifyActivity: () => void;
    private readonly createdAt: number;
    private readonly loadingBatch = 10;
    private readonly timeRatio: number;
    private readonly unreadMessagesSet = new Set<string>();
    private readonly receivingEvent: string;
    private readonly sendingEvent: string;
    private readonly contactDetails: Omit<Contact, "username">;
    private readonly messagesList = new Map<string, ChatMessage>();
    private readonly chatMessageLists = new Map<string, typeof ChatMessageList.InternalListType>();
    private readonly clientInterface: ClientChatInterface;
    readonly #chattingSession: ChattingSession;
    readonly #encryptionBaseVector: CryptoKey;
    #sessionCrypto: SessionCrypto;
    #socket: Socket;

    private constructor(chatId: string, timeRatio: number, recipientDetails: Contact, encryptionBaseVector: CryptoKey, clientInterface: ClientChatInterface, chattingSession: ChattingSession) {
        super();
        this.chatId = chatId;
        this.#chattingSession = chattingSession;
        this.timeRatio = timeRatio;
        this.loadedUpto = Date.now();
        const { username, ...contactDetails } = recipientDetails;
        const { me, otherUser, myAlias, otherAlias, sessionId, createdAt } = chattingSession;
        this.sessionId = sessionId;
        this.me = me;
        this.otherUser = otherUser;
        this.myAlias = myAlias;
        this.otherAlias = otherAlias;
        this.createdAt = createdAt;
        this.receivingEvent = `${otherUser} -> ${me}`;
        this.sendingEvent = `${me} -> ${otherUser}`;
        this.contactDetails = contactDetails;
        this.clientInterface = clientInterface;
        this.#encryptionBaseVector = encryptionBaseVector;
    }

    static async instantiate(encryptionBaseVector: CryptoKey, clientInterface: ClientChatInterface, chatData: ChatData, firstMessage?: { messageId: string, text: string, timestamp: number, sentByMe: boolean, respondedAt: number }) {
        const { chatDetails, exportedChattingSession } = chatData;
        const { chatId, contactDetails, timeRatio }: { chatId: string, contactDetails: Contact, timeRatio: number } = await crypto.deriveDecrypt(chatDetails, encryptionBaseVector, "ChatDetails");
        const chattingSession = await ChattingSession.importSession(exportedChattingSession, encryptionBaseVector);
        const chat = new Chat(chatId, timeRatio, contactDetails, encryptionBaseVector, clientInterface, chattingSession);
        if (firstMessage) {
            const { messageId, text, timestamp, sentByMe, respondedAt } = firstMessage;
            const delivery = { delivered: respondedAt, seen: respondedAt };
            await chat.encryptStoreMessage({ messageId, text, timestamp, sentByMe, delivery });
        }
        chat.loadNext().then(() => chat.checkNew());
        return chat;
    }

    private get hasRoom() { return !!this.#sessionCrypto; }

    set lastDraft(value: string) {
        this.draft = value;
        this.notifyActivity?.();
    }  

    get lastActive() { return this.lastActivity?.timestamp || Date.now() }

    get details(): ChatDetails {
        const { otherUser, contactDetails: { displayName, profilePicture, contactName }, lastActivity, otherTyping: isOtherTyping, draft } = this;
        const isOnline = this.hasRoom;
        const unreadMessages = this.unreadMessagesSet.size;
        return { otherUser, displayName, contactName, profilePicture, lastActivity, isOnline, isOtherTyping, unreadMessages, draft };
    }

    get messages() { 
        return Array.from(this.chatMessageLists.entries())
                .sort(([d1,], [d2,]) => DateTime.fromISO(d1).toMillis() - DateTime.fromISO(d2).toMillis())
                .map(([, l]) => l.chatMessageList);
    }

    get earliestLoaded() { return this.loadedUpto; }

    get canLoadFurther() { return this.loadedUpto > this.createdAt; }

    hasMessage(messageId: string) {
        return this.messagesList.has(messageId);
    }

    private set isOtherTyping(value: boolean) {
        window.clearTimeout(this.typingTimeout);
        if (this.otherTyping !== value) {
            this.otherTyping = value;
            this.notifyActivity?.();
            this.notify?.("details-change");
        }
        if (value) {
            this.typingTimeout = window.setTimeout(() => {
                this.isOtherTyping = false;
            }, 1500);
        }
    }

    subscribe(notifyAdded: (event: ChatEvent) => void) {
        this.notify = notifyAdded;
    }

    unsubscribe() {
        this.notify = null;
    }

    subscribeActivity(notifyActivity: () => void) {
        this.notifyActivity = notifyActivity;
    }

    unsubscribeActivity() {
        this.notifyActivity = null;
    }

    disconnectRoom() {
        this.#socket?.off(this.receivingEvent);
        this.#socket = null;
        this.#sessionCrypto = null;
        this.notify?.("details-change");
        this.notifyActivity?.();
        this.clientInterface.notifyClient(this);
    }

    async establishRoom(sessionCrypto: SessionCrypto, socket: Socket) {
        if (this.disposed) {
            return false;
        }
        const confirmed = await new Promise((resolve) => {
            socket.once(this.otherUser, (confirmation: string) => resolve(confirmation === "confirmed"));
            socket?.emit(SocketServerSideEvents.ClientRoomReady, this.otherUser);
            window.setTimeout(() => resolve(false), 1000);
        })
        if (!confirmed) {
            socket.off(this.otherUser);
            return false;
        }
        this.#sessionCrypto = sessionCrypto;
        this.#socket = socket;
        this.#socket.on(this.receivingEvent, this.receiveMessage.bind(this));
        this.#socket.on("disconnect", () => {
            this.disconnectRoom();
        })
        this.notifyActivity?.();
        this.notify?.("details-change");
    }

    async sendMessage(messageContent: MessageContent) {
        if (this.disposed) {
            return false;
        }
        const { text, timestamp, replyId } = messageContent;
        const messageId = `f${getRandomString(14, "hex")}`;
        const sendingMessage: SendingMessage = { messageId, text, timestamp, replyingTo: replyId };
        const replyingToInfo = await this.populateReplyingTo(replyId);
        if (replyingToInfo === undefined) {
            logError("Failed to come up with replied-to message.");
            return false;
        }
        const displayMessage: DisplayMessage ={ 
            messageId, 
            text,
            replyingToInfo,
            timestamp,
            sentByMe: true,
            delivery: null
        };
        this.addMessagesToList([displayMessage]);
        const result = await this.dispatchSendingMessage(sendingMessage, true);
        if (!result) return false;
        await this.encryptStoreMessage(displayMessage);
        const chatMessage = this.messagesList.get(messageId);
        if (chatMessage) {
            chatMessage.signalEvent("sent", Date.now());
            this.lastActivity = chatMessage.displayMessage;
            this.notifyActivity?.();
        }
        return true;
    }

    async sendTyping(event: "typing" | "stopped-typing", timestamp: number): Promise<boolean> {
        return await this.sendEvent(event, timestamp);
    }

    private async sendEvent(event: "typing" | "stopped-typing", timestamp: number): Promise<boolean>;
    private async sendEvent(event: "delivered" | "seen", timestamp: number, reportingAbout: string): Promise<boolean>;
    private async sendEvent(event: "typing" | "stopped-typing" | "delivered" | "seen", timestamp: number, reportingAbout?: string): Promise<boolean> {
        if (this.disposed) {
            return false;
        }
        const sendWithoutRoom = event === "delivered" || event === "seen";
        if (sendWithoutRoom) this.encryptStoreMessage(this.messagesList.get(reportingAbout).displayMessage);
        if (!sendWithoutRoom && !this.hasRoom) return false;
        if (event === "seen" && this.unreadMessagesSet.has(reportingAbout)) {
            this.unreadMessagesSet.delete(reportingAbout);
            this.notifyActivity?.();  
        }
        const messageId = `f${getRandomString(14, "hex")}`;
        const sendingMessage: SendingMessage =
            event === "delivered" || event === "seen"
                ? { messageId, timestamp, event, reportingAbout }
                : { messageId, timestamp, event };
        const result = await this.dispatchSendingMessage(sendingMessage, sendWithoutRoom);
        if (!result) return false;
        return true;
    }

    private async dispatchSendingMessage(sendingMessage: SendingMessage, sendWithoutRoom: boolean): Promise<{ acknowledged: boolean }> {
        if (!this.clientInterface.isConnected) return null;
        const messageHeader = await this.#chattingSession.sendMessage(sendingMessage, async (exportedChattingSession) => {
            const result = await this.clientInterface.UpdateChat({ chatId: this.chatId, exportedChattingSession });
            return result?.reason === false;
        });
        if (messageHeader === "Could Not Save") {
            logError(messageHeader);
            return null;
        }
        const { sessionId, headerId } = messageHeader;
        if (this.hasRoom) {
            const response = await this.dispatch(messageHeader);
            if (response) {
                const { signature, bounced } = response;
                if (!(await this.#chattingSession.verifyReceipt(headerId, signature, bounced)) || bounced) {
                    console.log("Resending.");
                    return this.dispatchSendingMessage(sendingMessage, sendWithoutRoom);
                }
                else return { acknowledged: true };
            }
        }
        if (sendWithoutRoom) {
            const content = await crypto.deriveEncrypt(sendingMessage, this.#encryptionBaseVector, this.sessionId);
            const backup: Backup = { byAlias: this.myAlias, sessionId, headerId, content };
            await this.clientInterface.StoreBackup(backup);
            await this.clientInterface.SendMessage(messageHeader);
            return { acknowledged: false };
        }
        else return null;
    }

    async checkNew() {
        await Promise.all([this.loadUnprocessedMessages(), this.loadAndProcessReceipts()]);
    }

    async performLoad(load: () => Promise<void>) {
        if (this.isLoading) return;
        if (this.disposed || !this.clientInterface.isConnected || !this.canLoadFurther) {
            this.isLoading = false;
            return;
        }
        this.isLoading = true;
        this.notify?.("loading-earlier");
        await load();
        this.isLoading = false;
        this.notify?.("loaded-earlier");
    }

    async loadNext() {
        await this.performLoad(async () => {
            const { chatId, loadedUpto, timeRatio, loadingBatch: limit } = this;
            const olderThanTimemark = loadedUpto / timeRatio;
            const messages = await this.clientInterface.GetMessagesByNumber({ chatId, limit, olderThanTimemark });
            if ("reason" in messages) {
                logError(messages);
                return;
            }
            await this.decryptPushMessages(messages);
        });
    }

    async loadUptoId(messageId: string) {
        if (this.messagesList.has(messageId)) return;
        await this.performLoad(async () => {
            const { chatId, myAlias, loadedUpto, timeRatio } = this;
            const olderThanTimemark = loadedUpto / timeRatio;
            const hashedId = await this.calculateHashedId(messageId);
            const messages = await this.clientInterface.GetMessagesUptoId({ chatId, hashedId, olderThanTimemark });
            if ("reason" in messages) {
                logError(messages);
                return;
            }
            await this.decryptPushMessages(messages);

        });
    }

    async loadUptoTime(newerThan: number) {
        await this.performLoad(async () => {
            const { chatId, loadedUpto, timeRatio } = this;
            const olderThanTimemark = loadedUpto / timeRatio;
            const newerThanTimemark = newerThan / timeRatio;
            const messages = await this.clientInterface.GetMessagesUptoTimestamp({ chatId, newerThanTimemark, olderThanTimemark });
            if ("reason" in messages) {
                logError(messages);
                return;
            }
            await this.decryptPushMessages(messages);
        });
    }

    async loadUnprocessedMessages() {
        const { sessionId, myAlias, otherAlias } = this;
        let unprocessedMessages = await this.clientInterface.GetMessageHeaders({ sessionId, toAlias: myAlias, fromAlias: otherAlias });
        if ("reason" in unprocessedMessages) {
            logError(unprocessedMessages);
            return;
        }
        unprocessedMessages = _.sortBy(unprocessedMessages, ["sendingRatchetNumber", "sendingChainNumber"]);
        for (const message of unprocessedMessages) {
            await this.processMessageHeader(message, false);
        }
    }

    private addMessagesToList(displayMessages: DisplayMessage[]) {
        for (const [date, messages] of _.chain(displayMessages)
                                        .groupBy(({ timestamp }) => DateTime.fromMillis(timestamp).toISODate())
                                        .map((messages, date) => ([date, messages] as const)).value()) {
            let chatMessageList = this.chatMessageLists.get(date);
            messages.forEach(({ messageId, sentByMe, delivery }) => {
                if (!sentByMe && !delivery?.seen) this.unreadMessagesSet.add(messageId);
            });
            if (chatMessageList) {
                chatMessageList.add(messages);
            }
            else {
                chatMessageList = ChatMessageList.construct(messages, (event, timestamp, reportingAbout) => this.sendEvent(event, timestamp, reportingAbout));
                this.chatMessageLists.set(date, chatMessageList);
                this.notify?.("added");
            }
            messages.forEach((message) => {
                const { messageId, sentByMe, timestamp, delivery } = message;
                const chatMessage = chatMessageList.messageById(messageId);
                this.messagesList.set(messageId, chatMessage);
                if (!sentByMe && !delivery?.delivered) chatMessage.signalEvent("delivered", Date.now());
                if (timestamp >= (this.lastActivity?.timestamp || 0)) {
                    this.lastActivity = message;
                    this.notify?.("received-new");
                    this.clientInterface.notifyClient(this);
                }
                else if (timestamp < this.loadedUpto) {
                    this.loadedUpto = timestamp;
                }
                this.notifyActivity?.();
            });

        }
    }

    private async dispatch(messageHeader: MessageHeader) {
        return await awaitCallback<{ signature: string, bounced: boolean }>(async (resolve) => {
            if (!this.#socket) resolve(null);
            else this.#socket.emit(this.sendingEvent, await this.#sessionCrypto.signEncryptToBase64(messageHeader, this.sendingEvent), (response: { signature: string, bounced: boolean }) => resolve(response));
        }, 1000);
    }

    private async receiveMessage(data: string, ack: (response: { signature: string, bounced: boolean }) => void) {
        if (!data) {
            ack(null);
            return;
        }
        if (data === "room-disconnected") {
            this.disconnectRoom();
            return;
        }
        try {
            const decryptedData: MessageHeader = await this.#sessionCrypto.decryptVerifyFromBase64(data, this.receivingEvent);
            if (!decryptedData) {
                ack(null);
            }
            else {
                ack(await this.processMessageHeader(decryptedData, true));
            }
        }
        catch (e: any) {
            logError(e);
            ack(null);
        }
    }

    private async decryptPushMessages(messages: StoredMessage[]) {
        this.addMessagesToList(await allSettledResults(messages.map(async (message) => (await crypto.deriveDecrypt(message.content, this.#encryptionBaseVector, this.sessionId)) as DisplayMessage)))
    }

    private async encryptStoreMessage(message: DisplayMessage) {
        const { messageId, timestamp } = message;
        const content = await crypto.deriveEncrypt(message, this.#encryptionBaseVector, this.sessionId);
        const { chatId, sessionId } = this;
        const hashedId = await this.calculateHashedId(messageId);
        const timemark = timestamp / this.timeRatio;
        const encryptedMessage: StoredMessage = { chatId, hashedId, timemark, content };
        await this.clientInterface.StoreMessage(encryptedMessage);
    }

    private async processMessageHeader(encryptedMessage: MessageHeader, live: boolean): Promise<{ signature: string, bounced: boolean }> {
        const { sessionId, headerId } = encryptedMessage;
        const toAlias = this.otherAlias;
        const [messageBody, signature] = await this.#chattingSession.receiveMessage(encryptedMessage, async (exportedChattingSession) => {
            const result = await this.clientInterface.UpdateChat({ chatId: this.chatId, exportedChattingSession });
            return result?.reason === false; 
        });
        const sendReceipt = async ({ bounced }: { bounced: boolean }) => {
            live || await this.clientInterface.MessageHeaderProcessed({ sessionId, headerId, toAlias: this.myAlias });
            live || await this.clientInterface.SendReceipt({ toAlias, sessionId, headerId, signature, bounced });
            return { signature, bounced }
        }
        if (typeof messageBody === "string") {
            logError(messageBody);
            return sendReceipt({ bounced: true });
        };
        const { sender, timestamp, messageId } = messageBody;
        if (sender !== this.otherUser) {
            return sendReceipt({ bounced: true });
        }
        let displayMessage: DisplayMessage;
        if ("event" in messageBody) {
            if (messageBody.event !== "delivered" && messageBody.event !== "seen") {
                if ((Date.now() - timestamp) < 1500) {
                    this.isOtherTyping = messageBody.event === "typing";
                }
                return sendReceipt({ bounced: false });
            }
            const { event, reportingAbout } = messageBody;
            const chatMessage = this.messagesList.get(reportingAbout);
            if (chatMessage) {
                chatMessage.signalEvent(event, timestamp);
                displayMessage = chatMessage.displayMessage;
                if (reportingAbout === this.lastActivity.messageId) {
                    this.lastActivity = displayMessage;
                    this.notifyActivity?.();
                }
            }
            else {
                const storedMessage = await this.getMessageById(reportingAbout);
                if (storedMessage) {
                    const delivery = calculateDelivery(storedMessage.delivery, event, timestamp, storedMessage.timestamp);
                    displayMessage = { ...storedMessage, delivery };
                }
            }
        }
        else {
            const { text, replyingTo } = messageBody;
            const replyingToInfo = await this.populateReplyingTo(replyingTo);
            if (replyingToInfo === undefined) {
                logError("Failed to come up with replied-to message.");
                return sendReceipt({ bounced: true });
            }
            displayMessage = { messageId, timestamp, text, replyingToInfo, sentByMe: false };
            this.addMessagesToList([displayMessage]);
        }
        if (displayMessage) await this.encryptStoreMessage(displayMessage);
        return sendReceipt({ bounced: false });
    }

    private async populateReplyingTo(replyId: string): Promise<ReplyingToInfo> {
        if (!replyId) return null;
        const repliedTo = await this.getMessageById(replyId);
        if (!repliedTo) return undefined;
        const replyToOwn = repliedTo.sentByMe;
        const displayText = truncateText(repliedTo.text);
        return { replyId, replyToOwn, displayText };
    }

    private async getMessageById(messageId: string): Promise<DisplayMessage> {
        if (!messageId) return null;
        if (this.messagesList.has(messageId)) return this.messagesList.get(messageId).displayMessage;
        const hashedId = await this.calculateHashedId(messageId);
        const fetched = await this.clientInterface.GetMessageById({ chatId: this.chatId, hashedId });
        if ("reason" in fetched) {
            logError(fetched);
            return undefined;
        };
        return await crypto.deriveDecrypt(fetched.content, this.#encryptionBaseVector, this.sessionId);
    }

    private async calculateHashedId(messageId: string) {
        return (await crypto.digestToBase64("SHA-256", Buffer.from(`${this.myAlias}${messageId}`, "hex"))).slice(0, 15);
    }

    private async processReceipt(receipt: Receipt) {
        const { headerId, sessionId, signature, bounced, toAlias } = receipt;
        if (!(await this.#chattingSession.verifyReceipt(headerId, signature, bounced))) return;
        if (!bounced) {
            await this.clientInterface.BackupProcessed({ byAlias: toAlias, sessionId, headerId });
        }
        else {
            let sendingMessage: SendingMessage
            const backup = await this.clientInterface.GetBackupById({ byAlias: toAlias, sessionId, headerId });
            if ("reason" in backup) {
                logError(backup);
                return;
            }
            else {
                sendingMessage: sendingMessage = await crypto.deriveDecrypt(backup.content, this.#encryptionBaseVector, this.sessionId);
                await this.clientInterface.BackupProcessed({ byAlias: toAlias, sessionId, headerId });
            }
            await this.dispatchSendingMessage(sendingMessage, true);
        }

    }

    async loadAndProcessReceipts() {
        const { sessionId, myAlias } = this;
        let receipts = await this.clientInterface.GetAllReceipts({ sessionId, toAlias: myAlias });
        if ("reason" in receipts) {
            logError(receipts);
            return;
        }
        await Promise.all(receipts.map((receipt) => this.processReceipt(receipt)));
        await this.clientInterface.ClearAllReceipts({ sessionId, toAlias: myAlias });
    }
}

export class ChatMessageList {
    private internalList: typeof ChatMessageList.InternalListType;

    private constructor() {
    }

    static construct(messages: DisplayMessage[], sendEvent: (event: "delivered" | "seen", timestamp: number, reportingAbout: string) => void) {
        const list = new ChatMessageList();
        list.internalList = new ChatMessageList.InternalList(messages, sendEvent, list);
        return list.internalList;
    }

    public get date() {
        return this.internalList.date;
    }

    public get messageList() {
        return this.internalList.messageList;
    }

    subscribe(notifyAdded: () => void) {
        this.internalList.subscribe(notifyAdded);
    }

    unsubscribe() {
        this.internalList.unsubscribe();
    }

    static readonly InternalListType: typeof this.InternalList.prototype = null;

    private static InternalList = class {
        readonly date: string;
        private indexedMessages = new Map<string, readonly [ChatMessage, (isFirst: boolean) => void]>();
        private chatMessages: ChatMessage[] = [];
        private notifyAdded: () => void;
        private sendEvent: (event: "delivered" | "seen", timestamp: number, reportingAbout: string) => void;
        private earliest: number;
        private latest: number;
        private exposedList: ChatMessageList;

        constructor(messages: DisplayMessage[], sendEvent: (event: "delivered" | "seen", timestamp: number, reportingAbout: string) => void, exposedList: ChatMessageList) {
            this.date = DateTime.fromMillis(messages[0].timestamp).toISODate();
            if (messages.some(({ timestamp }) => DateTime.fromMillis(timestamp).toISODate() !== this.date)) throw "All messages must be same date";
            this.sendEvent = sendEvent;
            this.exposedList = exposedList;
            this.add(messages);
        }

        public get messageList() {
            return [...this.chatMessages];
        }
    
        public get chatMessageList() {
            return this.exposedList;
        }
    
        messageById(messageId: string) {
            return this.indexedMessages.get(messageId)[0];
        }
    
        subscribe(notifyAdded: () => void) {
            this.notifyAdded = notifyAdded;
        }
    
        unsubscribe() {
            this.notifyAdded = null;
        }
    
        add(messages: DisplayMessage[]) {
            this.breakIntoChunks(messages).forEach(([index, messagesChunk]) => this.insertChunk(index, messagesChunk));
        }

        private breakIntoChunks(messages: DisplayMessage[]): [number, DisplayMessage[]][] {
            if (messages.some(({ timestamp }) => DateTime.fromMillis(timestamp).toISODate() !== this.date)) throw "All messages must be same date";
            messages = messages.filter(({ messageId }) => !this.indexedMessages.has(messageId)).sort((m1, m2) => m1.timestamp - m2.timestamp);
            if (messages.length === 0) return [];
            if (!this.earliest || messages.at(-1).timestamp < this.earliest) return [[0, messages]];
            if (messages.at(-1).timestamp > this.latest) return [[this.chatMessages.length, messages]];
            const oldMessages = this.chatMessages.map(({ timestamp }, index) => ({ index, timestamp, newlyAdded: false }));
            const newMessages = messages.map(({ timestamp }, index) => ({ index, timestamp, newlyAdded: true }));
            const ordered = [...newMessages, ...oldMessages].sort((m1, m2) => m1.timestamp - m2.timestamp);
            const chunks:  [number, DisplayMessage[]][] = [];
            let cursor = 0;
            while (cursor < ordered.length) {
                cursor = ordered.findIndex(({ newlyAdded }, i) => i >= cursor && newlyAdded);
                if (cursor < 0) break;
                const insertIndex = 
                    cursor > 0
                        ? ordered[cursor - 1].index + 1
                        : 0;
                const startIndex = ordered[cursor].index;
                cursor = ordered.findIndex(({ newlyAdded }, i) => i > cursor && !newlyAdded);
                const stopIndex = 
                    cursor > 0
                        ? ordered[cursor - 1].index
                        : ordered.at(-1).index;
                chunks.push([insertIndex, messages.slice(startIndex, stopIndex + 1)]);
                if (cursor < 0) cursor = ordered.length;
            }
            return chunks;
        }

        private insertChunk(index: number, messages: DisplayMessage[]) {
            const startSentByMe = index > 0 ? this.chatMessages[index - 1].sentByMe : null;
            const [lastSentByMe, newChatMessages] = this.constructChatMessages(startSentByMe, messages);
            if (index === 0) {
                this.earliest = newChatMessages[0][0].timestamp;
            }
            if (index >= this.chatMessages.length) {
                this.latest = newChatMessages.at(-1)[0].timestamp;
            }
            if (lastSentByMe !== null && index > 0 && index < this.chatMessages.length) {
                const { messageId, sentByMe } = this.chatMessageList[index].messageId;
                this.indexedMessages.get(messageId)[1](sentByMe !== lastSentByMe);
            }
            const chatMessages = newChatMessages.map(([message, updateFirst]) => {
                this.indexedMessages.set(message.messageId, [message, updateFirst]);
                return message;
            });
            this.chatMessages.splice(index, 0, ...chatMessages);
            this.notifyAdded?.();
        }

        private constructChatMessages(startSentByMe: boolean, messages: DisplayMessage[]) {
            const chatMessages: (readonly [ChatMessage, (isFirst: boolean) => void])[] = [];
            let index = 0;
            let lastSentByMe = startSentByMe;
            while (index < messages.length) {
                const message = messages[index];
                const { sentByMe, messageId } = message;
                const sendEvent = 
                    sentByMe 
                        ? null
                        : (event: "delivered" | "seen", timestamp: number) => this.sendEvent(event, timestamp, messageId);
                const isFirst = 
                    lastSentByMe === null 
                        ? true 
                        : lastSentByMe !== sentByMe;
                chatMessages.push(ChatMessage.new(message, isFirst, sendEvent));
                index += 1;
                lastSentByMe = sentByMe;
            }
            return [lastSentByMe, chatMessages] as const;
        }
    }
}

export class ChatMessage {
    private message: DisplayMessage;
    private isFirst: boolean;
    private notifyChange: (event: "first" | "sent" | "delivered" | "seen") => void;
    readonly signalEvent: (event: "sent" | "delivered" | "seen", timestamp: number) => void;

    public get displayMessage() {
        return { ...this.message };
    }

    public get messageId() {
        return this.displayMessage.messageId;
    }
        
    public get replyingToInfo() {
        return { ...this.displayMessage.replyingToInfo };
    }

    public get timestamp() {
        return this.displayMessage.timestamp;
    }

    public get text() {
        return this.displayMessage.text;
    }

    public get sentByMe() {
        return this.displayMessage.sentByMe;
    }

    public get delivery() {
        return { ...this.displayMessage.delivery };
    }

    public get isFirstOfType() {
        return this.isFirst === null || this.isFirst;
    }

    private updateFirst(isFirst: boolean) {
        if (this.isFirst !== isFirst) {
            this.isFirst = isFirst;
            this.notifyChange?.("first");
        }

    }

    subscribe(notifyChange: (event: "first" | "sent" | "delivered" | "seen") => void) {
        this.notifyChange = notifyChange;
    }

    unsubscribe() {
        this.notifyChange = null;
    }

    private constructor(displayMessage: DisplayMessage, 
        isFirst: boolean,
        signalEvent?: (event: "delivered" | "seen", timestamp: number) => void) {
            this.message = displayMessage;
            this.isFirst = isFirst;
            let signaling = false;
            this.signalEvent = (event, timestamp) => {
                if (signaling) return;
                signaling = true;
                const prevDelivery = this.message.delivery;
                let delivery: DeliveryInfo;
                if (event === "sent") {
                    delivery = prevDelivery || {
                        delivered: false,
                        seen: false
                    };
                }
                else {
                    delivery = calculateDelivery(prevDelivery, event, timestamp, this.message.timestamp);
                }
                if (!_.isEqual(delivery, prevDelivery)) {
                    this.message = { ...this.message, delivery };
                    this.notifyChange?.(event);
                    if (event !== "sent") signalEvent?.(event, timestamp);
                }
                signaling = false;
            }
    }

    static new(displayMessage: DisplayMessage, isFirst: boolean, signalEvent?: (event: "delivered" | "seen", timestamp: number) => void) {
        const chatMessage = new ChatMessage(displayMessage, isFirst, signalEvent);
        return [chatMessage, (isFirst: boolean) => chatMessage.updateFirst(isFirst)] as const;
    }
}

type MessageContent = Readonly<{
    text: string;
    timestamp: number;
    replyId?: string;
}>;

type ChatEvent = "details-change" | "added" | "loading-earlier" | "loaded-earlier" | "received-new";

function calculateDelivery(prevDelivery: DeliveryInfo, event: "delivered" | "seen", timestamp: number, messageTimestamp: number): DeliveryInfo {
    const { delivered, seen } = prevDelivery || {};
    let newDelivery: DeliveryInfo;
    if (event === "delivered") {
        newDelivery = {
            delivered: (delivered && (timestamp >= delivered || timestamp <= messageTimestamp)) ? delivered : timestamp,
            seen: seen || false
        };
    }
    else {
        newDelivery = {
            delivered: delivered || timestamp,
            seen: seen || timestamp
        };
    }
    return newDelivery;
}