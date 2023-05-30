import _ from "lodash";
import { Socket } from "socket.io-client";
import { SessionCrypto } from "../../shared/sessionCrypto";
import { ChattingSession, SendingMessage, ViewChatRequest } from "./e2e-encryption";
import * as crypto from "../../shared/cryptoOperator";
import { MessageHeader, ChatRequestHeader, StoredMessage, ChatData, DisplayMessage, Contact, ReplyingToInfo, SocketServerSideEvents, DeliveryInfo, Receipt  } from "../../shared/commonTypes";
import { DateTime } from "luxon";
import { allSettledResults, awaitCallback, logError, randomFunctions, truncateText } from "../../shared/commonFunctions";
import { ClientChatInterface, ClientChatRequestInterface } from "./client";
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
}>;
export abstract class AbstractChat {
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
        this.chatMessage = new ChatMessage({ 
            messageId, 
            text, 
            timestamp,
            sentByMe: true,
            delivery: {
                delivered: false, 
                seen: false 
            } 
        }, null);
        const displayName = otherUser;
        const profilePicture = noProfilePictureImage;
        const lastActivity = this.chatMessage.displayMessage;
        const isOnline = false;
        const isOtherTyping = false;
        const unreadMessages = 0
        this.details = { otherUser, displayName, profilePicture, lastActivity, isOnline, isOtherTyping, unreadMessages };
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
        return { otherUser, displayName, contactName, profilePicture, lastActivity, isOnline, isOtherTyping, unreadMessages };
    }

    constructor(chatRequestHeader: ChatRequestHeader, clientInterface: ClientChatRequestInterface, viewRequest: ViewChatRequest) {
        super();
        const { text, messageId, timestamp, profile: { username: otherUser, ...contactDetails } } = viewRequest;
        this.sessionId = chatRequestHeader.sessionId;
        this.otherUser = otherUser;
        this.lastActive = timestamp;
        this.contactDetails = contactDetails;
        this.chatMessage = new ChatMessage({ messageId, text, timestamp, sentByMe: false }, null);
        this.chatRequestHeader = chatRequestHeader;
        this.clientInterface = clientInterface;
    }

    async rejectRequest() {
        return await this.clientInterface.rejectRequest(this.otherUser, this.sessionId, this.chatRequestHeader.yourOneTimeKeyIdentifier);
    }

    async respondToRequest(respondingAt: number) {
        return await this.clientInterface.respondToRequest(this.chatRequestHeader, respondingAt);
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
    private disposed = false;
    private readonly loadingBatch = 10;
    private isLoading = false;
    private loadedUpto = Date.now();
    private createdAt: number;
    private latestMessageAt: number;
    private lastActivity: DisplayMessage;
    private readonly unreadMessagesList: string[] = [];
    private otherTyping: boolean;
    private typingTimeout: number;
    private notify: (event: ChatEvent) => void;
    private notifyActivity: () => void;
    private readonly messagesList = new Map<string, ChatMessage>();
    private readonly chatMessageLists = new Map<string, ChatMessageListInternal>();
    private readonly clientInterface: ClientChatInterface;
    readonly type = "Chat";
    readonly sessionId: string;
    readonly me: string;
    readonly otherUser: string;
    private readonly receivingEvent: string;
    private readonly sendingEvent: string;
    private readonly contactDetails: Omit<Contact, "username">;
    readonly #chattingSession: ChattingSession;
    readonly #encryptionBaseVector: CryptoKey;
    #sessionCrypto: SessionCrypto;
    #socket: Socket;

    private get hasRoom() { return !!this.#sessionCrypto; }

    get lastActive() { return this.latestMessageAt; }

    get details(): ChatDetails {
        const { otherUser, contactDetails: { displayName, profilePicture, contactName }, lastActivity, otherTyping: isOtherTyping } = this;
        const isOnline = this.hasRoom;
        const unreadMessages = this.unreadMessagesList.length;
        return { otherUser, displayName, contactName, profilePicture, lastActivity, isOnline, isOtherTyping, unreadMessages };
    }

    get messages() { 
        return Array.from(this.chatMessageLists.entries())
                .sort(([d1,], [d2,]) => DateTime.fromISO(d1).toMillis() - DateTime.fromISO(d2).toMillis())
                .map(([d, l]) => l.exposeList);
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
        this.clientInterface.notifyClient();
    }

    private constructor(sessionId: string, me: string, recipientDetails: Contact, encryptionBaseVector: CryptoKey, clientInterface: ClientChatInterface, chattingSession: ChattingSession) {
        super();
        this.sessionId = sessionId;
        this.me = me;
        const { username: recipient, ...contactDetails } = recipientDetails;
        this.otherUser = recipient;
        this.receivingEvent = `${recipient} -> ${me}`;
        this.sendingEvent = `${me} -> ${recipient}`;
        this.contactDetails = contactDetails;
        this.clientInterface = clientInterface;
        this.#encryptionBaseVector = encryptionBaseVector;
        this.#chattingSession = chattingSession;
    }

    static async instantiate(me: string, encryptionBaseVector: CryptoKey, clientInterface: ClientChatInterface, chatData: ChatData, firstMessage?: { messageId: string, text: string, timestamp: number, sentByMe: boolean, deliveredAt?: number }) {
        const { chatDetails, exportedChattingSession, lastActive, createdAt, sessionId } = chatData;
        const contactDetails: Contact = await crypto.deriveDecrypt(chatDetails, encryptionBaseVector, "ContactDetails");
        const chattingSession = await ChattingSession.importSession(exportedChattingSession, encryptionBaseVector);
        const chat = new Chat(sessionId, me, contactDetails, encryptionBaseVector, clientInterface, chattingSession);
        chat.latestMessageAt = lastActive;
        chat.createdAt = createdAt;
        if (firstMessage) {
            const { messageId, text, timestamp, sentByMe, deliveredAt: deliveredAt } = firstMessage;
            const delivery = { delivered: deliveredAt, seen: deliveredAt };
            await chat.encryptStoreMessage({ messageId, text, timestamp, sentByMe, delivery }, false);
        }
        await chat.loadUnprocessedMessages();
        await chat.loadNext();
        chat.loadAndProcessReceipts();
        return chat;
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
        const messageId = getRandomString(15, "hex");
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
        this.addMessageToList(displayMessage);
        const result = await this.dispatchSendingMessage(sendingMessage, true);
        if (!result) return false;
        const chatMessage = this.messagesList.get(messageId);
        if (chatMessage) {
            chatMessage.signalEvent("sent", Date.now());
            this.lastActivity = chatMessage.displayMessage;
            this.notifyActivity?.();
        }
        this.encryptStoreMessage(displayMessage, false);
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
        if (sendWithoutRoom) this.encryptStoreMessage(this.messagesList.get(reportingAbout).displayMessage, false);
        if (!sendWithoutRoom && !this.hasRoom) return false;
        if (event === "seen" && this.unreadMessagesList.includes(reportingAbout)) {
            _.pull(this.unreadMessagesList, reportingAbout);
            this.notifyActivity?.();  
        }
        const sendingMessage: SendingMessage =
            event === "delivered" || event === "seen"
                ? { timestamp, event, reportingAbout }
                : { timestamp, event };
        const result = await this.dispatchSendingMessage(sendingMessage, sendWithoutRoom);
        if (!result) return false;
        const { messageId, acknowledged } = result;
        if (sendWithoutRoom && !acknowledged) {
            const content = await crypto.deriveEncrypt(sendingMessage, this.#encryptionBaseVector, this.sessionId);
            const encryptedMessage = { messageId, timestamp, content };
            await this.clientInterface.StoreBackup(encryptedMessage);
        }
        return true;
    }

    private async dispatchSendingMessage(sendingMessage: SendingMessage, sendWithoutRoom: boolean): Promise<{ messageId: string, acknowledged: boolean }> {
        if (!this.clientInterface.isConnected) return null;
        const messageHeader = await this.#chattingSession.sendMessage(sendingMessage, async (exportedChattingSession) => {
            const result = await this.clientInterface.UpdateChat({ lastActive: this.latestMessageAt, exportedChattingSession });
            return !result.reason;
        });
        if (messageHeader === "Could Not Save") {
            logError(messageHeader);
            return null;
        }
        const { messageId } = messageHeader;
        if (this.hasRoom) {
            const response = await this.dispatch(messageHeader);
            if (response) {
                const { signature, bounced } = response;
                if (!(await this.#chattingSession.verifyReceipt(messageId, signature)) || bounced) {
                    console.log("Resending.");
                    return this.dispatchSendingMessage(sendingMessage, sendWithoutRoom);
                }
                else return { messageId, acknowledged: true };
            }
        }
        if (sendWithoutRoom) {
            await this.clientInterface.SendMessage(messageHeader);
            return { messageId, acknowledged: false };
        }
        else return null;
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
            const messages = await this.clientInterface.GetMessagesByNumber({ limit: this.loadingBatch, olderThan: this.loadedUpto });
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
            const messages = await this.clientInterface.GetMessagesUptoId({ messageId, olderThan: this.loadedUpto });
            if ("reason" in messages) {
                logError(messages);
                return;
            }
            await this.decryptPushMessages(messages);

        });
    }

    async loadUptoTime(newerThan: number) {
        await this.performLoad(async () => {
            const messages = await this.clientInterface.GetMessagesUptoTimestamp({ newerThan, olderThan: this.loadedUpto });
            if ("reason" in messages) {
                logError(messages);
                return;
            }
            await this.decryptPushMessages(messages);
        });
    }

    async messageReceived(message: MessageHeader) {
        if (this.disposed) {
            return false;
        }
        return await this.processMessageHeader(message, false);
    }

    private addMessageToList(message: DisplayMessage) {
        const { messageId, timestamp } = message;
        const date = DateTime.fromMillis(timestamp).toISODate();
        let chatMessageList = this.chatMessageLists.get(date);
        const notifyUnread = !message.sentByMe && !message.delivery?.seen; 
        if (notifyUnread) this.unreadMessagesList.push(messageId);
        if (chatMessageList) {
            chatMessageList.add(message);
        }
        else {
            chatMessageList = 
            ChatMessageListInternal.construct(message, (event, timestamp, reportingAbout) => this.sendEvent(event, timestamp, reportingAbout));
            this.chatMessageLists.set(date, chatMessageList);
            this.notify?.("added");
        }
        const chatMessage = chatMessageList.messageById(messageId);
        this.messagesList.set(messageId, chatMessage);
        if (!message.sentByMe) chatMessage.signalEvent("delivered", Date.now());
        if (timestamp >= (this.lastActivity?.timestamp || 0)) {
            this.lastActivity = message;
            this.latestMessageAt = timestamp;
            this.notify?.("received-new");
            this.notifyActivity?.();
            this.clientInterface.notifyClient();
        }
        else if (timestamp < this.loadedUpto) {
            this.loadedUpto = timestamp;
            if (notifyUnread) this.notifyActivity?.();
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
        const decrypted = await allSettledResults(messages.map(async (message) => (await crypto.deriveDecrypt(message.content, this.#encryptionBaseVector, this.sessionId)) as DisplayMessage));
        for (const message of _.orderBy(decrypted, (m) => m.timestamp, "desc")) {
            this.addMessageToList(message);
        }
    }

    private async encryptStoreMessage(message: DisplayMessage, wasUnprocessed: boolean) {
        const { messageId, timestamp, sentByMe } = message;
        const content = await crypto.deriveEncrypt(message, this.#encryptionBaseVector, this.sessionId);
        const encryptedMessage = { messageId, timestamp, content };
        await this.clientInterface.StoreMessage(encryptedMessage);
        if (wasUnprocessed || sentByMe) {
            await this.clientInterface.MessageProcessed({ messageId });
        }
    }

    private async processMessageHeader(encryptedMessage: MessageHeader, live: boolean): Promise<{ signature: string, bounced: boolean }> {
        const { messageId } = encryptedMessage;
        const addressedTo = this.otherUser;
        const [messageBody, signature] = await this.#chattingSession.receiveMessage(encryptedMessage, async (exportedChattingSession) => {
            const result = await this.clientInterface.UpdateChat({ lastActive: this.latestMessageAt, exportedChattingSession });
            return !result.reason; 
        });
        const sendReceipt = async ({ bounced }: { bounced: boolean }) => {
            live || await this.clientInterface.MessageProcessed({ messageId });
            live || await this.clientInterface.SendReceipt({ addressedTo, messageId, signature, bounced });
            return { signature, bounced }
        }
        if (typeof messageBody === "string") {
            logError(messageBody);
            return sendReceipt({ bounced: true });
        };
        const { sender, timestamp } = messageBody;
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
                    const delivery = calculateDelivery(storedMessage.delivery, event, timestamp);
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
            this.addMessageToList(displayMessage);
        }
        await this.encryptStoreMessage(displayMessage, true);
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
        const fetched = await this.clientInterface.GetMessageById({ messageId });
        if ("reason" in fetched) {
            logError(fetched);
            return undefined;
        };
        return await crypto.deriveDecrypt(fetched.content, this.#encryptionBaseVector, this.sessionId);
    }

    private async loadUnprocessedMessages() {
        let unprocessedMessages = await this.clientInterface.GetUnprocessedMessages();
        if ("reason" in unprocessedMessages) {
            logError(unprocessedMessages);
            return;
        }
        unprocessedMessages = _.sortBy(unprocessedMessages, ["sendingRatchetNumber", "sendingChainNumber"]);
        for (const message of unprocessedMessages) {
            await this.processMessageHeader(message, false);
        }
    }

    private async loadAndProcessReceipts() {
        let receipts = await this.clientInterface.GetAllReceipts();
        if ("reason" in receipts) {
            logError(receipts);
            return;
        }
        await Promise.all(receipts.map((receipt) => this.processReceipt(receipt)));
        await this.clientInterface.ClearAllReceipts();
    }

    async processReceipt(receipt: Receipt) {
        const { messageId, signature, bounced } = receipt;
        if (!(await this.#chattingSession.verifyReceipt(messageId, signature))) return;
        if (!bounced) {
            await this.clientInterface.BackupProcessed({ messageId });
        }
        else {
            let sendingMessage: SendingMessage
            const backup = await this.clientInterface.GetBackupById({ messageId });
            if ("reason" in backup) {
                logError(backup);
                const message = await this.clientInterface.GetMessageById({ messageId });
                if ("reason" in message) {
                    logError(backup);
                    return;
                }
                const { text, replyingToInfo: { replyId: replyingTo }, timestamp }: DisplayMessage = await crypto.deriveDecrypt(message.content, this.#encryptionBaseVector, this.sessionId);
                sendingMessage = { text, replyingTo, timestamp };
            }
            else {
                sendingMessage = await crypto.deriveDecrypt(backup.content, this.#encryptionBaseVector, this.sessionId);
                await this.clientInterface.BackupProcessed({ messageId });
            }
            await this.dispatchSendingMessage(sendingMessage, true);
        }

    }
}

export class ChatMessageList {
    private internalList: ChatMessageListInternal;

    constructor(internalList: ChatMessageListInternal) {
        this.internalList = internalList;
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
}

export class ChatMessage {
    private message: DisplayMessage;
    private isFirst: null | boolean;
    private notifyChange: (event: "first" | "sent" | "delivered" | "seen") => void;
    readonly signalEvent: (event: "sent" | "delivered" | "seen", timestamp: number) => void;

    public get messageId() {
        return this.displayMessage.messageId;
    }

    public get displayMessage() {
        return this.message;
    }

    public get isFirstOfType() {
        return this.isFirst === null || this.isFirst;
    }

    public updateFirst(isFirst: boolean) {
        if (this.isFirst === null || isFirst !== null || this.isFirst !== isFirst) {
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

    constructor(displayMessage: DisplayMessage, 
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
                    delivery = calculateDelivery(prevDelivery, event, timestamp);
                }
                if (!_.isEqual(delivery, prevDelivery)) {
                    this.message = { ...this.message, delivery };
                    this.notifyChange?.(event);
                    if (event !== "sent") signalEvent?.(event, timestamp);
                }
                signaling = false;
            }
    }
}

class ChatMessageListInternal {
    readonly date: string;
    private indexedMessages = new Map<string, ChatMessage>();
    private messages: ChatMessage[] = [];
    private notifyAdded: () => void;
    private sendEvent: (event: "delivered" | "seen", timestamp: number, reportingAbout: string) => void;
    private earliest: number;
    private latest: number;
    private exposedList: ChatMessageList;

    static construct(message: DisplayMessage, sendEvent: (event: "delivered" | "seen", timestamp: number, reportingAbout: string) => void) {
        const internalList = new ChatMessageListInternal(message, sendEvent);
        internalList.exposedList = new ChatMessageList(internalList);
        return internalList;
    }

    private constructor(message: DisplayMessage, sendEvent: (event: "delivered" | "seen", timestamp: number, reportingAbout: string) => void) {
        const { timestamp } = message;
        this.date = DateTime.fromMillis(timestamp).toISODate();
        this.sendEvent = sendEvent;
        this.latest = timestamp;
        this.earliest = this.latest + 1;
        this.add(message);
    }

    public get messageList() {
        return [...this.messages];
    }

    public get exposeList() {
        return this.exposedList;
    }

    messageById(messageId: string) {
        return this.indexedMessages.get(messageId);
    }

    subscribe(notifyAdded: () => void) {
        this.notifyAdded = notifyAdded;
    }

    unsubscribe() {
        this.notifyAdded = null;
    }

    add(displayMessage: DisplayMessage) {
        const { messageId, timestamp, sentByMe } = displayMessage;
        let message: ChatMessage;
        const sendEvent = 
            sentByMe 
                ? null
                : (event: "delivered" | "seen", timestamp: number) => this.sendEvent(event, timestamp, messageId);
        if (timestamp < this.earliest) {            
            message = new ChatMessage(displayMessage, null, sendEvent);
            const previous = this.messages[0];
            this.messages.unshift(message);
            previous?.updateFirst(sentByMe !== previous.displayMessage.sentByMe);
            this.earliest = timestamp;
        }
        else if (timestamp > this.latest) {
            const lastSentByMe = this.messages.slice(-1)[0].displayMessage.sentByMe;
            message = new ChatMessage(displayMessage, sentByMe !== lastSentByMe, sendEvent);
            this.messages.push(message);
            this.latest = timestamp;
        }
        if (message) {
            this.indexedMessages.set(messageId, message);
            this.notifyAdded?.();
        }
        else logError(new Error("New message cannot be added in the middle."));
    }
}

type MessageContent = Readonly<{
    text: string;
    timestamp: number;
    replyId?: string;
}>;

type ChatEvent = "details-change" | "added" | "loading-earlier" | "loaded-earlier" | "received-new";

function calculateDelivery(prevDelivery: DeliveryInfo, event: "delivered" | "seen", timestamp: number) {
    const { delivered, seen } = prevDelivery || {};
    let newDelivery: DeliveryInfo;
    if (event === "delivered") {
        newDelivery = {
            delivered: delivered && delivered < timestamp ? delivered : timestamp,
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