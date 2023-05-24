import _ from "lodash";
import { Socket } from "socket.io-client";
import { SessionCrypto } from "../../shared/sessionCrypto";
import { ChattingSession, SendingMessage, ViewChatRequest } from "./e2e-encryption";
import * as crypto from "../../shared/cryptoOperator";
import { MessageHeader, ChatRequestHeader, StoredMessage, ChatData, DisplayMessage, Contact, ReplyingToInfo, SocketServerSideEvents, DeliveryInfo  } from "../../shared/commonTypes";
import { DateTime } from "luxon";
import { allSettledResults, logError, randomFunctions, truncateText } from "../../shared/commonFunctions";
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
    private readonly contactDetails: Omit<Contact, "username">;
    readonly #chattingSession: ChattingSession;
    readonly #encryptionBaseVector: CryptoKey;
    #sessionCrypto: SessionCrypto;
    #socket: Socket;

    private get hasRoom() { return !!this.#sessionCrypto; }

    get lastActive() { return this.latestMessageAt; }

    get details(): ChatDetails {
        const { otherUser, contactDetails: { displayName, profilePicture, contactName }, lastActivity, isOtherTyping } = this;
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
        this.#socket?.off(`${this.otherUser} -> ${this.me}`);
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
        await chat.loadUnprocessedMessages().then(() => chat.loadNext());
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
        this.#socket.on(`${this.otherUser} -> ${this.me}`, this.receiveMessage.bind(this));
        this.#socket.on("disconnect", () => {
            this.disconnectRoom();
        })
        this.notifyActivity?.();
        this.loadUnprocessedMessages();
        this.notify?.("details-change");
    }

    async sendMessage(messageContent: MessageContent) {
        if (this.disposed) {
            return false;
        }
        const { text, timestamp, replyId } = messageContent;
        const messageId = getRandomString(15, "hex");
        const sendingMessage = { messageId, text, timestamp, replyingTo: replyId };
        const replyingTo = await this.populateReplyingTo(replyId);
        if (replyingTo === undefined) {
            logError("Failed to come up with replied-to message.");
            return false;
        }
        const displayMessage: DisplayMessage ={ 
            messageId, 
            text,
            replyingTo,
            timestamp,
            sentByMe: true,
            delivery: null
        };
        this.addMessageToList(displayMessage);
        const encryptedMessage = crypto.deriveEncrypt(displayMessage, this.#encryptionBaseVector, this.sessionId).then((content) => ({ messageId, timestamp, content }));
        const exportedChattingSession = await this.#chattingSession.sendMessage(sendingMessage, async (header) => await this.dispatch(header, true));
        if (typeof exportedChattingSession === "string") {
            logError(exportedChattingSession);
            return false;
        }
        await this.clientInterface.StoreMessage(await encryptedMessage);
        const sentChatMessage = this.messagesList.get(messageId);
        if (sentChatMessage) {
            sentChatMessage.signalEvent("sent", Date.now());
            this.lastActivity = sentChatMessage.displayMessage;
            this.notifyActivity?.();
        }
        const { latestMessageAt: lastActive } = this;
        await this.clientInterface.UpdateChat({ lastActive, exportedChattingSession });
        return true;
    }

    async sendEvent(event: "typing" | "stopped-typing", timestamp: number): Promise<boolean>;
    async sendEvent(event: "delivered" | "seen", timestamp: number, reportingAbout: string): Promise<boolean>;
    async sendEvent(event: "typing" | "stopped-typing" | "delivered" | "seen", timestamp: number, reportingAbout?: string): Promise<boolean> {
        if (this.disposed) {
            return false;
        }
        const sendWithoutRoom = event === "delivered" || event === "seen";
        if (!sendWithoutRoom && !this.hasRoom) {
            return false;
        }
        const decrementUnread = event === "seen" && this.unreadMessagesList.includes(reportingAbout);
        const messageId = getRandomString(15, "hex");
        const sendingMessage: SendingMessage =
            event === "delivered" || event === "seen"
                ? { messageId, timestamp, event, reportingAbout }
                : { messageId, timestamp, event };
        const exportedChattingSession = await this.#chattingSession.sendMessage(sendingMessage, async (header) => {
            const success = await this.dispatch(header, sendWithoutRoom);
            if (success && (event === "delivered" || event === "seen")) {
                const message = await this.getMessageById(reportingAbout);
                const delivery = calculateDelivery(message.delivery, event, timestamp);
                await this.encryptStoreMessage({ ...message, delivery }, false);
            }
            return success;
        });
        if (typeof exportedChattingSession === "string") {
            logError(exportedChattingSession);
            return false;
        }
        const { latestMessageAt: lastActive } = this;
        await this.clientInterface.UpdateChat({ lastActive, exportedChattingSession });
        if (decrementUnread) {
            _.pull(this.unreadMessagesList, reportingAbout);
            this.notifyActivity?.();
        }
    }

    private async dispatch(header: MessageHeader, sendWithoutRoom: boolean) {
        let tries = 0;
        let success = false;
        const dispatchEvent = `${this.me} -> ${this.otherUser}`;
        if (this.hasRoom) {
            while (!success && tries <= 10) {
                tries++;
                success = await new Promise<boolean>(async (resolve) => {
                    this.#socket?.emit(dispatchEvent, await this.#sessionCrypto.signEncryptToBase64(header, dispatchEvent), (response: boolean) => resolve(response));
                    window.setTimeout(() => resolve(false), 5000);
                });
            }
        }
        else if (sendWithoutRoom) {
            while (!success && tries <= 10) {
                tries++;
                success = !(await this.clientInterface.SendMessage(header)).reason;
            }
        }
        return success;
    }

    async performLoad(load: () => Promise<void>) {
        this.isLoading = true;
        this.notify?.("loading-earlier");
        await load();
        this.isLoading = false;
        this.notify?.("loaded-earlier");
    }

    async loadNext() {
        if (this.disposed || this.isLoading || !this.canLoadFurther) return;
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
        if (this.disposed || this.isLoading || this.messagesList.has(messageId)) return;
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
        if (this.disposed || this.isLoading || !this.canLoadFurther) return;
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
        return await this.processEncryptedMessage(message);
    }

    private addMessageToList(message: DisplayMessage) {
        const { messageId, timestamp } = message;
        const date = DateTime.fromMillis(timestamp).toISODate();
        let chatMessageList = this.chatMessageLists.get(date);
        if (chatMessageList) {
            chatMessageList.add(message);
        }
        else {
            chatMessageList = 
            ChatMessageListInternal.construct(message, (event, timestamp, reportingAbout) => this.sendEvent(event, timestamp, reportingAbout));
            this.chatMessageLists.set(date, chatMessageList);
            this.notify?.("added");
        }
        this.messagesList.set(messageId, chatMessageList.messageById(messageId));
        if (timestamp >= (this.lastActivity?.timestamp || 0)) {
            this.lastActivity = message;
            this.latestMessageAt = timestamp;
            if (!message.sentByMe && !message.delivery?.seen) this.unreadMessagesList.push(messageId);
            this.notify?.("received-new");
            this.notifyActivity?.();
            this.clientInterface.notifyClient();
        }
        else if (timestamp < this.loadedUpto) {
            this.loadedUpto = timestamp;
        }
    }

    private async receiveMessage(data: string, ack: (recv: boolean) => void) {
        if (!data) {
            ack(false);
            return;
        }
        if (data === "room-disconnected") {
            this.disconnectRoom();
            return;
        }
        try {
            const decryptedData: MessageHeader = await this.#sessionCrypto.decryptVerifyFromBase64(data, `${this.otherUser} -> ${this.me}`);
            if (!decryptedData) {
                ack(false);
            }
            else {
                ack(await this.processEncryptedMessage(decryptedData));
            }
        }
        catch (e: any) {
            logError(e);
            ack(false);
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
        const encryptedContent = await crypto.deriveEncrypt(message, this.#encryptionBaseVector, this.sessionId);
        const encryptedMessage = { messageId, timestamp, content: encryptedContent };
        await this.clientInterface.StoreMessage(encryptedMessage);
        if (wasUnprocessed || sentByMe) {
            await this.clientInterface.MessageProcessed({ messageId });
        }
    }

    private async processEncryptedMessage(encryptedMessage: MessageHeader): Promise<boolean> {
        const { messageId } = encryptedMessage;
        const exportedChattingSession = await this.#chattingSession.receiveMessage(encryptedMessage, async (messageBody) => {
            const { sender, timestamp } = messageBody;
            if (sender !== this.otherUser) {
                return false;
            }
            let displayMessage: DisplayMessage;
            if ("event" in messageBody) {
                if (messageBody.event !== "delivered" && messageBody.event !== "seen") {
                    if ((Date.now() - timestamp) < 5000) {
                        this.isOtherTyping = messageBody.event === "typing";
                    }
                    return true;
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
                const { text, replyingTo: replyId } = messageBody;
                const replyingTo = await this.populateReplyingTo(replyId);
                if (replyingTo === undefined) {
                    logError("Failed to come up with replied-to message.");
                    return false;
                }
                displayMessage = { messageId, timestamp, text, replyingTo, sentByMe: false };
                this.addMessageToList(displayMessage);
            }
            await this.encryptStoreMessage(displayMessage, true);
            return true;
        });
        if (typeof exportedChattingSession === "string") {
            if (exportedChattingSession === "Receving Ratchet Number Mismatch") {
                await this.clientInterface.MessageProcessed({ messageId });
            }
            logError(exportedChattingSession);
            return false;
        };
        const { latestMessageAt: lastActive } = this;
        await this.clientInterface.UpdateChat({ lastActive, exportedChattingSession });
        return true;
    }

    private async populateReplyingTo(id: string): Promise<ReplyingToInfo> {
        if (!id) return null;
        const repliedTo = await this.getMessageById(id);
        if (!repliedTo) return undefined;
        const replyToOwn = repliedTo.sentByMe;
        const displayText = truncateText(repliedTo.text);
        return { id, replyToOwn, displayText };
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
            logError(unprocessedMessages.reason);
            return;
        }
        unprocessedMessages = _.sortBy(unprocessedMessages, ["sendingRatchetNumber", "sendingChainNumber"]);
        for (const message of unprocessedMessages) {
            await this.processEncryptedMessage(message);
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
            this.signalEvent = (event, timestamp) => {
                const prevDelivery = this.message.delivery;
                let newDelivery: DeliveryInfo;
                if (event === "sent") {
                    newDelivery = prevDelivery || {
                        delivered: false,
                        seen: false
                    };
                }
                else {
                    newDelivery = calculateDelivery(prevDelivery, event, timestamp);
                }
                if (!_.isEqual(newDelivery, prevDelivery)) {
                    this.message = { ...this.message, delivery: newDelivery };
                    this.notifyChange?.(event);
                    if (event !== "sent") signalEvent?.(event, timestamp);
                }
            }
            if (!displayMessage.sentByMe && !displayMessage.delivery?.delivered) {
                this.signalEvent("delivered", Date.now());
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