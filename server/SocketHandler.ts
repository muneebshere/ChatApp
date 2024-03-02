import _ from "lodash";
import { Socket } from "socket.io";
import { SessionCrypto } from "../shared/sessionCrypto";
import { Failure, ErrorStrings, Username, RequestKeyBundleResponse, SocketClientSideEvents, ChatRequestHeader, EncryptedData, MessageHeader, StoredMessage, ChatData, SocketClientSideEventsKey, SocketServerSideEvents, SocketClientRequestParameters, SocketClientRequestReturn, Receipt, MessageIdentifier, ChatIdentifier, SessionIdentifier, HeaderIdentifier, Backup, SocketServerSideEventsKey, SocketServerRequestParameters, SocketServerRequestReturn, ServerMemo, X3DHKeysData, X3DHData, X3DHDataPartial, SignedEncryptedData, MutableChatData, StatusTransmitData, DirectChannelRequest, PerspectiveSessionInfo } from "../shared/commonTypes";
import { allSettledResults, failure, logError, typedEntries } from "../shared/commonFunctions";
import MongoHandlerCentral, { ServerConfig } from "./MongoHandler";

export type Notify = Readonly<{ 
    type: "Message" | "Receipt", 
    sessionId: string } | {
        type: "ServerMemo", 
        serverMemos: ServerMemo[] 
    } | {
        type: "DirectHeader", 
        header: MessageHeader 
    } | { 
        type: "Request" 
    }>;

type ResponseMap = Readonly<{
    [E in SocketClientSideEventsKey]: (arg: SocketClientRequestParameters[E]) => Promise<SocketClientRequestReturn[E] | Failure>
}>

type EmitHandler = (data: string, respond: (recv: boolean) => void) => void;

type ChannelUser = [string, Socket];

async function createDirectChannel(channelId: string, sessionId: string, [initiatorAlias, initiatorSocket]: ChannelUser, [acceptorAlias, acceptorSocket]: ChannelUser, messageTimeoutMs = 20000): Promise<() => void> {

    try {
        const configureSocket = (socketRecv: Socket, socketForw: Socket, socketEvent: string) => {
            const forward: EmitHandler =
                messageTimeoutMs > 0
                    ? async (data, respond) => {
                        const timeout = setTimeout(() => respond(false), messageTimeoutMs);
                        socketForw.emit(socketEvent, data, (response: boolean) => {
                            clearTimeout(timeout);
                            respond(response);
                        });
                    }
                    : async (data, respond) => socketForw.emit(socketEvent, data, respond);
            socketRecv.on(socketEvent, forward);
            return forward;
        }
        const awaitClient = (socket: Socket) => {
            return new Promise<string>(resolve => {
                socket.once(`${channelId}-establishing`, (response: string) => resolve(response));
                setTimeout(() => resolve(null), 2000);
            });
        }
        const promptClient = (socketRecv: Socket, socketForw: Socket, message: string) => {
            return new Promise<boolean>(resolve => {
                socketRecv.emit(`${channelId}-establishing`, message, (response: string) => {
                    if (response) socketForw.emit(`${channelId}-accepted`, response);
                    resolve(!!response);
                });
                setTimeout(() => resolve(false), 1000);
            });
        }
        console.log(`Attempting to establish channel between socket#${initiatorSocket.id} and socket#${acceptorSocket.id}.`);
        const [initiatorEstablishing, acceptorEstablishing] = await allSettledResults([awaitClient(initiatorSocket), awaitClient(acceptorSocket)]);
        if (initiatorEstablishing && acceptorEstablishing) {
            console.log(`Socket#${initiatorSocket.id} and socket#${acceptorSocket.id}: both establishing connection.`);
            const [initiatorAcceptedInit, acceptorAccepted] = await allSettledResults([promptClient(initiatorSocket, acceptorSocket, acceptorEstablishing), promptClient(acceptorSocket, initiatorSocket, initiatorEstablishing)]);
            if (initiatorAcceptedInit && acceptorAccepted) {
                console.log(`Socket#${initiatorSocket.id} and socket#${acceptorSocket.id}: both accepted connection.`);
                const socketInitiatorEvent = `${sessionId}: ${initiatorAlias} -> ${acceptorAlias}`;
                const socketAcceptorEvent = `${sessionId}: ${acceptorAlias} -> ${initiatorAlias}`;
                const forward1 = configureSocket(initiatorSocket, acceptorSocket, socketInitiatorEvent);
                const forward2 = configureSocket(acceptorSocket, initiatorSocket, socketAcceptorEvent);
                const dispose = () => {
                    initiatorSocket?.emit(socketAcceptorEvent, "channel-disconnected");
                    acceptorSocket?.emit(socketInitiatorEvent, "channel-disconnected");
                    initiatorSocket?.off(socketInitiatorEvent, forward1);
                    acceptorSocket?.off(socketAcceptorEvent, forward2);
                }
                initiatorSocket.on("disconnect", dispose);
                acceptorSocket.on("disconnect", dispose);
                return dispose;
            }
        }
        console.log("Couldn't establish channel");
        console.log(`Initiator socket#${initiatorSocket.id} establishing: ${!!initiatorEstablishing}.\n`);
        console.log(`Acceptor socket#${acceptorSocket.id} establishing: ${!!acceptorEstablishing}.\n`);
        console.log(`Initiator socket#${initiatorSocket.id} accepted: ${!!initiatorEstablishing}.\n`);
        console.log(`Acceptor socket#${acceptorSocket.id} accepted: ${!!acceptorEstablishing}.\n`);
        return null;
    }
    catch(err) {
        logError(err);
        return null;
    }
}

function initializeDirectChannel(channelId: string, sessionId: string, channelInitiator: ChannelUser, messageTimeoutMs = 20000) {
    return (channelAcceptor: ChannelUser) => createDirectChannel(channelId, sessionId, channelInitiator, channelAcceptor, messageTimeoutMs);
}

export default class SocketHandler {
    static serverConfig: ServerConfig;
    private static socketHandlers = new Map<string, SocketHandler>();
    private static onlineUsers = new Map<string, { sessionReference: string, ipRep: string }>();
    private static waitingChannels = new Map<string, & Readonly<{
        sessionId: string,
        initiatorAlias: string,
        acceptorAlias: string,
        halfChannel: ReturnType<typeof initializeDirectChannel>
    }>>();
    private readonly responseMap: ResponseMap = {
        [SocketClientSideEvents.ClientLoaded]: this.OnClientLoad,
        [SocketClientSideEvents.UsernameExists]: this.UsernameExists,
        [SocketClientSideEvents.UpdateProfile]: this.UpdateProfile,
        [SocketClientSideEvents.UpdateX3DHData]: this.UpdateX3DHData,
        [SocketClientSideEvents.FetchUserData]: this.FetchUserData,
        [SocketClientSideEvents.RequestKeyBundle]: this.RequestKeyBundle,
        [SocketClientSideEvents.GetAllChats]: this.GetAllChats,
        [SocketClientSideEvents.GetAllRequests]: this.GetAllRequests,
        [SocketClientSideEvents.GetMessageHeaders]: this.GetMessageHeaders,
        [SocketClientSideEvents.GetMessagesByNumber]: this.GetMessagesByNumber,
        [SocketClientSideEvents.GetMessagesUptoTimestamp]: this.GetMessagesUptoTimestamp,
        [SocketClientSideEvents.GetMessagesUptoId]: this.GetMessagesUptoId,
        [SocketClientSideEvents.GetMessageById]: this.GetMessageById,
        [SocketClientSideEvents.StoreMessage]: this.StoreMessage,
        [SocketClientSideEvents.MessageHeaderProcessed]: this.MessageHeaderProcessed,
        [SocketClientSideEvents.CreateChat]: this.CreateChat,
        [SocketClientSideEvents.UpdateChat]: this.UpdateChat,
        [SocketClientSideEvents.RegisterPendingSession]: this.RegisterPendingSession,
        [SocketClientSideEvents.SendChatRequest]: this.SendChatRequest,
        [SocketClientSideEvents.SendMessage]: this.SendMessage,
        [SocketClientSideEvents.DeleteChatRequest]: this.DeleteChatRequest,
        [SocketClientSideEvents.StoreBackup]: this.StoreBackup,
        [SocketClientSideEvents.GetBackupById]: this.GetBackupById,
        [SocketClientSideEvents.BackupProcessed]: this.BackupProcessed,
        [SocketClientSideEvents.ServerMemosProcessed]: this.ServerMemosProcessed,
        [SocketClientSideEvents.SendReceipt]: this.SendReceipt,
        [SocketClientSideEvents.GetAllReceipts]: this.GetAllReceipts,
        [SocketClientSideEvents.ClearAllReceipts]: this.ClearAllReceipts,
        [SocketClientSideEvents.RequestDirectChannel]: this.RequestDirectChannel,
        [SocketClientSideEvents.TransmitStatus]: this.TransmitStatus
    };
    
    private interval: NodeJS.Timeout;
    #sessionCrypto: SessionCrypto;
    #socket: Socket;
    #mongoHandler: typeof MongoHandlerCentral.UserHandlerType;
    #username: string;
    readonly #deleteSelf: () => void;
    readonly #disposeChannels: (() => void)[] = [];
    readonly #notifyOffline = new Map<string, MessageHeader>();

    static get sessionReferences() {
        return Array.from(this.socketHandlers.keys());
    }

    static getUsername(sessionReference: string) {
        const sessionHandler = this.socketHandlers.get(sessionReference);
        return sessionHandler ? sessionHandler.#username : null;
    }

    static isUserActive(username: string) {
        return this.onlineUsers.has(username);
    }

    static async confirmUserSession(sessionReference: string, authToken: string, authData: string) {
        return this.socketHandlers.get(sessionReference)?.confirmAuthToken(authToken, authData) || false;

    }

    static async registerSocket(sessionReference: string, ipRep: string, authToken: string, authData: string, socket: Socket) {
        return this.socketHandlers.get(sessionReference)?.registerNewSocket(ipRep, authToken, authData, socket) || false;
    }

    static async disposeSession(sessionReference: string, reason: string) {
        await this.socketHandlers.get(sessionReference)?.dispose(reason);
        MongoHandlerCentral.clearRunningClientSession(sessionReference);
    }

    constructor(username: string, sessionReference: string, ipRep: string, mongoHandler: typeof MongoHandlerCentral.UserHandlerType, sessionCrypto: SessionCrypto) {
        this.#username = username;
        this.#mongoHandler = mongoHandler;
        this.#sessionCrypto = sessionCrypto;
        this.#mongoHandler.subscribe(this.notify.bind(this));
        this.#deleteSelf = () => SocketHandler.socketHandlers.delete(sessionReference);
        SocketHandler.socketHandlers.set(sessionReference, this);
        SocketHandler.onlineUsers.set(username, { sessionReference, ipRep });
    }

    private async confirmAuthToken(authToken: string, authData: string) {
        const { username, authNonce } = await this.#sessionCrypto?.decryptVerifyFromBase64(authToken, "Socket Auth") || {};
        return (username === this.#username) && (authNonce === authData);
    }

    private async deregisterSocket(reason: string) {
        clearInterval(this.interval);
        if (this.#socket) {
            console.log(`Disonnected: socket#${this.#socket.id} due to ${reason}.`);
            this.#disposeChannels.forEach((disposeRoom) => disposeRoom());
            this.#socket.removeAllListeners();
            await this.request(SocketServerSideEvents.ServerDisconnecting, { reason }, 500);
            this.#socket?.disconnect(true);
            this.#socket = null;
        }
    }

    private async registerNewSocket(ipRep: string, authToken: string, authData: string, socket: Socket) {
        if (!this.#username) return false;
        if (SocketHandler.onlineUsers.get(this.#username)?.ipRep !== ipRep) return false;
        if (!(await this.confirmAuthToken(authToken, authData))) return false;
        await this.deregisterSocket("Another socket connection being established with this session.");
        this.#socket = socket;
        for (let [event] of typedEntries(this.responseMap)) {
            const responseBy = this.responseMap[event].bind(this);
            socket.on(event, async (data: string, resolve) => await this.respond(event, data, responseBy, resolve));
        }
        socket.on("disconnect", async () => await this.deregisterSocket(""));
        /* this.interval = setInterval(async () => {
            const response = await this.request(SocketServerSideEvents.PollConnection, [], 9500);
            if (response?.reason !== false || response.details.alive !== "aliveHere") this.dispose("No response when polled.");
        }, 5000) */
        return true;
    }

    private async request<E extends SocketServerSideEventsKey>(event: E, data: SocketServerRequestParameters[E], timeout = 0): Promise<SocketServerRequestReturn[E] | Failure> {
        if (!this.#socket) return failure(ErrorStrings.NoConnectivity);
        const { payload } = await new Promise<any>(async (resolve) => {
            this.#socket.emit(event, (await this.#sessionCrypto?.signEncryptToBase64({ payload: data }, event)),
                async (response: string) => resolve((response && await this.#sessionCrypto?.decryptVerifyFromBase64(response, event)) || {}));
            if (timeout > 0) {
                setTimeout(() => resolve(failure(ErrorStrings.NoConnectivity)), timeout);
            }
        });
        return payload || failure(ErrorStrings.DecryptFailure);
    }

    private async respond<E extends SocketClientSideEventsKey>(event: E, data: string, responseBy: (arg: SocketClientRequestParameters[E]) => Promise<SocketClientRequestReturn[E] | Failure>, resolve: (arg0: string) => void) {
        const encryptResolve = async (response: SocketClientRequestReturn[E] | Failure) => {
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

    private async OnClientLoad(): Promise<Failure> {
        const { minOneTimeKeys, maxOneTimeKeys, replaceKeyAtMillis } = SocketHandler.serverConfig;
        const { preKeyLastReplacedAt, currentOneTimeKeysNumber } = this.#mongoHandler.getKeyStats();
        const preKeyResult = await this.replacePreKey(preKeyLastReplacedAt, replaceKeyAtMillis);
        const oneTimeKeyResult = await this.newOneTimeKeys(minOneTimeKeys, maxOneTimeKeys, currentOneTimeKeysNumber);
        if (preKeyResult?.reason !== false || oneTimeKeyResult?.reason !== false) {
            logError(`${preKeyResult.reason}\n${oneTimeKeyResult.reason}`);
            return failure(ErrorStrings.ProcessFailed, { preKeyResult, oneTimeKeyResult });
        }
        return { reason: false };
    }

    private async replacePreKey(preKeyLastReplacedAt: number, replaceKeyAtMillis: number): Promise<Failure> {
        if (preKeyLastReplacedAt === 0 || (Date.now() - preKeyLastReplacedAt) > replaceKeyAtMillis) {
            const response = await this.request(SocketServerSideEvents.RequestIssueNewKeys, { n: 0 });
            if ("reason" in response) {
                logError(response);
                return failure(ErrorStrings.ProcessFailed, response);
            }
            if (!(await this.#mongoHandler.rotateKeys(response))) {
                logError("Couldn't change preKey in database.");
                return failure(ErrorStrings.ProcessFailed);
            };
        }
        return { reason: false };
    }

    private async newOneTimeKeys(minOneTimeKeys: number, maxOneTimeKeys: number, currentOneTimeKeysNumber: number): Promise<Failure> {
        if (currentOneTimeKeysNumber < minOneTimeKeys) {
            const n = maxOneTimeKeys - currentOneTimeKeysNumber;
            const response = await this.request(SocketServerSideEvents.RequestIssueNewKeys, { n });
            if ("reason" in response) {
                logError(response);
                return failure(ErrorStrings.ProcessFailed, response);
            }
            if (!(await this.#mongoHandler.rotateKeys(response))) {
                logError("Couldn't set oneTimeKeys in database.");
                return failure(ErrorStrings.ProcessFailed);
            };
        }
        return { reason: false };
    }

    private async UsernameExists({ username }: Username): Promise<{ exists: boolean }> {
        return { exists: await MongoHandlerCentral.userExists(username) };
    }

    private async RegisterPendingSession(param: Readonly<{ sessionId: string, myAlias: string, otherAlias: string }>): Promise<Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.registerPendingSession(param.sessionId, param.myAlias, param.otherAlias))) return failure(ErrorStrings.ProcessFailed);
        return { reason: false };

    }

    private async UpdateProfile({ profileData }: { profileData: SignedEncryptedData }): Promise<Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.updateProfile(profileData))) return failure(ErrorStrings.ProcessFailed);
        return { reason: false };
    }

    private async UpdateX3DHData({ x3dhData }: { x3dhData: X3DHDataPartial }): Promise<Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.updateX3dhData(x3dhData))) return failure(ErrorStrings.ProcessFailed);
        return { reason: false };
    }
 
    private async FetchUserData(): Promise<({ x3dhIdentity: EncryptedData, x3dhData: X3DHData, profileData: SignedEncryptedData }) | Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        const { x3dhIdentity, x3dhData, profileData } = this.#mongoHandler.getUserData();
        return { x3dhIdentity, x3dhData, profileData };
    }

    private async RequestKeyBundle({ username }: Username): Promise<RequestKeyBundleResponse | Failure> {
        if (!this.#username || username === this.#username) return failure(ErrorStrings.InvalidRequest);
        const keyBundle = await this.#mongoHandler.getKeyBundle(username);
        if (!keyBundle) return failure(ErrorStrings.ProcessFailed);
        if (typeof keyBundle === "string") return failure(ErrorStrings.ProcessFailed, keyBundle);
        return { keyBundle };
    }

    private async RequestDirectChannel({ action, directChannelId, header }: DirectChannelRequest): Promise<Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        const { sessionId, fromAlias, toAlias } = header;
        if (action === "requesting") {
            console.log(`Socket#${this.#socket.id} requested direct channel.`);
            const halfChannel: ReturnType<typeof initializeDirectChannel> = async (channelUser2) => {
                const dispose = await initializeDirectChannel(directChannelId, sessionId, [fromAlias, this.#socket])(channelUser2);
                if (dispose) this.#disposeChannels.push(dispose);
                return dispose;
            };
            SocketHandler.waitingChannels.set(directChannelId, { sessionId, initiatorAlias: fromAlias, acceptorAlias: toAlias , halfChannel });
            const success = this.#mongoHandler.sendDirectHeader(header);
            if (success) setTimeout(() => SocketHandler.waitingChannels.delete(directChannelId), 2000);
            else SocketHandler.waitingChannels.delete(directChannelId);
            return success 
                    ? { reason: false } 
                    : failure(ErrorStrings.ProcessFailed);
        }
        else if (action === "responding") {
            console.log(`Socket#${this.#socket.id} responded to direct channel.`);
            const waitingChannel = SocketHandler.waitingChannels.get(directChannelId);
            SocketHandler.waitingChannels.delete(directChannelId);
            if (!waitingChannel) return failure(ErrorStrings.ProcessFailed);
            const { halfChannel, ...req } = waitingChannel;
            if (req.sessionId !== sessionId || req.initiatorAlias !== toAlias || req.acceptorAlias !== fromAlias) return failure(ErrorStrings.InvalidRequest);
            const success = this.#mongoHandler.sendDirectHeader(header);
            if (success) {
                halfChannel([fromAlias, this.#socket]).then(dispose => this.#disposeChannels.push(dispose));
                return { reason: false };
            }
            else return  failure(ErrorStrings.ProcessFailed);
        }
        else return failure(ErrorStrings.InvalidRequest);
    }

    private async SendChatRequest(chatRequest: ChatRequestHeader): Promise<Failure> {
        if (!this.#username || this.#username === chatRequest.addressedTo) return failure(ErrorStrings.InvalidRequest);
        if (!(await MongoHandlerCentral.depositChatRequest(chatRequest))) return failure(ErrorStrings.ProcessFailed);
        return { reason: false };
    }

    private async SendMessage(message: MessageHeader): Promise<Failure> {
        if (!this.#username || this.#username === message.toAlias) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.depositMessage(message))) return failure(ErrorStrings.ProcessFailed);
        else return { reason: false };
    }
 
    private async GetAllChats(): Promise<ChatData[] | Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        return await this.#mongoHandler.getAllChats();
    }

    private async GetAllRequests(): Promise<ChatRequestHeader[] | Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        return (await this.#mongoHandler.getAllRequests(this.#username)) || failure(ErrorStrings.ProcessFailed);
    }

    private async GetMessageHeaders({ sessionId, toAlias, fromAlias }: SessionIdentifier & { fromAlias: string }): Promise<MessageHeader[] | Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        return (await this.#mongoHandler.getMessageHeaders(sessionId, toAlias, fromAlias)) || failure(ErrorStrings.ProcessFailed);
    }

    private async GetMessagesByNumber(param: ChatIdentifier & { limit: number, olderThanTimemark: number }): Promise<StoredMessage[] | Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        let { chatId, limit, olderThanTimemark } = param;
        return (await this.#mongoHandler.getMessagesByNumber(chatId, limit, olderThanTimemark)) || failure(ErrorStrings.ProcessFailed);
    }

    private async GetMessagesUptoTimestamp(param: ChatIdentifier & { newerThanTimemark: number, olderThanTimemark: number }): Promise<StoredMessage[] | Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        let { chatId, newerThanTimemark, olderThanTimemark } = param;
        return (await this.#mongoHandler.getMessagesUptoTimestamp(chatId, newerThanTimemark, olderThanTimemark)) || failure(ErrorStrings.ProcessFailed);
    }

    private async GetMessagesUptoId(param: MessageIdentifier & { olderThanTimemark: number }): Promise<StoredMessage[] | Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        let { chatId, hashedId, olderThanTimemark } = param;
        return (await this.#mongoHandler.getMessagesUptoId(chatId, hashedId, olderThanTimemark)) || failure(ErrorStrings.ProcessFailed);
    }

    private async GetMessageById({ chatId, hashedId }: MessageIdentifier): Promise<StoredMessage | Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        return (await this.#mongoHandler.getMessageById(chatId, hashedId)) || failure(ErrorStrings.ProcessFailed);
    }

    private async StoreMessage(message: StoredMessage): Promise<Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.storeMessage(message))) return failure(ErrorStrings.ProcessFailed);
        return { reason: false };
    }

    private async MessageHeaderProcessed({ sessionId, toAlias, headerId }: SessionIdentifier & HeaderIdentifier): Promise<Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.messageHeaderProcessed(toAlias, sessionId, headerId))) return failure(ErrorStrings.ProcessFailed);
        return { reason: false };
    }

    private async CreateChat(chatData: ChatData & { otherUser: string }): Promise<Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.createChat(chatData))) return failure(ErrorStrings.ProcessFailed);
        return { reason: false };
    }

    private async UpdateChat(chat: ChatIdentifier & Partial<MutableChatData>): Promise<Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.updateChat(chat))) return failure(ErrorStrings.ProcessFailed);
        return { reason: false };
    }

    private async DeleteChatRequest({ headerId }: { headerId: string }): Promise<Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.deleteChatRequest(headerId))) return failure(ErrorStrings.ProcessFailed);
        return { reason: false };
    }

    private async StoreBackup(backup: Backup): Promise<Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.storeBackup(backup))) return failure(ErrorStrings.ProcessFailed);
        return { reason: false };
    }

    private async GetBackupById({ byAlias, sessionId, headerId }: HeaderIdentifier & { byAlias: string }): Promise<Backup | Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        return (await this.#mongoHandler.getBackupById(byAlias, sessionId, headerId)) || failure(ErrorStrings.ProcessFailed);
    }

    private async BackupProcessed({ byAlias, sessionId, headerId }: HeaderIdentifier & { byAlias: string }): Promise<Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.backupProcessed(byAlias, sessionId, headerId))) return failure(ErrorStrings.ProcessFailed);
        return { reason: false };
    }

    private async ServerMemosProcessed({ processed, x3dhData }: { processed: string[], x3dhData: X3DHKeysData }): Promise<Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.discardMemos(processed, x3dhData))) return failure(ErrorStrings.ProcessFailed);
        return { reason: false };
    }

    private async SendReceipt(receipt: Receipt): Promise<Failure> {
        if (!this.#username || this.#username === receipt.toAlias) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.depositReceipt(receipt))) return failure(ErrorStrings.ProcessFailed);
        return { reason: false };
    }

    private async TransmitStatus(status: StatusTransmitData): Promise<Failure> {
        const { sessionId, toAlias, fromAlias, online, offline } = status;
        if (!this.#mongoHandler.sendDirectHeader({ sessionId, toAlias, fromAlias, ...online })) return failure(ErrorStrings.ProcessFailed);
        this.#notifyOffline.set(sessionId, { sessionId, toAlias, fromAlias, ...offline });
        return { reason: false };
    }

    private async GetAllReceipts({ toAlias, sessionId }: SessionIdentifier): Promise<Receipt[] | Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        return (await this.#mongoHandler.getAllReceipts(toAlias, sessionId)) || failure(ErrorStrings.ProcessFailed);
    }

    private async ClearAllReceipts({ toAlias, sessionId }: SessionIdentifier): Promise<Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.clearAllReceipts(toAlias, sessionId))) return failure(ErrorStrings.ProcessFailed);
        return { reason: false };
    }

    private async notify(notify: Notify) {
        if (notify.type === "Request") {
            await this.request(SocketServerSideEvents.ChatRequestReceived, []);
        }
        else if (notify.type === "Message") {
            await this.request(SocketServerSideEvents.MessageReceived, _.pick(notify, "sessionId"));
        }
        else if (notify.type === "ServerMemo") {
            await this.request(SocketServerSideEvents.ServerMemoDeposited, _.pick(notify, "serverMemos"));
        }
        else if (notify.type === "DirectHeader") {
            await this.request(SocketServerSideEvents.DirectHeaderReceived, _.pick(notify, "header"));
        }
        else {
            await this.request(SocketServerSideEvents.ReceiptReceived, _.pick(notify, "sessionId"));
        }
    }

    private async dispose(reason: string) {
        await this.deregisterSocket(reason);
        await Promise.all(Array.from(this.#notifyOffline.entries()).map(([,header]) => this.#mongoHandler.sendDirectHeader(header)));
        this.#notifyOffline.clear();
        this.#disposeChannels.forEach((disposeChannel) => disposeChannel());
        this.#disposeChannels.length = 0;
        this.#mongoHandler?.unsubscribe();
        SocketHandler.onlineUsers.delete(this.#username);
        this.#deleteSelf();
        this.#sessionCrypto = null;
        this.#username = null;
        this.#mongoHandler = null;
    }
}