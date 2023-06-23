import _ from "lodash";
import { Socket } from "socket.io";
import { SessionCrypto } from "../shared/sessionCrypto";
import { Failure, ErrorStrings, Username, PublishKeyBundlesRequest, RequestKeyBundleResponse, SocketClientSideEvents, ChatRequestHeader, UserEncryptedData, MessageHeader, StoredMessage, ChatData, SocketClientSideEventsKey, SocketServerSideEvents, SocketClientRequestParameters, SocketClientRequestReturn, Receipt, MessageIdentifier, ChatIdentifier, SessionIdentifier, HeaderIdentifier, Backup, UserData } from "../shared/commonTypes";
import { allSettledResults, failure, logError, typedEntries } from "../shared/commonFunctions";
import { MongoHandlerCentral } from "./MongoHandler";

export type Notify = Readonly<{ type: "Message" | "Receipt", sessionId: string } | { type: "Request" }>;

type ResponseMap = Readonly<{
    [E in SocketClientSideEventsKey]: (arg: SocketClientRequestParameters[E]) => Promise<SocketClientRequestReturn[E] | Failure>
}>

type EmitHandler = (data: string, respond: (recv: boolean) => void) => void;

type RoomUser = [string, Socket, SessionCrypto];

async function createRoom([username1, socket1, sessionCrypto1]: RoomUser, [username2, socket2, sessionCrypto2]: RoomUser, messageTimeoutMs = 20000): Promise<() => void> {

    function configureSocket(socketRecv: Socket, cryptoRecv: SessionCrypto, socketForw: Socket, cryptoForw: SessionCrypto, socketEvent: string) {
        const decrypt = (data: string) => cryptoRecv.decryptVerifyFromBase64(data, socketEvent);
        const encrypt = (data: any) => cryptoForw.signEncryptToBase64(data, socketEvent);
        const repackage = async (data: string) => await encrypt(await decrypt(data))
        const forward: EmitHandler =
            messageTimeoutMs > 0
                ? async (data, respond) => {
                    const timeout = setTimeout(() => respond(false), messageTimeoutMs);
                    socketForw.emit(socketEvent, await repackage(data), (response: boolean) => {
                        clearTimeout(timeout);
                        respond(response);
                    });
                }
                : async (data, respond) => socketForw.emit(socketEvent, await repackage(data), respond);
        socketRecv.on(socketEvent, forward);
        return forward;
    }

    function constructRoom() {
        const socket1Event = `${username1} -> ${username2}`;
        const socket2Event = `${username2} -> ${username1}`;
        const forward1 = configureSocket(socket1, sessionCrypto1, socket2, sessionCrypto2, socket1Event);
        const forward2 = configureSocket(socket2, sessionCrypto2, socket1, sessionCrypto1, socket2Event);
        const dispose = () => {
            socket1?.emit(socket2Event, "room-disconnected");
            socket2?.emit(socket1Event, "room-disconnected");
            socket1?.off(socket1Event, forward1);
            socket2?.off(socket2Event, forward2);
        }
        socket1.on("disconnect", dispose);
        socket2.on("disconnect", dispose);
        return dispose;
    }

    function awaitClientRoomReady(socket: Socket, otherUsername: string) {
        return new Promise<boolean>((resolve) => {
            const response = (withUser: string) => {
                if (withUser === otherUsername) {
                    socket.off(SocketServerSideEvents.ClientRoomReady, response);
                    resolve(true);
                }
            };
            socket.on(SocketServerSideEvents.ClientRoomReady, response);
            setTimeout(() => {
                socket.off(SocketServerSideEvents.ClientRoomReady, response);
                resolve(false);
            }, 1000);
        });
    }

    const established1 = awaitClientRoomReady(socket1, username2);
    const established2 = awaitClientRoomReady(socket2, username1);

    socket1.emit(SocketServerSideEvents.ServerRoomReady, username2);
    socket2.emit(SocketServerSideEvents.ServerRoomReady, username1);

    const [est1, est2] = await allSettledResults([established1, established2]);
    if (est1 && est2) {
        const dispose = constructRoom();
        socket1.emit(username2, "confirmed");
        socket2.emit(username1, "confirmed");
        return dispose;
    }
    else {
        return null;
    }
}

function halfCreateRoom(roomUser1: RoomUser, messageTimeoutMs = 20000) {
    return (roomUser2: RoomUser) => createRoom(roomUser1, roomUser2, messageTimeoutMs);
}

export default class SocketHandler {
    private static socketHandlers = new Map<string, SocketHandler>();
    private static onlineUsers = new Map<string, { sessionReference: string, ipRep: string }>();

    private readonly responseMap: ResponseMap = {
        [SocketClientSideEvents.UsernameExists]: this.UsernameExists,
        [SocketClientSideEvents.PublishKeyBundles]: this.PublishKeyBundles,
        [SocketClientSideEvents.UpdateUserData]: this.UpdateUserData,
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
        [SocketClientSideEvents.SendReceipt]: this.SendReceipt,
        [SocketClientSideEvents.GetAllReceipts]: this.GetAllReceipts,
        [SocketClientSideEvents.ClearAllReceipts]: this.ClearAllReceipts,
        [SocketClientSideEvents.RequestRoom]: this.RoomRequested
    };
    private readonly deleteSelf: () => void;
    #sessionCrypto: SessionCrypto;
    #socket: Socket;
    #mongoHandler: typeof MongoHandlerCentral.UserHandlerType;
    #openToRoomTemp: Username;
    #username: string;
    #disposeRooms: (() => void)[] = [];

    static getUsername(sessionReference: string) {
        const sessionHandler = this.socketHandlers.get(sessionReference);
        return sessionHandler ? sessionHandler.#username : null;
    }

    static getUserStatus(username: string, currentIp: string): "ActiveHere" | "ActiveElsewhere" | "Offline" {
        const { sessionReference, ipRep } = this.onlineUsers.get(username) || {};
        if (!sessionReference) return "Offline";
        return currentIp === ipRep ? "ActiveHere" : "ActiveElsewhere";
    }

    static async registerSocket(sessionReference: string, ipRep: string, authToken: string, authData: string, socket: Socket) {
        return this.socketHandlers.get(sessionReference)?.registerNewSocket(ipRep, authToken, authData, socket) || false;
    }

    static disposeUserSessions(username: string) {
        this.socketHandlers.get(this.onlineUsers.get(username)?.sessionReference)?.dispose();
    }

    static disposeSession(sessionReference: string) {
        this.socketHandlers.get(sessionReference)?.dispose();
    }

    constructor(username: string, sessionReference: string, ipRep: string, mongoHandler: typeof MongoHandlerCentral.UserHandlerType, sessionCrypto: SessionCrypto) {
        this.#username = username;
        this.#mongoHandler = mongoHandler;
        this.#sessionCrypto = sessionCrypto;
        this.#mongoHandler.subscribe(this.notifyMessage.bind(this));
        this.deleteSelf = () => SocketHandler.socketHandlers.delete(sessionReference);
        SocketHandler.socketHandlers.set(sessionReference, this);
        SocketHandler.onlineUsers.set(username, { sessionReference, ipRep });
    }

    private deregisterSocket() {
        if (this.#socket) {
            console.log(`Disonnected: socket#${this.#socket.id}`);
            this.#disposeRooms.forEach((disposeRoom) => disposeRoom());
            this.#socket.removeAllListeners();
            this.#socket.disconnect();
            this.#socket = null;
        }
    }

    private async registerNewSocket(ipRep: string, authToken: string, authData: string, socket: Socket) {
        if (!this.#username) return false;
        if (SocketHandler.onlineUsers.get(this.#username)?.ipRep !== ipRep) return false;
        const { username, authNonce } = await this.#sessionCrypto.decryptVerifyFromBase64(authToken, "Socket Auth") || {};
        if (username !== this.#username || authNonce !== authData) return false;
        this.deregisterSocket();
        this.#socket = socket;
        for (let [event] of typedEntries(this.responseMap)) {
            const responseBy = this.responseMap[event].bind(this);
            socket.on(event, async (data: string, resolve) => await this.respond(event, data, responseBy, resolve));
        }
        socket.on("disconnect", this.deregisterSocket.bind(this));
        return true;
    }

    private async request(event: string, data: any, timeout = 0): Promise<any> {
        return await new Promise(async (resolve: (result: any) => void) => {
            this.#socket?.emit(event, await this.#sessionCrypto.signEncryptToBase64(data, event),
                async (response: string) => resolve(response ? await this.#sessionCrypto.decryptVerifyFromBase64(response, event) : failure(ErrorStrings.DecryptFailure)));
            if (timeout > 0) {
                setTimeout(() => resolve(failure(ErrorStrings.NoConnectivity)), timeout);
            }
        }).catch((err) => console.log(`${err}\n${err.stack}`));
    }

    private async respond(event: SocketClientSideEventsKey, data: string, responseBy: (arg: SocketClientRequestParameters[typeof event]) => Promise<SocketClientRequestReturn[typeof event] | Failure>, resolve: (arg0: string) => void) {
        const encryptResolve = async (response: SocketClientRequestReturn[typeof event] | Failure) => {
            if (!this.#sessionCrypto) resolve(null);
            else resolve(await this.#sessionCrypto.signEncryptToBase64({ payload: response }, event));
        }
        try {
            const decryptedData = await this.#sessionCrypto.decryptVerifyFromBase64(data, event);
            if (!decryptedData) await encryptResolve(failure(ErrorStrings.DecryptFailure));
            else {
                const response = await responseBy(decryptedData);
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

    private async UsernameExists({ username }: Username): Promise<{ exists: boolean }> {
        return { exists: await MongoHandlerCentral.userExists(username) };
    }

    private async RegisterPendingSession(param: Readonly<{ sessionId: string, myAlias: string, otherAlias: string }>): Promise<Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.registerPendingSession(param.sessionId, param.myAlias, param.otherAlias))) return failure(ErrorStrings.ProcessFailed);
        return { reason: null };

    }

    private async UpdateUserData(userData: { x3dhInfo?: UserEncryptedData, chatsData?: UserEncryptedData } & Username): Promise<Failure> {
        if (!this.#username || this.#username !== userData.username) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.updateUserData(userData))) return failure(ErrorStrings.ProcessFailed);
        return { reason: null };
    }

    private async PublishKeyBundles(keyBundles: PublishKeyBundlesRequest): Promise<Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.publishKeyBundles(keyBundles))) return failure(ErrorStrings.ProcessFailed);
        return { reason: null };
    }

    private async RequestKeyBundle({ username }: Username): Promise<RequestKeyBundleResponse | Failure> {
        if (!this.#username || username === this.#username) return failure(ErrorStrings.InvalidRequest);
        const keyBundle = await MongoHandlerCentral.getKeyBundle(username);
        if (!keyBundle) return failure(ErrorStrings.ProcessFailed);
        return { keyBundle };
    }

    private async RoomRequested({ username }: Username): Promise<Failure> {
        if (!this.#username || this.#username === username) return failure(ErrorStrings.InvalidRequest);
        const otherSocketHandler = SocketHandler.socketHandlers.get(SocketHandler.onlineUsers.get(username)?.sessionReference);
        if (!otherSocketHandler) return failure(ErrorStrings.ProcessFailed);
        const response  = await otherSocketHandler.requestRoom(this.#username);
        if (!response?.reason) {
            const halfRoom = halfCreateRoom([this.#username, this.#socket, this.#sessionCrypto]);
            otherSocketHandler.establishRoom(this.#username, halfRoom).then((dispose) => {
                if (dispose) {
                    this.#disposeRooms.push(dispose);
                }
            });
        }
        return response;
    }

    private async SendChatRequest(chatRequest: ChatRequestHeader): Promise<Failure> {
        if (!this.#username || this.#username === chatRequest.addressedTo) return failure(ErrorStrings.InvalidRequest);
        if (!(await MongoHandlerCentral.depositChatRequest(chatRequest))) return failure(ErrorStrings.ProcessFailed);
        return { reason: null };
    }

    private async SendMessage(message: MessageHeader): Promise<Failure> {
        if (!this.#username || this.#username === message.toAlias) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.depositMessage(message))) return failure(ErrorStrings.ProcessFailed);
        else return { reason: null };
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
        return { reason: null };
    }

    private async MessageHeaderProcessed({ sessionId, toAlias, headerId }: SessionIdentifier & HeaderIdentifier): Promise<Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.messageHeaderProcessed(toAlias, sessionId, headerId))) return failure(ErrorStrings.ProcessFailed);
        return { reason: null };
    }

    private async CreateChat(chat: ChatData): Promise<Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.createChat(chat))) return failure(ErrorStrings.ProcessFailed);
        return { reason: null };
    }

    private async UpdateChat(chat: Omit<ChatData, "chatDetails" | "exportedChattingSession"> & Partial<ChatData>): Promise<Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.updateChat(chat))) return failure(ErrorStrings.ProcessFailed);
        return { reason: null };
    }

    private async DeleteChatRequest({ headerId }: { headerId: string }): Promise<Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.deleteChatRequest(headerId))) return failure(ErrorStrings.ProcessFailed);
        return { reason: null };
    }

    private async StoreBackup(backup: Backup): Promise<Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.storeBackup(backup))) return failure(ErrorStrings.ProcessFailed);
        return { reason: null };
    }

    private async GetBackupById({ byAlias, sessionId, headerId }: HeaderIdentifier & { byAlias: string }): Promise<Backup | Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        return (await this.#mongoHandler.getBackupById(byAlias, sessionId, headerId)) || failure(ErrorStrings.ProcessFailed);
    }

    private async BackupProcessed({ byAlias, sessionId, headerId }: HeaderIdentifier & { byAlias: string }): Promise<Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.backupProcessed(byAlias, sessionId, headerId))) return failure(ErrorStrings.ProcessFailed);
        return { reason: null };
    }

    private async SendReceipt(receipt: Receipt): Promise<Failure> {
        if (!this.#username || this.#username === receipt.toAlias) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.depositReceipt(receipt))) return failure(ErrorStrings.ProcessFailed);
        return { reason: null };
    }

    private async GetAllReceipts({ toAlias, sessionId }: SessionIdentifier): Promise<Receipt[] | Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        return (await this.#mongoHandler.getAllReceipts(toAlias, sessionId)) || failure(ErrorStrings.ProcessFailed);
    }

    private async ClearAllReceipts({ toAlias, sessionId }: SessionIdentifier): Promise<Failure> {
        if (!this.#username) return failure(ErrorStrings.InvalidRequest);
        if (!(await this.#mongoHandler.clearAllReceipts(toAlias, sessionId))) return failure(ErrorStrings.ProcessFailed);
        return { reason: null };
    }

    private async requestRoom(username: string): Promise<Failure> {
        if (!this.#username || this.#username === username) return failure(ErrorStrings.InvalidRequest);
        const response: Failure = await this.request(SocketServerSideEvents.RoomRequested, { username }, 2000);
        if (!response?.reason) {
            this.#openToRoomTemp = { username };
            setTimeout(() => { this.#openToRoomTemp = null; }, 5000);
        }
        return response;
    }

    private async establishRoom(username: string, halfRoom: (roomUser2: RoomUser) => Promise<() => void>): Promise<(() => void)> 
    {
        if (!this.#openToRoomTemp || this.#openToRoomTemp.username !== username) return null;
        return halfRoom([this.#username, this.#socket, this.#sessionCrypto]).then((dispose) => {
            if (dispose) {
                this.#disposeRooms.push(dispose);
            }
            return dispose;
        });
    }

    private async notifyMessage(notify: Notify) {
        if (notify.type === "Request") {
            await this.request(SocketServerSideEvents.ChatRequestReceived, []);
        }
        else if (notify.type === "Message") {
            await this.request(SocketServerSideEvents.MessageReceived, _.pick(notify, "sessionId"));
        }
        else {
            await this.request(SocketServerSideEvents.ReceiptReceived, _.pick(notify, "sessionId"));
        }
    }

    private dispose() {
        this.deregisterSocket();
        this.#mongoHandler.unsubscribe();
        SocketHandler.onlineUsers.delete(this.#username);
        this.deleteSelf();
        this.#sessionCrypto = null;
        this.#username = null;
        this.#mongoHandler = null;
    }
}