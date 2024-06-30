import _ from "lodash";
import { DateTime } from "luxon";
import { ServerOptions, createServer as createHTTPSServer } from "node:https";
import fs, { promises as fsPromises } from "node:fs";
import { Buffer } from "node:buffer";
import cookieParser from "cookie-parser";
import express, { Request, Response, NextFunction, CookieOptions } from "express";
import cors, { CorsOptions } from "cors";
import * as ipaddr from "ipaddr.js";
import { Server as SocketServer, Socket } from "socket.io";
import * as crypto from "../shared/cryptoOperator";
import { serialize, deserialize } from "../shared/cryptoOperator";
import { SignUpRequest, SignUpChallengeResponse, LogInRequest, LogInChallengeResponse, LogInSavedRequest, SavePasswordRequest } from "../shared/commonTypes";
import { fromBase64, logError, randomFunctions } from "../shared/commonFunctions";
import MongoHandlerCentral, { ServerConfig } from "./MongoHandler";
import AuthHandler from "./AuthHandler";
import SocketHandler from "./SocketHandler";
import path from "node:path";

declare module "http" {
    interface IncomingMessage {
        cookies: any;
        signedCookies: any;
    }
}
const { getRandomString, getRandomVector } = randomFunctions();
let latestJsHash: string;

function parseIpRepresentation(address: string | undefined) {
    if (!address) return null;
    if (!ipaddr.isValid(address)) return null;
    const ipv4_or_ipv6 = ipaddr.parse(address);
    const ipv6 =
        "octets" in ipv4_or_ipv6
            ? ipv4_or_ipv6.toIPv4MappedAddress()
            : ipv4_or_ipv6;
    return Buffer.from(ipv6.toByteArray()).toString("base64");
}

async function calculateNonce(ipRep: string, sessionReference: string, nonce: string): Promise<{ nonce: string, authNonce: string }> {
    const nonceVector = nonce ? fromBase64(nonce) : getRandomVector(64);
    nonce ||= nonceVector.toString("base64");
    const authNonce = await crypto.digestToBase64("SHA-256",Buffer.concat([fromBase64(ipRep), fromBase64(sessionReference), nonceVector]));
    return { authNonce, nonce };
}

export function parseIpReadable(ipRep: string) {
    const ipv6 = new ipaddr.IPv6(Array.from(Buffer.from(ipRep, "base64")));
    return ipv6.isIPv4MappedAddress()
        ? ipv6.toIPv4Address().toString()
        : ipv6.toRFC5952String();
}

async function writeJsHash() {
    const file = await fsPromises.readFile(path.resolve(`../public/main.js`), { flag: "r" });
    latestJsHash = await crypto.digestToBase64("SHA-256", file);
}

async function watchForJsHashChange() {
    await writeJsHash();
    const watcher = fsPromises.watch(path.resolve(`../public/main.js`));
    for await (const { eventType } of watcher) {
        if (eventType === "change") {
            await writeJsHash();
        }
    }
}

export const defaultServerConfig: ServerConfig = {
    minOneTimeKeys: 50,
    maxOneTimeKeys: 50,
    replaceKeyAtMillis: 1000 * 60
}

async function main() {

    const PORT = 443;
    const mongoUrl = "mongodb://localhost:27017/chatapp";
    const httpsOptions: ServerOptions = {
        key: fs.readFileSync(path.resolve(`../certificates/key.pem`)),
        cert: fs.readFileSync(path.resolve(`../certificates/cert.pem`))
    }
    const corsOptions: CorsOptions = { origin: /.*/, methods: ["GET", "POST", "DELETE"], exposedHeaders: ["set-cookie"], allowedHeaders: ["content-type"], credentials: true };

    watchForJsHashChange();
    MongoHandlerCentral.connect(mongoUrl);
    const { signingKey, verifyingKey, cookieSign, serverConfig } = await MongoHandlerCentral.setupServer();
    SocketHandler.serverConfig = serverConfig;
    const authHandler = AuthHandler.initiate(signingKey, verifyingKey);
    const cookieParserMiddle = cookieParser(cookieSign);
    const cookieOptions: CookieOptions = { httpOnly: true, secure: true, sameSite: "strict", signed: true };
    const app = express()
                    .use("/files", express.static(path.resolve("../public")))
                    .use(cors(corsOptions))
                    .use(cookieParserMiddle)
                    .use(express.json());
    const backendServer = createHTTPSServer(httpsOptions, app);
    const interruptedAuthentications = new Map<string, NodeJS.Timeout>();
    const saveSessionKeys = new Map<string, string>();
    const disposeSession = async (sessionReference: string, reason: string) => {
        await SocketHandler.disposeSession(sessionReference, reason);
        saveSessionKeys.delete(sessionReference);
    }

    const io = new SocketServer(backendServer, {
        cors: {
            origin: /.*/,
            methods: ["GET", "POST"],
            credentials: true
        }
    });

    app.get("/isServerActive", async (req, res) => {
        return res.status(200).end();
    });

    app.get("/latestJsHash", async (req, res) => {
        return res.json({ latestJsHash });
    });

    app.get("/userLogInPermitted/:username", async (req, res) => {
        const ipRep = parseIpRepresentation(req.socket.remoteAddress);
        if (!ipRep) return res.status(400).end();
        const { login } = await authHandler.userLoginPermitted(req.params.username, ipRep);
        return res.json({ login });
    });

    app.get("/userExists/:username", async (req, res) => {
        const { exists } = await authHandler.userExists(req.params.username);
        return res.json({ exists });
    });

    app.post("/initiateSignUp", async (req, res) => {
        const ipRep = parseIpRepresentation(req.socket.remoteAddress);
        const { payload } = req.body;
        if (!ipRep || typeof payload !== "string") return res.status(400).end();
        const request: SignUpRequest = deserialize(fromBase64(payload));
        const challengeReference = getRandomString(16, "base64");
        const result = await authHandler.initiateSignUp(ipRep, challengeReference, request);
        if (!("reason" in result)) {
            res.cookie("signUpInit", { challengeReference }, { ...cookieOptions, maxAge: 5000 });
        }
        return res.json({ payload: serialize(result).toString("base64") });
    });

    app.post("/concludeSignUp", async (req, res) => {
        const ipRep = parseIpRepresentation(req.socket.remoteAddress);
        const { challengeReference } = req.signedCookies?.signUpInit || {};
        res.clearCookie("signUpInit");
        const { payload } = req.body;
        if (!ipRep || typeof payload !== "string") return res.status(400).end();
        const request: SignUpChallengeResponse= deserialize(fromBase64(payload));
        const sessionReference = getRandomString(16, "base64");
        const result = await authHandler.concludeSignUp(ipRep, challengeReference, sessionReference, request);
        if (!("reason" in result)) {
            saveSessionKeys.set(sessionReference, result.saveSessionKey.toString("base64"));
            res.cookie("authenticated", { sessionReference, sessionIp: ipRep }, cookieOptions);
        }
        return res.json({ payload: serialize(result).toString("base64") });
    });

    app.post("/initiateLogIn", async (req, res) => {
        const ipRep = parseIpRepresentation(req.socket.remoteAddress);
        const { payload } = req.body;
        if (!ipRep || typeof payload !== "string") return res.status(400).end();
        const request: LogInRequest = deserialize(fromBase64(payload));
        const challengeReference = getRandomString(16, "base64");
        const result = await authHandler.initiateLogIn(ipRep, challengeReference, request);
        if (!("reason" in result)) {
            res.cookie("logInInit", { challengeReference }, { ...cookieOptions, maxAge: 5000 });
        }
        return res.json({ payload: serialize(result).toString("base64") }).status(200).end();
    });

    app.post("/concludeLogIn", async (req, res) => {
        const ipRep = parseIpRepresentation(req.socket.remoteAddress);
        const { challengeReference } = req.signedCookies?.logInInit || {};
        const { sessionReference: prevSession } = req.signedCookies?.authenticated || {};
        res.clearCookie("logInInit");
        const { payload } = req.body;
        if (!ipRep || typeof payload !== "string") return res.status(400).end();
        const request: LogInChallengeResponse= deserialize(fromBase64(payload));
        const sessionReference = getRandomString(16, "base64");
        const dispose = async () => disposeSession(prevSession, "Logging in again from the same device");
        const result = await authHandler.concludeLogIn(ipRep, prevSession, challengeReference, sessionReference, dispose, request);
        if (!("reason" in result)) {
            saveSessionKeys.set(sessionReference, result.saveSessionKey.toString("base64"));
            if (prevSession) res.clearCookie("authenticated");
            res.cookie("authenticated", { sessionReference, sessionIp: ipRep }, cookieOptions);
        }
        return res.json({ payload: serialize(result).toString("base64") });
    });

    app.post("/initiateLogInSaved", async (req, res) => {
        const ipRep = parseIpRepresentation(req.socket.remoteAddress);
        const { saveToken } = req.signedCookies?.passwordSaved || {};
        const { payload } = req.body;
        if (!ipRep || typeof payload !== "string") return res.status(400).end();
        const request: LogInSavedRequest = deserialize(fromBase64(payload));
        const result = await authHandler.InitiateLogInSaved(ipRep, saveToken, request);
        if (!("reason" in result)) {
            const { username } = result;
            res.cookie("logInSavedInit", { username }, { ...cookieOptions, maxAge: 5000 });
        }
        return res.json({ payload: serialize("reason" in result ? result : _.pick(result, "authKeyBits")).toString("base64") });
    });

    app.post("/concludeLogInSaved", async (req, res) => {
        const ipRep = parseIpRepresentation(req.socket.remoteAddress);
        const { username } = req.signedCookies?.logInSavedInit || {};
        const { sessionReference: prevSession } = req.signedCookies?.authenticated || {};
        res.clearCookie("logInSavedInit");
        const { payload } = req.body;
        if (!ipRep || typeof payload !== "string") return res.status(400).end();
        const request: LogInChallengeResponse= deserialize(fromBase64(payload));
        const sessionReference = getRandomString(16, "base64");
        const dispose = async () => disposeSession(prevSession, "Logging in again from the same device");
        const result = await authHandler.concludeLogInSaved(ipRep, prevSession, sessionReference, dispose, { ...request, username });
        if (!("reason" in result)) {
            saveSessionKeys.set(sessionReference, result.saveSessionKey.toString("base64"));
            if (prevSession) res.clearCookie("authenticated");
            res.cookie("authenticated", { sessionReference, sessionIp: ipRep }, cookieOptions);
        }
        return res.json({ payload: serialize(result).toString("base64") });
    });

    app.post("/savePassword", async (req, res) => {
        const ipRep = parseIpRepresentation(req.socket.remoteAddress);
        const { sessionReference } = req.signedCookies?.authenticated || {};
        const { payload } = req.body || {};
        if (!ipRep || typeof payload !== "string") return res.status(400).end();
        const request: SavePasswordRequest = crypto.deserialize(fromBase64(payload));
        const username = SocketHandler.getUsername(sessionReference);
        if (!username) return res.status(400).end();
        const saveToken = getRandomString(16, "base64");
        const result = await authHandler.savePassword(username, ipRep, saveToken, request);
        if (!("reason" in result)) {
            res.cookie("passwordSaved", { saveToken }, { ...cookieOptions, maxAge: 10 * 24 * 60 * 60 * 1000, expires: DateTime.now().plus({ days: 10 }).toJSDate() });
        }
        return res.json({ payload: serialize(result).toString("base64") });
    });

    app.post("/userLogOut", async (req, res) => {
        const { sessionReference } = req.signedCookies?.authenticated || {};
        await disposeSession(sessionReference, "Logging out");
        return res.clearCookie("authenticated").clearCookie("savedPassword").status(200).end();
    });

    app.post("/terminateCurrentSession", async (req, res) => {
        const { sessionReference } = req.signedCookies?.authenticated || {};
        if (sessionReference) {
            interruptedAuthentications.set(sessionReference, setTimeout(() => {
                interruptedAuthentications.delete(sessionReference);
                disposeSession(sessionReference, "Session terminated");
            }, 5000));
        }
        return res.status(200).end();
    });

    app.get("/resumeAuthenticatedSession", async (req, res) => {
        const ipRep = parseIpRepresentation(req.socket.remoteAddress);
        const { sessionReference, sessionIp } = req.signedCookies?.authenticated || {};
        const timeout = interruptedAuthentications.get(sessionReference);
        clearTimeout(timeout);
        if (!timeout) return res.clearCookie("authenticated").json({ resumed: false });
        if (!ipRep || ipRep !== sessionIp) return res.status(400).end();
        interruptedAuthentications.delete(sessionReference);
        const saveSessionKeyBase64 = saveSessionKeys.get(sessionReference);
        return res.json({ resumed: true, saveSessionKeyBase64 });
    });

    app.get("/isPasswordSaved", async (req, res) => {
        const ipRep = parseIpRepresentation(req.socket.remoteAddress);
        if (!ipRep) return res.status(400).end();
        const { saveToken } = req.signedCookies?.passwordSaved || {};
        const passwordSaved =
            !(await MongoHandlerCentral.savedAuthExists(saveToken))
                ? false
                : (await MongoHandlerCentral.savedAuthExists(saveToken, ipRep)
                    ? "same-ip"
                    : "other-ip");
        if (saveToken && !passwordSaved) {
            res.clearCookie("passwordSaved");
        }
        return res.json({ passwordSaved });
    });

    app.get("/isAuthenticated", async (req, res) => {
        const ipRep = parseIpRepresentation(req.socket.remoteAddress);
        if (!ipRep) return res.status(400).end();
        const { sessionReference, sessionIp } = req.signedCookies?.authenticated || {};
        const authenticationExists = !!sessionReference && sessionIp === ipRep;
        const running = !!SocketHandler.getUsername(sessionReference);
        const authenticated = authenticationExists && (running || await MongoHandlerCentral.runningClientSessionExists(sessionReference));
        if (authenticationExists && !authenticated) {
            res.clearCookie("authenticated");
        }
        const crashed = authenticated ? !running: undefined;
        return res.json({ authenticated, crashed });
    });

    app.get("/authNonce", async (req, res) => {
        const ipRep = parseIpRepresentation(req.socket.remoteAddress);
        const { sessionReference, sessionIp } = req.signedCookies?.authenticated || {};
        if (!ipRep || !sessionReference || !sessionIp || sessionIp !== ipRep) return res.status(400).end();
        let { nonce: existingNonce, nonceId } = req.signedCookies?.authNonce || {};
        nonceId ||= getRandomString(10, "hex");
        console.log(`Issuing nonce id ${nonceId}`);
        const { nonce, authNonce } = await calculateNonce(ipRep, sessionReference, existingNonce);
        if (!existingNonce) res.cookie("authNonce", { nonceId, nonce, authNonce }, { ...cookieOptions, maxAge: 5000 });
        return res.json({ nonceId, authNonce });
    });

    app.get("/verifyAuthentication/:clientNonceId/:authToken/:sessionRecordKey", async (req, res) => {
        const ipRep = parseIpRepresentation(req.socket.remoteAddress);
        const { sessionReference, sessionIp } = req.signedCookies?.authenticated || {};
        if (!sessionReference) return res.clearCookie("authNonce").json({ verified: false });
        const { nonceId, nonce, authNonce: existingAuthNonce } = req.signedCookies?.authNonce || {};
        let { authToken, clientNonceId, sessionRecordKey } = req.params;
        if (nonceId !== clientNonceId) console.log(`Mismatch of nonceId ${nonceId} with client nonceId ${clientNonceId}`);
        if (!ipRep || !authToken || !clientNonceId || !nonceId || nonceId !== clientNonceId) return res.status(400).end();
        console.log(`Testing nonce id ${nonceId}`);
        authToken = Buffer.from(authToken, "hex").toString("base64");
        const { authNonce } = await calculateNonce(ipRep, sessionReference, nonce);
        const verified = (sessionIp === ipRep) && (await authHandler.restartCrashedSession(sessionReference, Buffer.from(sessionRecordKey, "hex")) && await SocketHandler.confirmUserSession(sessionReference, authToken, authNonce));
        console.log(`Verified authentication: ${verified} for authNonce: ${authNonce} against originalAuthNonce ${existingAuthNonce}`);
        return res.clearCookie("authNonce").json({ verified });
    });

    app.delete("/clearSavedPassword", async (req, res) => {
        const ipRep = parseIpRepresentation(req.socket.remoteAddress);
        if (!ipRep) return res.status(400).end();
        const { saveToken } = req.signedCookies?.passwordSaved || {};
        if (saveToken) {
            MongoHandlerCentral.clearSavedAuth(saveToken);
        }
        return res.clearCookie("passwordSaved").status(200).end();
    });

    app.delete("/clearNonce", async (req, res) => {
        const ipRep = parseIpRepresentation(req.socket.remoteAddress);
        if (!ipRep) return res.status(400).end();
        return res.clearCookie("authNonce").status(200).end();
    });

    app.get("/*", async (req, res) => {
       res.status(200).sendFile(path.resolve("../public/index.html"));
    });

    io.use((socket: Socket, next) => {
        cookieParserMiddle(socket.request as Request, ((socket.request as any).res || {}) as Response, next as NextFunction)
    });

    io.use(async (socket: Socket, next) => {
        try {
            const ipRep = parseIpRepresentation(socket.request.socket.remoteAddress);
            if (!ipRep) return next(new Error(("Could not parse ip.")));
            const { authenticated: { sessionReference }, authNonce: { nonceId, nonce } } = socket.request.signedCookies;
            const { nonceId: clientNonceId, authToken, sessionRecordKey } = socket.handshake.auth ?? {};
            if (nonceId !== clientNonceId) {
                console.log(`Mismatch of nonceId ${nonceId} with client nonceId ${clientNonceId}`);
                return next(new Error("Nonce mismatch."));
            }
            console.log(`Connecting on nonce id ${nonceId}`);
            const { authNonce } = await calculateNonce(ipRep, sessionReference, nonce);
            if (await authHandler.restartCrashedSession(sessionReference, fromBase64(sessionRecordKey))) {
                if (await SocketHandler.registerSocket(sessionReference, ipRep, authToken, authNonce, socket)) {
                    console.log(`Socket connected from ip ${parseIpReadable(ipRep)} with sessionReference ${sessionReference}.`);
                    return next();
                }
            }
            console.log(`Socket connection from ip ${parseIpReadable(ipRep)} with sessionReference ${sessionReference} rejected.`);
            return next(new Error(("Registering socket failed.")));
        }
        catch (err) {
            next(new Error(err?.toString()));
        }
    });

    backendServer.listen(PORT, () => console.log(`listening on *:${PORT}`));
}

process.on("uncaughtException", (err, origin) => logError({ err, origin }));
main();