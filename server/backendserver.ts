import _ from "lodash";
import { DateTime } from "luxon";
import { config } from "./node_modules/dotenv";
import { ServerOptions, createServer } from "node:https";
import fs, { promises as fsPromises } from "node:fs";
import cookieParser from "cookie-parser";
import express, { Request, Response, NextFunction, CookieOptions } from "express";
import cors, { CorsOptions } from "cors";
import * as ipaddr from "ipaddr.js";
import { Server as SocketServer, Socket } from "socket.io";
import * as crypto from "../shared/cryptoOperator";
import { serialize, deserialize } from "../shared/cryptoOperator";
import { SignUpRequest, SignUpChallengeResponse, LogInRequest, LogInChallengeResponse, LogInSavedRequest, SavePasswordRequest } from "../shared/commonTypes";
import { fromBase64, logError, randomFunctions } from "../shared/commonFunctions";
import { MongoHandlerCentral } from "./MongoHandler";
import AuthHandler from "./AuthHandler";
import SocketHandler from "./SocketHandler";

declare module "http" {
    interface IncomingMessage {
        cookies: any;
        signedCookies: any;
    }
}

function parseIpRepresentation(address: string) {
    if (!ipaddr.isValid(address)) return null;
    const ipv4_or_ipv6 = ipaddr.parse(address);
    const ipv6 =
        "octets" in ipv4_or_ipv6
            ? ipv4_or_ipv6.toIPv4MappedAddress()
            : ipv4_or_ipv6;
    return Buffer.from(ipv6.toByteArray()).toString("base64");
}

export function parseIpReadable(ipRep: string) {
    const ipv6 = new ipaddr.IPv6(Array.from(Buffer.from(ipRep, "base64")));
    return ipv6.isIPv4MappedAddress()
        ? ipv6.toIPv4Address().toString()
        : ipv6.toRFC5952String();
}

async function writeJsHash() {
    const file = await fsPromises.readFile(`..\\client\\public\\main.js`, { flag: "r" });
    const hash = await crypto.digestToBase64("SHA-256", file);
    await fsPromises.writeFile(`..\\client\\public\\prvJsHash.txt`, hash);
}

async function watchForJsHashChange() {
    const watcher = fsPromises.watch(`..\\client\\public\\main.js`);
    for await (const { eventType } of watcher) {
        if (eventType === "change") {
            await writeJsHash();
        }
    }
}

async function main() {
    
    const PORT = 8080;
    const mongoUrl = "mongodb://localhost:27017/chatapp";
    const httpsOptions: ServerOptions = {
        key: fs.readFileSync(`..\\certificates\\key.pem`),
        cert: fs.readFileSync(`..\\certificates\\cert.pem`)
    }
    const corsOptions: CorsOptions = { origin: /.*/, methods: ["GET", "POST"], exposedHeaders: ["set-cookie"], allowedHeaders: ["content-type"], credentials: true };
    const { getRandomString, getRandomVector } = randomFunctions();

    try {
        config({ debug: true, path: "./config.env" });
    }
    catch (e) {
        logError(e);
        console.log("Could not load config.env");
    }

    await writeJsHash(); 
    watchForJsHashChange();
    MongoHandlerCentral.connect(mongoUrl);
    const { signingKey, verifyingKey, cookieSign } = await MongoHandlerCentral.setupIdentity();
    const authHandler = AuthHandler.initiate(signingKey, verifyingKey);
    const cookieParserMiddle = cookieParser(cookieSign);
    const cookieOptions: CookieOptions = { httpOnly: true, secure: true, sameSite: "strict", signed: true };
    const app = express().use(cors(corsOptions)).use(cookieParserMiddle).use(express.json());
    const httpsServer = createServer(httpsOptions, app);
    
    
    const io = new SocketServer(httpsServer, {
        cors: {
            origin: /.*/,
            methods: ["GET", "POST"],
            credentials: true
        }
    });

    app.get("/userLogInPermitted", async (req, res) => {
        const ipRep = parseIpRepresentation(req.socket.remoteAddress);
        const { payload } = req.body;
        if (!ipRep || payload !== "string") return res.status(400).end();
        const { username } = deserialize(fromBase64(payload));
        const result = await authHandler.userLoginPermitted(username, ipRep);
        return res.json({ payload: serialize(result).toString("base64") }).status(200).end();
    })
    
    app.get("/initiateSignUp", async (req, res) => {
        const ipRep = parseIpRepresentation(req.socket.remoteAddress);
        const { payload } = req.body;
        if (!ipRep || payload !== "string") return res.status(400).end();
        const request: SignUpRequest = deserialize(fromBase64(payload));
        const challengeReference = getRandomString(16, "base64");
        const result = await authHandler.initiateSignUp(ipRep, challengeReference, request);
        res.json({ payload: serialize(result).toString("base64") });
        if (!("reason" in result)) {
            res.cookie("signUpInit", { challengeReference }, { ...cookieOptions, maxAge: 5000 });
        }
        return res.status(200).end();
    });
    
    app.connect("/concludeSignUp", async (req, res) => {
        const ipRep = parseIpRepresentation(req.socket.remoteAddress);
        const { challengeReference } = req.signedCookies?.signUpInit || {};
        res.clearCookie("signUpInit");
        const { payload } = req.body;
        if (!ipRep || payload !== "string") return res.status(400).end();
        const request: SignUpChallengeResponse= deserialize(fromBase64(payload));
        const sessionReference = getRandomString(16, "base64");
        const result = await authHandler.concludeSignUp(ipRep, challengeReference, sessionReference, request);
        res.json({ payload: serialize(result).toString("base64") });
        if (!("reason" in result)) {
            res.cookie("authenticated", { sessionReference }, cookieOptions);
        }
        return res.status(200).end();
    });
    
    app.get("/initiateLogIn", async (req, res) => {
        const ipRep = parseIpRepresentation(req.socket.remoteAddress);
        const { payload } = req.body;
        if (!ipRep || payload !== "string") return res.status(400).end();
        const request: LogInRequest = deserialize(fromBase64(payload));
        const challengeReference = getRandomString(16, "base64");
        const result = await authHandler.initiateLogIn(ipRep, challengeReference, request);
        res.json({ payload: serialize(result).toString("base64") });
        if (!("reason" in result)) {
            res.cookie("logInInit", { challengeReference }, { ...cookieOptions, maxAge: 5000 });
        }
        return res.status(200).end();
    });
    
    app.connect("/concludeLogIn", async (req, res) => {
        const ipRep = parseIpRepresentation(req.socket.remoteAddress);
        const { challengeReference } = req.signedCookies?.logInInit || {};
        res.clearCookie("logInInit");
        const { payload } = req.body;
        if (!ipRep || payload !== "string") return res.status(400).end();
        const request: LogInChallengeResponse= deserialize(fromBase64(payload));
        const sessionReference = getRandomString(16, "base64");
        const result = await authHandler.concludeLogIn(ipRep, challengeReference, sessionReference, request);
        res.json({ payload: serialize(result).toString("base64") });
        if (!("reason" in result)) {
            res.cookie("authenticated", { sessionReference }, cookieOptions);
        }
        return res.status(200).end();
    });
    
    app.get("/initiateLogInSaved", async (req, res) => {
        const ipRep = parseIpRepresentation(req.socket.remoteAddress);
        const { saveToken } = req.signedCookies?.passwordSaved || {};
        const { payload } = req.body;
        if (!ipRep || payload !== "string") return res.status(400).end();
        const request: LogInSavedRequest = deserialize(fromBase64(payload));
        const challengeReference = getRandomString(16, "base64");
        const result = await authHandler.InitiateLogInSaved(ipRep, saveToken, request)
        res.json({ payload: serialize("reason" in result ? result : _.pick(result, "authKeyBits")).toString("base64") });
        if (!("reason" in result)) {
            const { username } = result;
            res.cookie("logInSavedInit", { username }, { ...cookieOptions, maxAge: 5000 });
        }
        return res.status(200).end();
    });
    
    app.connect("/concludeLogInSaved", async (req, res) => {
        const ipRep = parseIpRepresentation(req.socket.remoteAddress);
        const { username } = req.signedCookies?.logInSavedInit || {};
        res.clearCookie("logInSavedInit");
        const { payload } = req.body;
        if (!ipRep || payload !== "string") return res.status(400).end();
        const request: LogInChallengeResponse= deserialize(fromBase64(payload));
        const sessionReference = getRandomString(16, "base64");
        const result = await authHandler.concludeLogInSaved(ipRep, sessionReference, { ...request, username });
        res.json({ payload: serialize(result).toString("base64") });
        if (!("reason" in result)) {
            res.cookie("authenticated", { sessionReference }, cookieOptions);
        }
        return res.status(200).end();
    });
    
    app.post("/savePassword", async (req, res) => {
        const ipRep = parseIpRepresentation(req.socket.remoteAddress);
        const { sessionReference } = req.signedCookies?.authenticated || {};
        const { payload } = req.body || {};
        if (!ipRep || payload !== "string") return res.status(400).end();
        const request: SavePasswordRequest = crypto.deserialize(fromBase64(payload));
        const username = SocketHandler.getUsername(sessionReference);
        const saveToken = getRandomString(16, "base64");
        const result = await authHandler.savePassword(username, ipRep, saveToken, request);
        res.json({ payload: serialize(result).toString("base64") });
        if (!("reason" in result)) {
            res.cookie("passwordSaved", { saveToken }, { ...cookieOptions, maxAge: 10 * 24 * 60 * 60 * 1000, expires: DateTime.now().plus({ days: 10 }).toJSDate() });
        }
        return res.status(200).end();
    });
    
    app.get("/authNonce", async (req, res) => {
        const ipRep = parseIpRepresentation(req.socket.remoteAddress);
        const { sessionReference } = req.signedCookies?.authenticated || {};
        if (!ipRep || !sessionReference) return res.status(400).end();
        const nonce = getRandomVector(64).toString("base64");
        const payload = Buffer.concat([fromBase64(ipRep), fromBase64(sessionReference), fromBase64(nonce)]).toString("base64");
        res.json({ payload });
        res.cookie("authNonce", { nonce }, { ...cookieOptions, maxAge: 5000 });
        return res.status(200).end();
    });
    
    io.use((socket: Socket, next) => {
        cookieParserMiddle(socket.request as Request, ((socket.request as any).res || {}) as Response, next as NextFunction)
    });

    io.on("connection", async (socket) => {
        try {
            const ipRep = parseIpRepresentation(socket.request.socket.remoteAddress);
            const { authenticated: { sessionReference }, authNonce: { nonce } } = socket.request.signedCookies;
            const { authToken } = socket.handshake.auth ?? {};
            const authData = Buffer.concat([fromBase64(ipRep), fromBase64(sessionReference), fromBase64(nonce)]).toString("base64");
            console.log(`Socket connected from ip ${parseIpReadable(ipRep)} with sessionReference ${sessionReference}.`);
            if (!(await SocketHandler.registerSocket(sessionReference, ipRep, authToken, authData, socket))) {
                socket.disconnect(true);
            }
        }
        catch (err) {
            socket.disconnect(true);
        }
    });

    httpsServer.listen(PORT, () => console.log(`listening on *:${PORT}`));
}

main();