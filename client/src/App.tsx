import React, { useState, useEffect, useReducer } from "react";
import { createRoot } from "react-dom/client";

import { Container, CircularProgress } from "@mui/joy";
import { CssVarsProvider } from "@mui/joy/styles";
import { Theme, useMediaQuery } from "@mui/material";
import LogInSignUp from "./components/LogInSignUp";
import Main from "./components/Main";
import { LogInContext, defaultLogInDataReducer, defaultLogInData, logInAction } from "./components/Login";
import { SignUpContext, defaultSignUpDataReducer, defaultSignUpData, signUpAction } from "./components/Signup";
import { Spacer } from "./components/CommonElementStyles";
import Client, { ClientEvent } from "./client";
import * as crypto from "../../shared/cryptoOperator";
import { match } from "ts-pattern";
import tinycolor from "tinycolor2";

export type SubmitResponse = {
  displayName?: string;
  username: string;
  password: string;
  savePassword: boolean;
}

const PORT = 8080;
const { hostname, protocol } = window.location;
const client = new Client(`${protocol}//${hostname}:${PORT}`);
const generateAvatar = createAvatarGenerator(200, 200);
const jsHash = calculateJsHash();
window.setInterval(async () => {
  const hash = await jsHash;
  const latestHash = await fetch("./prvJsHash.txt").then((response) => response.text());
  if (hash !== latestHash) {
    console.log("js file changed.");
    window.history.go(); 
  }
}, 1000);
client.establishSession();

if ("virtualKeyboard" in navigator) {
  (navigator.virtualKeyboard as any).overlaysContent = true;
}

createRoot(document.getElementById("root")).render(<Root/>);

async function calculateJsHash() {
  const response = await fetch("./main.js");
  const fileBuffer = await response.arrayBuffer();
  return crypto.digestToBase64("SHA-256", fileBuffer);
}

function createAvatarGenerator(width: number, height: number) {
  const canvasRef = getCanvas();

  function getCanvas(): [HTMLCanvasElement, CanvasRenderingContext2D] {
    const canvas = document.createElement("canvas");
    canvas.height = height;
    canvas.width = width;
    const ctx = canvas.getContext("2d");
    fillRect(ctx);
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fontKerning = "none";
    ctx.font = `100px "Fira Sans", sans-serif`;
    ctx.moveTo(width, height);
    return [canvas, ctx];
  }

  function fillRect(ctx: CanvasRenderingContext2D) {
    const theta = 2 * Math.PI * Math.random();
    const x1 = width * (0.5 - Math.cos(theta));
    const x2 = width * (0.5 + Math.cos(theta));
    const y1 = height * (0.5 - Math.sin(theta));
    const y2 = height * (0.5 + Math.sin(theta));
    const gradient = ctx.createLinearGradient(x1, y1, x2, y2);
    gradient.addColorStop(0, tinycolor.random().toHexString());
    gradient.addColorStop(1, tinycolor.random().toHexString());
    ctx.fillStyle = gradient;
    ctx.fillRect(0, 0, width, height);
  }

  return (displayName: string, username: string) => {
    const [canvas, ctx] = canvasRef;
    const initials = 
      (displayName
        ? displayName.split(" ").filter((s, i) => i < 2).map((s) => s[0]).join("")
        : username.substring(0, 2)).toUpperCase();
    ctx.fillStyle = "#ffffff"
    ctx.fillText(initials, width/2, height/2);
    return canvas.toDataURL();
  }
}

function Root() {
  return (
    <CssVarsProvider>
      <App />
    </CssVarsProvider>)
}

function App() {
  const belowXL = useMediaQuery((theme: Theme) => theme.breakpoints.down("xl"));
  const [logInData, logInDispatch] = useReducer(defaultLogInDataReducer, { ...defaultLogInData, usernameExists, userLoginPermitted, submit: logIn });
  const [signUpData, signUpDispatch] = useReducer(defaultSignUpDataReducer, { ...defaultSignUpData, usernameExists, submit: signUp });
  const [connected, setConnected] = useState(false);
  const [retrying, setRetrying] = useState(true);
  const [signedIn, setSignedIn] = useState(false);
  const [displayName, setDisplayName] = useState("");
  const [currentTab, setCurrentTab] = useState(0);
  const [visualHeight, setVisualHeight] = useState(window.visualViewport.height);

  const notifyStatus = (status: ClientEvent) => {
    match(status)
      .with(ClientEvent.Disconnected,
        ClientEvent.FailedToConnect, () => setConnected(false))
      .with(ClientEvent.Connecting,
        ClientEvent.Reconnecting, () => {
          setConnected(false);
          setRetrying(true);
        })
      .with(ClientEvent.Connected, () => {
        if (window.localStorage.getItem("SavedAuth")) {
          client.logInSaved().then(({ reason }) => {
            setConnected(true);
            if (!reason) {
              setSignedIn(true);
            }
          })
        }
        else setConnected(true);
      })
      .with(ClientEvent.SigningIn,
        ClientEvent.FailedSignIn,
        ClientEvent.ReAuthenticating,
        ClientEvent.FailedReAuthentication,
        ClientEvent.CreatingNewUser,
        ClientEvent.FailedCreateNewUser,
        ClientEvent.CreatedNewUser,
        ClientEvent.SigningOut, () => { })
      .with(ClientEvent.SignedIn,
        ClientEvent.CreatedNewUser, () => {
          setSignedIn(true);
          setDisplayName(client.profile.displayName);
        })
      .with(ClientEvent.SignedOut, () => {
        setSignedIn(false);
        setDisplayName("");
      })
      .with(ClientEvent.ServerUnavailable, () => {
        setConnected(false);
        setRetrying(false);
      })
      .otherwise(() => { });
  }

  useEffect(() => {
    const terminate = () => client.terminateCurrentSession();
    const updateHeight = () => setVisualHeight(window.visualViewport.height - (navigator as any).virtualKeyboard.boundingRect.height);
    client.subscribeStatusChange(notifyStatus);
    window.addEventListener("beforeunload", terminate, { capture: true, once: true });
    window.visualViewport.addEventListener("resize", updateHeight);
    return () => {
      window.removeEventListener("beforeunload", terminate);
      window.visualViewport.removeEventListener("resize", updateHeight);
    }
  }, []);

  useEffect(() => {
    if (!connected && !signedIn) {
      logInDispatch(logInAction("submitted", false));
      signUpDispatch(signUpAction("submitted", false));
    }
  }, [connected]);

  function usernameExists(username: string) {
    return client.checkUsernameExists(username);
  }

  function userLoginPermitted(username: string) {
    return client.userLogInPermitted(username);
  }

  function logIn({ username, password, savePassword }: SubmitResponse) {
    return client.logIn(username, password, savePassword);
  }

  function signUp({ displayName, username, password, savePassword }: SubmitResponse) {
    const profilePicture = generateAvatar(displayName, username);
    displayName ||= username;
    return client.signUp({ username, displayName, profilePicture, description: "Hey there! I am using ChatApp." }, password, savePassword);
  }

  return (
    <Container maxWidth={false} disableGutters={true} sx={{ position: "relative", top: 0, height: `${visualHeight}px`, width: belowXL ? "90vw" : "100vw", overflow: "clip", display: "flex", flexDirection: "column"}}>
      {(!connected && !signedIn) &&
        <React.Fragment>
          <Spacer units={2} />
          <div style={{ display: "flex", justifyContent: "center" }}>
            <CircularProgress size="lg" variant="soft" />
          </div>
        </React.Fragment>}
      {connected && !signedIn &&
        <LogInContext.Provider value={{ logInData, logInDispatch }}>
          <SignUpContext.Provider value={{ signUpData, signUpDispatch }}>
            <LogInSignUp currentTab={currentTab} setCurrentTab={setCurrentTab} />
          </SignUpContext.Provider>
        </LogInContext.Provider>
      }
      {signedIn &&
        <Main client={client} connected={connected} retrying={retrying} displayName={displayName} />
      }
    </Container>);
}