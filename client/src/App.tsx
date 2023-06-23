import React, { useState, useEffect, useReducer, useRef } from "react";
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
import AuthClient from "./AuthClient";

export type SubmitResponse = {
  displayName?: string;
  username: string;
  password: string;
  savePassword: boolean;
}

const generateAvatar = createAvatarGenerator(200, 200);
const jsHash = calculateJsHash();
window.setInterval(async () => {
  const hash = await jsHash;
  const latestHash = await fetch("./prvJsHash.txt").then((response) => response.text());
  if (hash !== latestHash) {
    console.log("js file changed.");
    window.history.go(); 
  }
}, 10000);

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
  const [logInData, logInDispatch] = useReducer(defaultLogInDataReducer, { ...defaultLogInData, userLoginPermitted, submit: logIn });
  const [signUpData, signUpDispatch] = useReducer(defaultSignUpDataReducer, { ...defaultSignUpData, usernameExists, submit: signUp });
  const [loaded, setLoaded] = useState(false);
  const [signedIn, setSignedIn] = useState(false);
  const [currentTab, setCurrentTab] = useState(0);
  const [visualHeight, setVisualHeight] = useState(window.visualViewport.height);
  const clientRef = useRef<Client>(null);

  useEffect(() => {
    const updateHeight = () => setVisualHeight(window.visualViewport.height - (navigator as any).virtualKeyboard.boundingRect.height);
    window.addEventListener("beforeunload", (e) => {
      e.preventDefault();
      AuthClient.terminateCurrentSession();
      return false;
    }, { capture: true, once: true });
    window.visualViewport.addEventListener("resize", updateHeight);
    logInSaved().then(() => setLoaded(true));
    return () => {
      window.visualViewport.removeEventListener("resize", updateHeight);
    }
  }, []);

  function usernameExists(username: string) {
    return AuthClient.userExists(username);
  }

  function userLoginPermitted(username: string) {
    return AuthClient.userLogInPermitted(username);
  }

  async function signUp({ displayName, username, password, savePassword }: SubmitResponse) {
    const profilePicture = generateAvatar(displayName, username);
    displayName ||= username;
    const clientResult = await AuthClient.signUp({ username, displayName, profilePicture, description: "Hey there! I am using ChatApp." }, password, savePassword);
    if ("reason" in clientResult) return clientResult;
    clientRef.current = clientResult;
    setSignedIn(true);
    return { reason: null };
  }

  async function logIn({ username, password, savePassword }: SubmitResponse) {
    const clientResult = await AuthClient.logIn(username, password, savePassword);
    if ("reason" in clientResult) return clientResult;
    clientRef.current = clientResult;
    setSignedIn(true);
    return { reason: null };
  }

  async function logInSaved() {
    const clientResult = await AuthClient.logInSaved();
    if ("reason" in clientResult) return clientResult;
    clientRef.current = clientResult;
    setSignedIn(true);
    return { reason: null };
  }

  return (
    <Container maxWidth={false} disableGutters={true} sx={{ position: "relative", top: 0, height: `${visualHeight}px`, width: belowXL ? "90vw" : "100vw", overflow: "clip", display: "flex", flexDirection: "column"}}>
      {!loaded &&
        <React.Fragment>
          <Spacer units={2} />
          <div style={{ display: "flex", justifyContent: "center" }}>
            <CircularProgress size="lg" variant="soft" />
          </div>
        </React.Fragment>}
      {loaded && !signedIn &&
        <LogInContext.Provider value={{ logInData, logInDispatch }}>
          <SignUpContext.Provider value={{ signUpData, signUpDispatch }}>
            <LogInSignUp currentTab={currentTab} setCurrentTab={setCurrentTab} />
          </SignUpContext.Provider>
        </LogInContext.Provider>
      }
      {loaded && signedIn &&
        <Main client={clientRef.current}/>
      }
    </Container>);
}