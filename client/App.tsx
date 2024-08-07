import React, { useState, useEffect, useReducer, useCallback } from "react";
import { createRoot } from "react-dom/client";
import { Container, CircularProgress } from "@mui/joy";
import { CssVarsProvider } from "@mui/joy/styles";
import { Theme, useMediaQuery } from "@mui/material";
import LogInSignUp from "./components/LogInSignUp";
import Main from "./components/Main";
import { LogInContext, defaultLogInDataReducer, defaultLogInData } from "./components/Login";
import { SignUpContext, defaultSignUpDataReducer, defaultSignUpData } from "./components/Signup";
import Client, { ConnectionStatus } from "./Client";
import { generateAvatar, extractInitials } from "./imageUtilities";
import * as crypto from "../shared/cryptoOperator";
import AuthClient, { AuthConnectionStatus } from "./AuthClient";
import { Failure } from "../shared/commonTypes";
import { logError } from "../shared/commonFunctions";

export type SubmitResponse = {
  displayName?: string;
  username: string;
  password: string;
  savePassword: boolean;
}

const loaded = (status: ConnectionStatus): status is Exclude<ConnectionStatus, "NotLoaded"> => status !== "NotLoaded"
const loggedIn = (status: ConnectionStatus): status is Exclude<ConnectionStatus, "NotLoggedIn"> => status !== "NotLoggedIn";
const loggingOut = (status: ConnectionStatus): status is "LoggingOut" => status === "LoggingOut";

if ("virtualKeyboard" in navigator) {
  (navigator.virtualKeyboard as any).overlaysContent = true;
}

window.onerror = function(message, url, line, col, error) {
  logError({ message, url, line, col, error });
};

createRoot(document.getElementById("root")!).render(<Root/>);
setupJsHashChecker();

async function setupJsHashChecker() {
  const response = await fetch("/files/main.js");
  const currentJsHash = await crypto.digestToBase64("SHA-256", await response.arrayBuffer());
  let changed = false;
  let interval: number | null = null;
  setInterval();

  function setInterval(cancelled = false) {
    interval = window.setInterval(check, cancelled ? 30000 : 2000);
  }

  async function check() {
    if (!changed) {
      const latestJsHash = await AuthClient.latestJsHash();
      changed = !!latestJsHash && latestJsHash !== currentJsHash;
    }
    if (changed) {
      console.log("js file changed.");
      window.clearInterval(interval!);
      if (window.confirm("Js script file out of date. Reload?")) window.history.go();
      else setInterval(true);
    }
  }

}

function Root() {
  return (
    <CssVarsProvider>
      <App />
    </CssVarsProvider>)
}

let client: Client;

function App() {
  const belowXL = useMediaQuery((theme: Theme) => theme.breakpoints.down("xl"));
  const [logInData, logInDispatch] = useReducer(defaultLogInDataReducer, { ...defaultLogInData, userLoginPermitted, submit: logIn });
  const [signUpData, signUpDispatch] = useReducer(defaultSignUpDataReducer, { ...defaultSignUpData, usernameExists, submit: signUp });
  const [status, setStatus] = useState<ConnectionStatus>("NotLoaded");
  const [connectionStatus, setConnectionStatus] = useState<AuthConnectionStatus>("Online");
  const [currentTab, setCurrentTab] = useState<0 | 1>(0);
  const [visualHeight, setVisualHeight] = useState(window.visualViewport!.height);
  const [currentChatWith, setCurrentChatWith] = useState("");
  const updateStatus = () => Client.connectionStatus().then((status) => setStatus(status));
  const updateConnectionStatus = useCallback((currentConnectionStatus: AuthConnectionStatus) => {
    if (currentConnectionStatus !== connectionStatus) {
      setConnectionStatus(currentConnectionStatus);
      updateStatus();
    }
  },[connectionStatus])

  useEffect(() => {
    const updateHeight = () => setVisualHeight(window.visualViewport!.height - (navigator as any).virtualKeyboard.boundingRect.height);
    const onContextMenu = (e: Event) => {
      e.preventDefault();
      return false;
    }
    document.body.addEventListener("contextmenu", onContextMenu, { capture: true });
    window.addEventListener("online", updateStatus);
    window.addEventListener("offline", updateStatus);
    window.addEventListener("beforeunload", (e) => AuthClient.terminateCurrentSession(), { capture: true, once: true });
    window.visualViewport!.addEventListener("resize", updateHeight);
    AuthClient.subscribeConnectionStatus(updateConnectionStatus);
    initiate();
    return () => {
      document.body.removeEventListener("contextmenu", onContextMenu, { capture: true });
      window.removeEventListener("online", updateStatus);
      window.removeEventListener("offline", updateStatus);
      window.visualViewport!.removeEventListener("resize", updateHeight);
      AuthClient.subscribeConnectionStatus(null);
    }
  }, []);

  function usernameExists(username: string) {
    return AuthClient.userExists(username);
  }

  function userLoginPermitted(username: string) {
    return AuthClient.userLogInPermitted(username);
  }

  function clientResult(result: Client | Failure): Failure {
    if ("reason" in result) {
      setStatus("NotLoggedIn");
      return result;
    }
    client = result;
    client.subscribeStatus(setStatus);
    return { reason: false };
  }

  async function signUp({ displayName, username, password, savePassword }: SubmitResponse): Promise<Failure> {
    const initials = extractInitials(displayName, username);
    const profilePicture = generateAvatar({ initials });
    displayName ||= `@${username}`;
    return clientResult(await AuthClient.signUp({ username, displayName, profilePicture, description: "Hey there! I am using ChatApp." }, password, savePassword));
  }

  async function logIn({ username, password, savePassword }: SubmitResponse): Promise<Failure> {
    return clientResult(await AuthClient.logIn(username, password, savePassword));
  }

  async function initiate(): Promise<Failure> {
    let result = await AuthClient.resumeAuthenticatedSession();
    if ("reason" in result) {
      result = await AuthClient.logInSaved();
    }
    return clientResult(result);
  }

  return (
    <Container maxWidth={false} disableGutters={true} sx={{ position: "relative", top: 0, height: `${visualHeight}px`, width: belowXL ? "90vw" : "100vw", overflow: "clip", display: "flex", flexDirection: "column"}}>
      {(!loaded(status) || loggingOut(status)) &&
          <div style={{ display: "flex", justifyContent: "center", marginTop: "48px" }}>
            <CircularProgress size="lg" variant="soft" color="success"/>
          </div>}
      {!loggedIn(status) && !loggingOut(status) &&
        <LogInContext.Provider value={{ logInData, logInDispatch }}>
          <SignUpContext.Provider value={{ signUpData, signUpDispatch }}>
            <LogInSignUp connectionStatus={connectionStatus} currentTab={currentTab} setCurrentTab={setCurrentTab} />
          </SignUpContext.Provider>
        </LogInContext.Provider>
      }
      {loaded(status) && loggedIn(status) && !loggingOut(status) &&
        <Main client={client} status={status} currentChatWith={currentChatWith} setCurrentChatWith={setCurrentChatWith}/>
      }
    </Container>);
}