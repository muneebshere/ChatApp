import React, { useState, useEffect, useReducer, useCallback } from "react";
import { createRoot } from "react-dom/client";
import { useEffectOnce, useEventListener } from "usehooks-ts";
import { Container, CircularProgress } from "@mui/joy";
import { CssVarsProvider } from "@mui/joy/styles";
import { Theme, useMediaQuery } from "@mui/material";
import LogInSignUp from "./components/LogInSignUp";
import Main from "./components/Main";
import { LogInContext, defaultLogInDataReducer, defaultLogInData, logInAction } from "./components/Login";
import { SignUpContext, defaultSignUpDataReducer, defaultSignUpData, signUpAction } from "./components/Signup";
import { Spacer } from "./components/CommonElementStyles";
import { ClientEvent, Client } from "./client";
import { match } from "ts-pattern";

export type SubmitResponse = {
  displayName?: string;
  username: string;
  password: string;
  savePassword: boolean;
}

const PORT = 8080;
const { hostname, protocol } = window.location;
const client = new Client(`${protocol}//${hostname}:${PORT}`);
client.establishSession();

createRoot(document.getElementById("root")).render(<Root/>);

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
    client.subscribeStatusChange(notifyStatus);
    window.addEventListener("beforeunload", terminate, { capture: true, once: true });
    return () => {
      window.removeEventListener("beforeunload", terminate);
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
    displayName ||= username;
    return client.signUp({ username, displayName, profilePicture: "", description: "" }, password, savePassword);
  }

  return (
    <Container maxWidth={false} disableGutters={true} sx={{ height: `${visualHeight}px`, width: belowXL ? "90vw" : "100vw", overflow: "clip", display: "flex", flexDirection: "column" }}>
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