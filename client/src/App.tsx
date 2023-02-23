import { SubmitResponse, Spacer } from "./components/Common";
import LogInSignUp from "./components/LogInSignUp";
import Main from "./components/Main";
import { LogInContext, defaultLogInDataReducer, defaultLogInData, logInAction } from "./components/Login";
import { SignUpContext, defaultSignUpDataReducer, defaultSignUpData, signUpAction } from "./components/Signup";
import React, { useState, useRef, useEffect, useReducer, useCallback } from "react";
import { createRoot } from "react-dom/client";
import { Container, CircularProgress } from "@mui/joy";
import { CssVarsProvider } from "@mui/joy/styles";
import { Status, Client } from "./client";
import { useEffectOnce } from "usehooks-ts";

const PORT = 8080;
const { hostname, protocol } = window.location;
const client = new Client(`${protocol}//${hostname}:${PORT}`);
client.establishSession();

createRoot(document.getElementById("root")).render(<App/>);

function App() {
  const [logInData, logInDispatch] = useReducer(defaultLogInDataReducer, { ...defaultLogInData, usernameExists, userLoginPermitted, submit: logIn });
  const [signUpData, signUpDispatch] = useReducer(defaultSignUpDataReducer, { ...defaultSignUpData, usernameExists, submit: signUp });
  const [status, setStatus] = useState<Status>(null);
  const [connected, setConnected] = useState(false);
  const [signedIn, setSignedIn] = useState(false);
  const [displayName, setDisplayName] = useState("");
  const [currentTab, setCurrentTab] = useState(0);
  const notifyStatus = useCallback(setStatus, []);
  useEffectOnce(() => { 
    client.subscribeStatusChange(notifyStatus);
    window.addEventListener("beforeunload", client.terminateCurrentSession.bind(client), { capture: true, once: true })
  });
  
  useEffect(() => {
    switch (status) {
      case Status.Disconnected: 
        setConnected(false);
        break;
      case Status.Connecting: 
        setConnected(false);
        break;
      case Status.Reconnecting: 
        setConnected(false);
        break;
      case Status.FailedToConnect: 
        setConnected(false);
        break;
      case Status.Connected: 
        client.userLogIn().then(({ reason }) => {
          if (!reason) {
            setSignedIn(true);
          }
          setConnected(true);
        });
        break;
      case Status.SigningIn: break;
      case Status.FailedSignIn: break;
      case Status.ReAuthenticating: break;
      case Status.FailedReAuthentication: break;
      case Status.CreatingNewUser: break;
      case Status.FailedCreateNewUser: break;
      case Status.CreatedNewUser: break;
      case Status.SignedIn: 
        setSignedIn(true);
        setDisplayName(client.displayName);
        break;
      case Status.SigningOut: break;
      case Status.SignedOut:
        setSignedIn(false);
        setDisplayName("");
        break;
      default: break;
    }
  }, [status, connected]);

  useEffect(() => {
    if (!connected) {
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
    return client.userLogIn(username, password, savePassword);
  }

  function signUp({ displayName, username, password, savePassword }: SubmitResponse) {
    displayName ||= username;
    return client.registerNewUser(username, password, displayName, savePassword);
  }
  
  return (
    <CssVarsProvider>
      <Container maxWidth={false} disableGutters={true} sx={{ height: "100vh", overflow: "clip", display: "flex", flexDirection: "column" }}>
        {(!connected && !signedIn) &&
        <React.Fragment>
          <Spacer units={2}/>
          <div style={{ display: "flex", justifyContent: "center" }}>
            <CircularProgress size="lg" variant="soft"/>
          </div>
        </React.Fragment>}
        {connected && !signedIn &&
          <LogInContext.Provider value={{ logInData, logInDispatch }}>
            <SignUpContext.Provider value={{ signUpData, signUpDispatch }}>
              <LogInSignUp currentTab={currentTab} setCurrentTab={setCurrentTab}/>
            </SignUpContext.Provider>
          </LogInContext.Provider>
        }
        {signedIn &&
        <Main client={client} connected={connected} displayName={displayName}/>
        }
      </Container>
    </CssVarsProvider>);
}