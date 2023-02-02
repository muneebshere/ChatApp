import { SubmitResponse, Spacer } from "./components/Common";
import LogInSignUp from "./components/LogInSignUp";
import Main from "./components/Main";
import { LogInDataContext, LogInDataDispatchContext, defaultLogInDataReducer, defaultLogInData, logInAction } from "./components/Login";
import { SignUpDataContext, SignUpDataDispatchContext, defaultSignUpDataReducer, defaultSignUpData, signUpAction } from "./components/Signup";
import React, { useState, useRef, useEffect, useReducer } from "./node_modules/react";
import { createRoot } from "./node_modules/react-dom/client";
import { Container, Stack, CircularProgress } from "./node_modules/@mui/joy";
import { CssVarsProvider } from "./node_modules/@mui/joy/styles";
import { Status, Client } from "./client";

const PORT = 8080;

createRoot(document.getElementById("root")).render(<App/>);

function App() {
  const [logInData, logInDataDispatch] = useReducer(defaultLogInDataReducer, { ...defaultLogInData, usernameExists, submit: logIn });
  const [signUpData, signUpDataDispatch] = useReducer(defaultSignUpDataReducer, { ...defaultSignUpData, usernameExists, submit: signUp });
  const [status, setStatus] = useState<Status>(null);
  const [connected, setConnected] = useState(false);
  const [signedIn, setSignedIn] = useState(false);
  const [displayName, setDisplayName] = useState("");
  const [currentTab, setCurrentTab] = useState(0);
  const { hostname, protocol } = window.location;
  const client = useRef(new Client(`${protocol}//${hostname}:${PORT}`, setStatus));
  useEffect(() => { client.current.establishSession(); }, []);
  useEffect(() => window.addEventListener("beforeunload", client.current.terminateCurrentSession.bind(client.current), { capture: true, once: true }), []);
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
        client.current.userLogIn().then(({ reason }) => {
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
        setDisplayName(client.current.displayName);
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
      logInDataDispatch(logInAction("submitted", false));
      signUpDataDispatch(signUpAction("submitted", false));
    }
  }, [connected]);

  function usernameExists(username: string) {
    return client.current.checkUsernameExists(username);
  }

  function logIn({ username, password, savePassword }: SubmitResponse) {
    return client.current.userLogIn(username, password, savePassword);
  }

  function signUp({ displayName, username, password, savePassword }: SubmitResponse) {
    displayName ||= username;
    return client.current.registerNewUser(username, password, displayName, savePassword);
  }
  
  return (
    <CssVarsProvider>
      <Container maxWidth={false}>
        {(!connected && !signedIn) &&
        <React.Fragment>
          <Spacer units={2}/>
          <div style={{ display: "flex", justifyContent: "center" }}>
            <CircularProgress size="lg" variant="soft"/>
          </div>
        </React.Fragment>}
        {connected && !signedIn &&
          <LogInDataContext.Provider value={logInData}>
            <LogInDataDispatchContext.Provider value={logInDataDispatch}>
              <SignUpDataContext.Provider value={signUpData}>
                <SignUpDataDispatchContext.Provider value={signUpDataDispatch}>
                  <LogInSignUp currentTab={currentTab} setCurrentTab={setCurrentTab}/>
                </SignUpDataDispatchContext.Provider>
              </SignUpDataContext.Provider>
            </LogInDataDispatchContext.Provider>
          </LogInDataContext.Provider>
        }
        {signedIn &&
        <Main connected={connected} displayName={displayName}/>
        }
      </Container>
    </CssVarsProvider>);
}