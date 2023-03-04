import _ from "lodash";
import { match } from "ts-pattern";
import { SubmitResponse, SubmitProps, ControlledTextField, StyledSwitch } from "./Common";
import React, { useState, useRef, useEffect, useReducer, useContext, createContext, Dispatch } from "react";
import { FormControl, FormLabel, Stack, Button, CircularProgress, Modal, ModalClose, Sheet, Typography, Alert } from "@mui/joy";
import { CommonStrings, Failure } from "../../../shared/commonTypes";

type LogInData = {
  readonly username: string;
  readonly usernameValid: boolean;
  readonly usernameEntered: boolean;
  readonly password: string;
  readonly passwordValid: boolean;
  readonly lastIncorrectPasswords: [string, string][];
  readonly showPassword: boolean;
  readonly savePassword: boolean;
  readonly tryAgainIn: number;
  readonly tryCount: number;
  readonly tryAgain: number;
  readonly failed: boolean;
  readonly submitted: boolean;
  readonly warned: boolean;
  readonly usernameExists: (username: string) => Promise<boolean>;
  readonly userLoginPermitted: (username: string) => Promise<{ tries: number, allowsAt: number }>;
  readonly submit: (response: SubmitResponse) => Promise<Failure>;
}

type LogInAction<K extends keyof LogInData> = {
  id: K;
  value: LogInData[K];
}

type LogInDataReducer = (data: LogInData, action: LogInAction<keyof LogInData>) => LogInData;

type LogInContextType = {
  logInData: LogInData,
  logInDispatch: Dispatch<LogInAction<keyof LogInData>>;
}

export function logInAction<K extends keyof LogInData>(id: K, value: LogInData[K]): LogInAction<K> {
  return { id, value };
}

export const defaultLogInData: Omit<LogInData, "usernameExists" | "submit" | "userLoginPermitted"> = {
  username: "",
  usernameValid: false,
  usernameEntered: false,
  password: "",
  passwordValid: true,
  lastIncorrectPasswords: [],
  showPassword: false,
  savePassword: false,
  tryAgainIn: 0,
  tryCount: 0,
  tryAgain: 0,
  submitted: false,
  failed: false,
  warned: false
};

export const defaultLogInDataReducer: LogInDataReducer = (data, action) => {
  const { id, value } = action;
  return match(id)
    .with("username", () => ({ ...data, username: value as string }))
    .with("password", () => ({ ...data, password: value as string }))
    .with("savePassword", () => ({ ...data, savePassword: value as boolean }))
    .with("usernameValid", () => ({ ...data, usernameValid: value as boolean }))
    .with("usernameEntered", () => ({ ...data, usernameEntered: value as boolean }))
    .with("passwordValid", () => ({ ...data, passwordValid: value as boolean }))
    .with("lastIncorrectPasswords", () => ({ ...data, lastIncorrectPasswords: value as [string, string][] }))
    .with("showPassword", () => ({ ...data, showPassword: value as boolean }))
    .with("tryAgainIn", () => ({ ...data, tryAgainIn: value as number }))
    .with("tryCount", () => ({ ...data, tryCount: value as number }))
    .with("tryAgain", () => ({ ...data, tryAgain: value as number }))
    .with("failed", () => ({ ...data, failed: value as boolean }))
    .with("submitted", () => ({ ...data, submitted: value as boolean }))
    .with("warned", () => ({ ...data, warned: value as boolean }))
    .otherwise(() => data);
}

export const LogInContext = createContext<LogInContextType>(null);

export default function LogInForm() {
  const { logInData: { username, usernameValid, usernameEntered, password, passwordValid, lastIncorrectPasswords, showPassword, savePassword, tryAgainIn, tryCount, tryAgain, failed, submitted, warned, usernameExists, userLoginPermitted, submit },  logInDispatch } = useContext(LogInContext);
  const setUsername = (username: string) => logInDispatch(logInAction("username", username));
  const setUsernameValid = (usernameValid: boolean) => logInDispatch(logInAction("usernameValid", usernameValid));
  const setUsernameEntered = (usernameEntered: boolean) => logInDispatch(logInAction("usernameEntered", usernameEntered));
  const setPassword = (password: string) => logInDispatch(logInAction("password", password));
  const setPasswordValid = (passwordValid: boolean) => logInDispatch(logInAction("passwordValid", passwordValid));
  const setLastIncorrectPasswords = (lastIncorrectPasswords: [string, string][]) => logInDispatch(logInAction("lastIncorrectPasswords", lastIncorrectPasswords));
  const setShowPassword = (showPassword: boolean) => logInDispatch(logInAction("showPassword", showPassword));
  const setSavePassword = (savePassword: boolean) => logInDispatch(logInAction("savePassword", savePassword));
  const setFailed = (failed: boolean) => logInDispatch(logInAction("failed", failed));
  const setSubmitted = (submitted: boolean) => logInDispatch(logInAction("submitted", submitted));
  const setWarned = (warned: boolean) => logInDispatch(logInAction("warned", warned));
  const setTryAgainIn = (tryAgainIn: number) => logInDispatch(logInAction("tryAgainIn", tryAgainIn));
  const setTryAgainRef = (tryAgain: number) => logInDispatch(logInAction("tryAgain", tryAgain));
  const setTryCount = (tryCount: number) => logInDispatch(logInAction("tryCount", tryCount));
  const tryAgainRef = useRef(0);
  tryAgainRef.current ??= tryAgain;

  useEffect(() => {
    if (tryAgainIn > 0) {
      tryAgainRef.current = tryAgainIn;
      setTryAgainRef(tryAgainIn);
      const timer = window.setTimeout(() => setTryAgainIn(tryAgainRef.current - 1000), 1000);
      return () => window.clearTimeout(timer);
    }
  }, [tryAgainIn]);

  function onUsernameEntered() {
    userLoginPermitted(username).then((({ tries, allowsAt }) => {
      if (tries) {
        if (tries && allowsAt) {
          setTryCount(tries);
          setTryAgainIn(allowsAt - Date.now());
        }
      }
      setUsernameEntered(true);
    }));
  }

  function validateUserName(username: string): void {
    usernameExists(username).then((exists) => setUsernameValid(exists)).catch(() => {});
  }

  async function submitLocal() {
    if (submitted || !password || !passwordValid || tryAgainIn > 0) return;
    setFailed(false);
    setSubmitted(true);
    const { reason, details } = (await submit({ username, password, savePassword })) ?? {};
    if (!reason) setPasswordValid(true);
    else {
      if (reason === CommonStrings.IncorrectPassword) {
        setLastIncorrectPasswords([...lastIncorrectPasswords, [username, password]]);
        setPasswordValid(false);
      }
      else if (reason === CommonStrings.TooManyWrongTries) {
        setPasswordValid(false);
        const { tries, allowsAt } = details ?? {};
        if (allowsAt && allowsAt > Date.now()) {
          setTryCount(tries);
          setTryAgainIn(allowsAt - Date.now());
        }
      }
      else {
        setFailed(true);
      }
    }
    setSubmitted(false);
  }

  return(
    <Stack spacing={2}>
      {!usernameEntered &&
        <React.Fragment>
          <ControlledTextField 
            variant="outlined"
            placeholder="Please enter your username" 
            type="text"
            value={username}
            preventSpaces
            setValue={setUsername}
            validate={validateUserName}
            valid={usernameValid}
            forceInvalid={!!username}
            errorMessage="No such user."
            onEnter={ () => {
              if (!!usernameValid) {
                setUsernameEntered(true);
              }
            } }/>
          <Button variant="solid"
            onClick={onUsernameEntered} 
            disabled={ !usernameValid }>
              Next
          </Button>
        </React.Fragment>
      }
      {usernameEntered &&
        <React.Fragment>
          <ControlledTextField 
            variant="outlined"
            placeholder="Please enter your password" 
            type={ showPassword ? "text" : "password" }
            value={password}
            preventSpaces
            setValue={setPassword}
            validate={ (pass) => setPasswordValid(!lastIncorrectPasswords.some((([u, p]) => u === username && p === pass))) }
            valid={passwordValid && !!password && tryAgain <= 0}
            disabled={submitted || tryAgainIn > 0}
            forceInvalid={!passwordValid || tryAgainIn > 0}
            errorMessage={ tryAgainIn <= 0 ? (!password ? "Please provide password" : "Incorrect password.") : `Incorrect password entered ${tryCount} times. Try again in ${ (tryAgainIn / 1000).toFixed(0) }s.`}
            onEnter={submitLocal}/>
          <FormControl orientation="horizontal">
            <FormLabel>Show Password</FormLabel>
            <StyledSwitch checked={showPassword}
              disabled={submitted}
              onChange={ (e) => setShowPassword(e.target.checked) } 
              color={showPassword ? "primary" : "neutral"}/>
          </FormControl>
          <FormControl orientation="horizontal">
            <FormLabel>Save password</FormLabel>
            <StyledSwitch checked={savePassword} 
              disabled={submitted}
              onChange={ (e) => setSavePassword(e.target.checked) }
              color={savePassword ? "primary" : "neutral"}/>
          </FormControl>
          <Stack direction="row" spacing={2}>
            <Button variant="solid"
              onClick={ () => setUsernameEntered(false) }
              disabled={ submitted || tryAgainIn > 0 }>
              <Typography fontWeight="sm" textColor={ submitted || tryAgainIn > 0 ? "black" : "white" }>
                Back
              </Typography>
            </Button>
            <Button variant="solid"
              onClick={submitLocal}
              disabled={ !password || !passwordValid || submitted || tryAgainIn > 0 }>
              <Stack direction="row" spacing={2}>
                <Typography fontWeight="sm" textColor={ !password || submitted || tryAgainIn > 0 ? "black" : "white" }>
                  { submitted ? "Logging in..." :"Login" }
                </Typography>
                {submitted &&
                  <CircularProgress size="sm" variant="soft"/>
                }
              </Stack>
            </Button>
          </Stack>
          <Modal
            open={savePassword && !warned}
            onClose={() => setWarned(true)}
            sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
            <Sheet
              variant="outlined"
              sx={{
                maxWidth: 500,
                borderRadius: 'md',
                p: 3,
              boxShadow: 'lg'}}>
              <ModalClose
                variant="outlined"
                sx={{
                  top: 'calc(-1/4 * var(--IconButton-size))',
                  right: 'calc(-1/4 * var(--IconButton-size))',
                  boxShadow: '0 2px 12px 0 rgba(0 0 0 / 0.2)',
                  borderRadius: '50%',
                  bgcolor: 'background.body'}}/>
              <Typography
                component="h2"
                id="modal-title"
                level="h4"
                textColor="inherit"
                fontWeight="lg"
                mb={1}>
                Save password?
              </Typography>
              <Typography id="modal-desc" textColor="text.tertiary">
                The browser will save your password so you won't have to re-enter it on future visits. However, this compromises the security of your account. Anyone with access to your browser may be able to extract the password from its cookies. You may disable password saving later from your settings.
              </Typography>
            </Sheet>
          </Modal>
        </React.Fragment>
      }
      {failed &&
      <Alert variant="soft" color="danger" size="sm">
        <Typography color="danger" fontWeight="sm">Login error! Please try again.</Typography>
      </Alert>}
    </Stack>
  )
}