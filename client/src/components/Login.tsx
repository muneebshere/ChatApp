import _ from "lodash";
import { match } from "ts-pattern";
import React, { useRef, useEffect, useContext, createContext, Dispatch, useState, useCallback } from "react";
import { FormControl, FormLabel, Stack, Button, CircularProgress, Alert } from "@mui/joy";
import { SubmitResponse } from "../App";
import { DisableSelectTypography, StyledJoySwitch } from "./CommonElementStyles";
import ControlledTextField from "./ControlledTextField";
import WarnSavePassword from "./WarnSavePassword";
import { ErrorStrings, Failure } from "../../../shared/commonTypes";

type LogInData = {
  readonly username: string;
  readonly usernameEntered: boolean;
  readonly password: string;
  readonly lastIncorrectPasswords: [string, string][];
  readonly showPassword: boolean;
  readonly savePassword: boolean;
  readonly tryAgainIn: number;
  readonly tryCount: number;
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
  usernameEntered: false,
  password: "",
  lastIncorrectPasswords: [],
  showPassword: false,
  savePassword: false,
  tryAgainIn: 0,
  tryCount: 0,
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
    .with("usernameEntered", () => ({ ...data, usernameEntered: value as boolean }))
    .with("lastIncorrectPasswords", () => ({ ...data, lastIncorrectPasswords: value as [string, string][] }))
    .with("showPassword", () => ({ ...data, showPassword: value as boolean }))
    .with("tryAgainIn", () => ({ ...data, tryAgainIn: value as number }))
    .with("tryCount", () => ({ ...data, tryCount: value as number }))
    .with("failed", () => ({ ...data, failed: value as boolean }))
    .with("submitted", () => ({ ...data, submitted: value as boolean }))
    .with("warned", () => ({ ...data, warned: value as boolean }))
    .otherwise(() => data);
}

export const LogInContext = createContext<LogInContextType>(null);

export default function LogInForm() {
  const { logInData: { username, usernameEntered, password, lastIncorrectPasswords, showPassword, savePassword, tryAgainIn, tryCount, failed, submitted, warned, usernameExists, userLoginPermitted, submit },  logInDispatch } = useContext(LogInContext);
  const [usernameError, setUsernameError] = useState("");
  const setUsername = (username: string) => logInDispatch(logInAction("username", username));
  const setUsernameEntered = (usernameEntered: boolean) => logInDispatch(logInAction("usernameEntered", usernameEntered));
  const setPassword = (password: string) => logInDispatch(logInAction("password", password));
  const setLastIncorrectPasswords = (lastIncorrectPasswords: [string, string][]) => logInDispatch(logInAction("lastIncorrectPasswords", lastIncorrectPasswords));
  const setShowPassword = (showPassword: boolean) => logInDispatch(logInAction("showPassword", showPassword));
  const setSavePassword = (savePassword: boolean) => logInDispatch(logInAction("savePassword", savePassword));
  const setFailed = (failed: boolean) => logInDispatch(logInAction("failed", failed));
  const setSubmitted = (submitted: boolean) => logInDispatch(logInAction("submitted", submitted));
  const setWarned = (warned: boolean) => logInDispatch(logInAction("warned", warned));
  const setTryAgainIn = (tryAgainIn: number) => logInDispatch(logInAction("tryAgainIn", tryAgainIn));
  const setTryCount = (tryCount: number) => logInDispatch(logInAction("tryCount", tryCount));
  const canSubmit = !submitted && password && validatePassword(password) || tryAgainIn <= 0;
  const timerRef = useRef<number>(null);
  const decrementTimer = useCallback(() => setTryAgainIn(tryAgainIn - 1000), [tryAgainIn]);

  useEffect(() => {
    usernameExists(username).then((exists) => setUsernameError(exists ? null: "No such user.")).catch(() => {});
  }, [username]);

  useEffect(() => {
    if (tryAgainIn > 0) {
      timerRef.current = window.setInterval(decrementTimer, 1000);
      return () => window.clearTimeout(timerRef.current);
    }
    else if (timerRef.current) window.clearInterval(timerRef.current);
  }, [tryAgainIn]);

  function onUsernameEntered() {
    if (!usernameError) {
      setUsernameEntered(true);
      userLoginPermitted(username).then((({ tries, allowsAt }) => {
        if (tries && allowsAt) {
          setTryCount(tries);
          setTryAgainIn(allowsAt - Date.now());
        }
      }));
    }
  }

  function validatePassword(password: string) {
    return !lastIncorrectPasswords.some((([u, p]) => u === username && p === password));
  }

  async function submitLocal() {
    if (!canSubmit) return;
    setFailed(false);
    setSubmitted(true);
    const { reason, details } = (await submit({ username, password, savePassword })) ?? {};
    if (reason) {
      if (reason === ErrorStrings.IncorrectPassword) {
        setLastIncorrectPasswords([...lastIncorrectPasswords, [username, password]]);
      }
      else if (reason === ErrorStrings.TooManyWrongTries) {
        setLastIncorrectPasswords([...lastIncorrectPasswords, [username, password]]);
        const { tries, allowsAt } = details ?? {};
        if (allowsAt && allowsAt > Date.now()) {
          setTryCount(tries);
          setTryAgainIn(allowsAt - Date.now());
        }
      }
      else if (reason === ErrorStrings.InvalidRequest && details === "Already Logged In Elsewhere") {
        setUsernameError("This user is already logged in elsewhere.");
        setUsernameEntered(false);
      }
      else {
        setFailed(true);
      }
    }
    else {
      setTryCount(0);
      setTryAgainIn(0);
    }
    setSubmitted(false);
  }

  return(
    <Stack spacing={2}>
      {!usernameEntered &&
        <React.Fragment>
          <ControlledTextField 
            autoComplete="username"
            variant="outlined"
            placeholder="Please enter your username" 
            type="text"
            value={username}
            preventSpaces
            setValue={setUsername}
            valid={!usernameError}
            forceInvalid={!!username}
            errorMessage={usernameError}
            onEnter={onUsernameEntered}/>
          <Button variant="solid"
            onClick={onUsernameEntered} 
            disabled={ !!usernameError }>
              Next
          </Button>
        </React.Fragment>
      }
      {usernameEntered &&
        <React.Fragment>
          <ControlledTextField 
            variant="outlined"
            autoComplete="current-password"
            placeholder="Please enter your password" 
            type={ showPassword ? "text" : "password" }
            value={password}
            preventSpaces
            setValue={setPassword}
            valid={!!password && tryAgainIn <= 0 && validatePassword(password)}
            disabled={submitted || tryAgainIn > 0}
            forceInvalid={!validatePassword(password) || tryAgainIn > 0}
            errorMessage={ tryAgainIn <= 0 ? (!password ? "Please provide password" : "Incorrect password.") : `Incorrect password entered ${tryCount} times. Try again in ${ (tryAgainIn / 1000).toFixed(0) }s.`}
            onEnter={submitLocal}/>
          <FormControl orientation="horizontal">
            <FormLabel>Show Password</FormLabel>
            <StyledJoySwitch checked={showPassword}
              disabled={submitted}
              onChange={ (e) => setShowPassword(e.target.checked) } 
              color={showPassword ? "primary" : "neutral"}/>
          </FormControl>
          <FormControl orientation="horizontal">
            <FormLabel>Save password</FormLabel>
            <StyledJoySwitch checked={savePassword} 
              disabled={submitted}
              onChange={ (e) => setSavePassword(e.target.checked) }
              color={savePassword ? "primary" : "neutral"}/>
          </FormControl>
          <Stack direction="row" spacing={2}>
            <Button variant="solid"
              onClick={ () => setUsernameEntered(false) }
              disabled={ submitted || tryAgainIn > 0 }>
              <DisableSelectTypography fontWeight="sm" textColor={ submitted || tryAgainIn > 0 ? "black" : "white" }>
                Back
              </DisableSelectTypography>
            </Button>
            <Button variant="solid"
              onClick={submitLocal}
              disabled={!canSubmit}>
              <Stack direction="row" spacing={2}>
                <DisableSelectTypography fontWeight="sm" textColor={ !canSubmit ? "black" : "white" }>
                  { submitted ? "Logging in..." :"Login" }
                </DisableSelectTypography>
                {submitted &&
                  <CircularProgress size="sm" variant="soft"/>
                }
              </Stack>
            </Button>
          </Stack>
          <WarnSavePassword open={savePassword && !warned} setWarned={setWarned}/>
        </React.Fragment>
      }
      {failed &&
      <Alert variant="soft" color="danger" size="sm">
        <DisableSelectTypography color="danger" fontWeight="sm">Login error! Please try again.</DisableSelectTypography>
      </Alert>}
    </Stack>
  )
}