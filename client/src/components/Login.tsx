import _ from "lodash";
import { match } from "ts-pattern";
import React, { useRef, useEffect, useContext, createContext, Dispatch, useState, useCallback } from "react";
import { FormControl, FormLabel, Stack, Button, CircularProgress, Alert, FormHelperText } from "@mui/joy";
import { SubmitResponse } from "../App";
import { DisableSelectTypography, StyledJoySwitch } from "./CommonElementStyles";
import ControlledTextField from "./ControlledTextField";
import { ErrorStrings, Failure, LogInPermitted } from "../../../shared/commonTypes";

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
  readonly userLoginPermitted: (username: string) => Promise<LogInPermitted>;
  readonly submit: (response: SubmitResponse) => Promise<Failure>;
}

type LogInAction<K extends keyof LogInData> = {
  id: K | "clear";
  value: LogInData[K];
}

type LogInDataReducer = (data: LogInData, action: LogInAction<keyof LogInData>) => LogInData;

type LogInContextType = {
  logInData: LogInData,
  logInDispatch: Dispatch<LogInAction<keyof LogInData>>;
}

export function logInAction<K extends keyof LogInData>(id: K | "clear", value: LogInData[K]): LogInAction<K> {
  return { id, value };
}

export const defaultLogInData: Omit<LogInData, "submit" | "userLoginPermitted"> = {
  username: "",
  usernameEntered: false,
  password: "",
  lastIncorrectPasswords: [],
  showPassword: false,
  savePassword: false,
  tryAgainIn: 0,
  tryCount: 0,
  submitted: false,
  failed: false
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
    .with("clear", () => ({ ...defaultLogInData ,..._.pick(data, "userLoginPermitted", "submit") }))
    .otherwise(() => data);
}

export const LogInContext = createContext<LogInContextType>(null);

export default function LogInForm() {
  const { logInData: { username, usernameEntered, password, lastIncorrectPasswords, showPassword, savePassword, tryAgainIn, tryCount, failed, submitted, userLoginPermitted, submit },  logInDispatch } = useContext(LogInContext);
  const [usernameError, setUsernameError] = useState("");
  const setUsername = (username: string) => logInDispatch(logInAction("username", username));
  const setUsernameEntered = (usernameEntered: boolean) => logInDispatch(logInAction("usernameEntered", usernameEntered));
  const setPassword = (password: string) => logInDispatch(logInAction("password", password));
  const setLastIncorrectPasswords = (lastIncorrectPasswords: [string, string][]) => logInDispatch(logInAction("lastIncorrectPasswords", lastIncorrectPasswords));
  const setShowPassword = (showPassword: boolean) => logInDispatch(logInAction("showPassword", showPassword));
  const setSavePassword = (savePassword: boolean) => logInDispatch(logInAction("savePassword", savePassword));
  const setFailed = (failed: boolean) => logInDispatch(logInAction("failed", failed));
  const setSubmitted = (submitted: boolean) => logInDispatch(logInAction("submitted", submitted));
  const setTryAgainIn = (tryAgainIn: number) => logInDispatch(logInAction("tryAgainIn", tryAgainIn));
  const setTryCount = (tryCount: number) => logInDispatch(logInAction("tryCount", tryCount));
  const canSubmit = !submitted && password && validatePassword(password) || tryAgainIn <= 0;
  const timerRef = useRef<number>(null);
  const decrementTimer = useCallback(() => setTryAgainIn(tryAgainIn - 1000), [tryAgainIn]);

  useEffect(() => {
    if (username) {
      userLoginPermitted(username).then((result) => setUsernameError(result?.login ? null: "No such user.")).catch(() => {});
    }
  }, [username]);

  useEffect(() => {
    if (tryAgainIn) {
      timerRef.current = window.setTimeout(decrementTimer, 1000);
    }
    return () => window.clearTimeout(timerRef.current);
  }, [tryAgainIn]);

  async function onUsernameEntered() {
    if (!usernameError) {
      setUsernameEntered(true);
      const result = await userLoginPermitted(username);
      if (result?.login) {
        const { tries, allowsAt } = result.login;
        if (tries && allowsAt) {
          setTryCount(tries);
          setTryAgainIn(allowsAt - Date.now());
        }
      }
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
    if (reason !== false) {
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
      else if (reason === ErrorStrings.InvalidRequest && details === "Already Active Elsewhere") {
        setUsernameError("This user is already active elsewhere.");
        setPassword("");
        setUsernameEntered(false);
      }
      else {
        setFailed(true);
      }
    }
    else {
      logInDispatch(logInAction("clear", null));
    }
    setSubmitted(false);
  }

  return(
    <Stack spacing={2}
      onKeyUp={(e) => {
        if (e.key === "Enter") {
          e.stopPropagation();
          submitLocal();
        }
      }}>
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
            autoFocus={!usernameEntered}
            forceFocus={!usernameEntered}
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
            autoFocus={usernameEntered}/>
          <FormControl orientation="horizontal">
            <FormLabel>Show password</FormLabel>
            <StyledJoySwitch checked={showPassword}
              disabled={submitted}
              onChange={ (e) => setShowPassword(e?.target?.checked) } 
              color={showPassword ? "primary" : "neutral"}/>
            </FormControl>
          <div style={{ display: "flex", flexDirection: "column", width: "100%" }}>
            <FormControl orientation="horizontal" sx={{ width: "100%" }}>
              <FormLabel>Save password</FormLabel>
              <StyledJoySwitch checked={savePassword} 
                disabled={submitted}
                onChange={ (e) => setSavePassword(e?.target?.checked) }
                color={savePassword ? "primary" : "neutral"}/>
            </FormControl>
            {savePassword &&
              <FormHelperText sx={{ width: "100%", paddingTop: "4px", justifyItems: "flex-start", textAlign: "start", color: "var(--joy-palette-danger-outlinedColor)" }}>
                Please don't use this option on a shared computer.
              </FormHelperText>}
          </div>
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
        </React.Fragment>
      }
      {failed &&
      <Alert variant="soft" color="danger" size="sm">
        <DisableSelectTypography color="danger" fontWeight="sm">Login error! Please try again.</DisableSelectTypography>
      </Alert>}
    </Stack>
  )
}