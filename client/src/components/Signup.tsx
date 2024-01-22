import _ from "lodash";
import { match } from "ts-pattern";
import React, { createContext, Dispatch, useCallback, useContext, useEffect, useRef, useState } from "react";
import { FormControl, FormLabel, Stack, Button, CircularProgress, Alert, FormHelperText } from "@mui/joy";
import { SubmitResponse } from "../App";
import { DisableSelectTypography, StyledJoySwitch } from "./CommonElementStyles";
import ControlledTextField from "./ControlledTextField";
import { Failure } from "../../../shared/commonTypes";

type SignUpData = {
  readonly displayName: string;
  readonly username: string;
  readonly password: string;
  readonly repeatPassword: string;
  readonly showPassword: boolean;
  readonly savePassword: boolean;
  readonly failed: boolean;
  readonly submitted: boolean;
  readonly usernameExists: (username: string) => Promise<boolean>;
  readonly submit: (response: SubmitResponse) => Promise<Failure>;
}

type SignUpAction<K extends keyof SignUpData> = {
  id: K | "clear";
  value: SignUpData[K];
}

type SignUpDataReducer = (data: SignUpData, action: SignUpAction<keyof SignUpData>) => SignUpData;

type SignUpContextType = {
  signUpData: SignUpData,
  signUpDispatch: Dispatch<SignUpAction<keyof SignUpData>>;
}

export function signUpAction<K extends keyof SignUpData>(id: K | "clear", value: SignUpData[K]): SignUpAction<K> {
  return { id, value };
}

export const defaultSignUpData: Omit<SignUpData, "usernameExists" | "submit"> = {
  displayName: "",
  username: "",
  password: "",
  repeatPassword: "",
  showPassword: false,
  savePassword: false,
  submitted: false,
  failed: false
};

export const defaultSignUpDataReducer: SignUpDataReducer = (data, action) => {
  const { id, value } = action;
  return match(id)
    .with("displayName", () => ({ ...data, displayName: value as string }))
    .with("username", () => ({ ...data, username: value as string }))
    .with("password", () => ({ ...data, password: value as string }))
    .with("repeatPassword", () => ({ ...data, repeatPassword: value as string }))
    .with("showPassword", () => ({ ...data, showPassword: value as boolean }))
    .with("savePassword", () => ({ ...data, savePassword: value as boolean }))
    .with("submitted", () => ({ ...data, submitted: value as boolean }))
    .with("failed", () => ({ ...data, failed: value as boolean }))
    .with("clear", () => ({ ...defaultSignUpData ,..._.pick(data, "usernameExists", "submit") }))
    .otherwise(() => data);    
}

export const SignUpContext = createContext<SignUpContextType>(null);

export default function SignUpForm() {
  const { signUpData: { displayName, username, password, repeatPassword, showPassword, savePassword, failed, submitted, usernameExists, submit }, signUpDispatch } = useContext(SignUpContext);
  const [usernameError, setUsernameError] = useState("");
  const setDisplayName = (displayName: string) => signUpDispatch(signUpAction("displayName", displayName));
  const setUsername = (username: string) => signUpDispatch(signUpAction("username", username));
  const setPassword = (password: string) => signUpDispatch(signUpAction("password", password));
  const setRepeatPassword = (repeatPassword: string) => signUpDispatch(signUpAction("repeatPassword", repeatPassword));
  const setShowPassword = (showPassword: boolean) => signUpDispatch(signUpAction("showPassword", showPassword));
  const setSavePassword = (savePassword: boolean) => signUpDispatch(signUpAction("savePassword", savePassword));
  const setFailed = (failed: boolean) => signUpDispatch(signUpAction("failed", failed));
  const setSubmitted = (submitted: boolean) => signUpDispatch(signUpAction("submitted", submitted));
  const canSubmit = !submitted && !usernameError && isPasswordValid(password) && (showPassword || password === repeatPassword);

  useEffect(() => {
    getUsernameError(username).then((error) => setUsernameError(error));
  }, [username]);


  async function getUsernameError(username: string): Promise<string> {
    if (username.match(/^[a-z][a-z0-9_]{2,14}$/) === null) {
      return "Username may contain only lowercase letters, digits and underscores, must start with a letter, and must be between 3 and 15 characters.";
    }
    else {
      return (await usernameExists(username)) ? "Username already exists." : "";
    }
  }

  function isPasswordValid(password: string): boolean {
    return password.match(/^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$/) !== null;
  }

  async function submitLocal() {
    if (!canSubmit) return;
    setFailed(false);
    setSubmitted(true);
    const { reason } = await submit({ displayName, username, password, savePassword });
    if (reason !== false) {
      setFailed(true);
    }
    signUpDispatch(signUpAction("clear", null));
    setSubmitted(false);
  }

  const usernameInput = useRef<HTMLInputElement>(null);
  const newPasswordInput = useRef<HTMLInputElement>(null);
  const passwordAgainInput = useRef<HTMLInputElement>(null);

  return(
    <React.Fragment>
      <Stack spacing={2}
      onKeyUp={(e) => {
        if (e.key === "Enter") {
          e.stopPropagation();
          submitLocal();
        }
      }}>
        <ControlledTextField 
          variant="outlined"
          highlightColor="#1f7a1f"
          placeholder="Display Name (Optional)" 
          type="text"
          value={displayName}
          setValue={setDisplayName}
          valid={true}
          disabled={submitted}
          autoFocus={true}
          helperText="If you don't specify a display name, your username will be used as your display name."
          onEnter={() => usernameInput.current?.focus()}/>
        <ControlledTextField
          ref={usernameInput}
          variant="outlined"
          highlightColor="#1f7a1f"
          placeholder="Please choose a unique username" 
          type="text"
          value={username}
          preventSpaces
          setValue={setUsername}
          valid={!usernameError}
          disabled={submitted}
          errorMessage={usernameError}
          onEnter={async (e) => {
            const { value } = (e.target as HTMLInputElement);
            if (!(await getUsernameError(value))) { 
              newPasswordInput.current?.focus();
            }
            else {
              usernameInput.current?.blur();
              usernameInput.current?.focus();
            }
          }}/>
        <ControlledTextField
          ref={newPasswordInput}
          autoComplete="new-password"
          variant="outlined"
          highlightColor="#1f7a1f"
          placeholder="Please choose a new password" 
          type={ showPassword ? "text" : "password" }
          value={password}
          preventSpaces
          setValue={setPassword}
          valid={isPasswordValid(password)}
          disabled={submitted}
          errorMessage={`Please choose a password at least 8 characters long, with at least one uppercase letter, one lowercase letter, one digit and one special character (#?!@$%^&*-]).${showPassword ? "\nKeep this password safe. If lost, you will irretrievably lose access to all chats.": ""}`}
          helperText={showPassword ? "Keep this password safe. If lost, you will irretrievably lose access to all chats." : undefined}
          onEnter={(e) => {
            const { value } = (e.target as HTMLInputElement);
            if (isPasswordValid(value)) {
              if (passwordAgainInput.current) passwordAgainInput.current.focus();
              else submitLocal();
            }
            else {
              newPasswordInput.current?.blur();
              newPasswordInput.current?.focus();
            }
          }}/>
        {!showPassword &&
          <ControlledTextField 
            ref={passwordAgainInput}
            autoComplete="new-password"
            variant="outlined"
            highlightColor="#1f7a1f"
            placeholder="Please re-enter password" 
            type={ "password" }
            value={repeatPassword}
            preventSpaces
            setValue={setRepeatPassword}
            valid={password === repeatPassword}
            disabled={!password || submitted}
            errorMessage="Passwords don't match."
            helperText="Keep this password safe. If lost, you will irretrievably lose access to all chats."
            onEnter={(e) => {
              const { value } = (e.target as HTMLInputElement);
              if (value === newPasswordInput.current.value && isPasswordValid(value)) {
                submitLocal();
              }
            }}/>
        }
        <FormControl orientation="horizontal">
          <FormLabel>Show password</FormLabel>
          <StyledJoySwitch checked={showPassword} 
            disabled={submitted}
            onChange={ (e) => setShowPassword(e?.target?.checked) }
            color={showPassword ? "success" : "neutral"}/>
        </FormControl>
        <div style={{ display: "flex", flexDirection: "column", width: "100%" }}>
          <FormControl orientation="horizontal" sx={{ width: "100%" }}>
            <FormLabel>Save password</FormLabel>
            <StyledJoySwitch checked={savePassword} 
              disabled={submitted}
              onChange={ (e) => setSavePassword(e?.target?.checked) }
              color={savePassword ? "success" : "neutral"}/>
          </FormControl>
          {savePassword &&
            <FormHelperText sx={{ width: "100%", paddingTop: "4px", justifyItems: "flex-start", textAlign: "start", color: "var(--joy-palette-danger-outlinedColor)" }}>
              Please don't use this option on a shared computer.
            </FormHelperText>}
        </div>
        <Button variant="solid"
          color="success"
          onClick={submitLocal} 
          disabled={!canSubmit}>
          <Stack direction="row" spacing={2}>
            <DisableSelectTypography textColor={ !canSubmit ? "black" : "white" }>
              { submitted ? "Creating account..." :"Sign Up" }
            </DisableSelectTypography>
            {submitted &&
              <CircularProgress size="sm" variant="soft" color="success"/>
            }
          </Stack>
        </Button>
        {failed &&
        <Alert variant="soft" color="danger" size="sm">
          <DisableSelectTypography color="danger" fontWeight="sm">Sign up failed! Please try again.</DisableSelectTypography>
        </Alert>}
      </Stack>
    </React.Fragment>
  )
}