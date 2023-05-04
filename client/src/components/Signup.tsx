import _ from "lodash";
import { match } from "ts-pattern";
import React, { createContext, Dispatch, useCallback, useContext, useEffect, useState } from "react";
import { FormControl, FormLabel, Stack, Button, CircularProgress, Alert } from "@mui/joy";
import { SubmitResponse } from "../App";
import { DisableSelectTypography, StyledJoySwitch } from "./CommonElementStyles";
import WarnSavePassword from "./WarnSavePassword";
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
  readonly warned: boolean;
  readonly usernameExists: (username: string) => Promise<boolean>;
  readonly submit: (response: SubmitResponse) => Promise<Failure>;
}

type SignUpAction<K extends keyof SignUpData> = {
  id: K;
  value: SignUpData[K];
}

type SignUpDataReducer = (data: SignUpData, action: SignUpAction<keyof SignUpData>) => SignUpData;

type SignUpContextType = {
  signUpData: SignUpData,
  signUpDispatch: Dispatch<SignUpAction<keyof SignUpData>>;
}

export function signUpAction<K extends keyof SignUpData>(id: K, value: SignUpData[K]): SignUpAction<K> {
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
  failed: false,
  warned: false
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
    .with("warned", () => ({ ...data, warned: value as boolean }))
    .otherwise(() => data);    
}

export const SignUpContext = createContext<SignUpContextType>(null);

export default function SignUpForm() {
  const { signUpData: { displayName, username, password, repeatPassword, showPassword, savePassword, failed, submitted, warned, usernameExists, submit }, signUpDispatch } = useContext(SignUpContext);
  const [usernameError, setUsernameError] = useState("");
  const setDisplayName = (displayName: string) => signUpDispatch(signUpAction("displayName", displayName));
  const setUsername = (username: string) => signUpDispatch(signUpAction("username", username));
  const setPassword = (password: string) => signUpDispatch(signUpAction("password", password));
  const setRepeatPassword = (repeatPassword: string) => signUpDispatch(signUpAction("repeatPassword", repeatPassword));
  const setShowPassword = (showPassword: boolean) => signUpDispatch(signUpAction("showPassword", showPassword));
  const setSavePassword = (savePassword: boolean) => signUpDispatch(signUpAction("savePassword", savePassword));
  const setFailed = (failed: boolean) => signUpDispatch(signUpAction("failed", failed));
  const setSubmitted = (submitted: boolean) => signUpDispatch(signUpAction("submitted", submitted));
  const setWarned = (warned: boolean) => signUpDispatch(signUpAction("warned", warned));
  const canSubmit = !submitted && !usernameError && validatePassword(password) && (showPassword || password === repeatPassword);

  validateUsername(username).then((error) => setUsernameError(error));

  async function validateUsername(username: string): Promise<string> {
    if (username.match(/^[a-z][a-z0-9_]{2,14}$/) === null) {
      return "Username may contain only lowercase letters, digits and underscores, must start with a letter, and must be between 3 and 15 characters.";
    }
    else {
      return (await usernameExists(username)) ? "Username already exists." : "";
    }
  }

  function validatePassword(password: string): boolean {
    return password.match(/^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$/) !== null;
  }

  async function submitLocal() {
    if (!canSubmit) return;
    setFailed(false);
    setSubmitted(true);
    const { reason } = await submit({ displayName, username, password, savePassword });
    if (reason) {
      setFailed(true);
    }
    setSubmitted(false);
  }

  return(
    <React.Fragment>
      <Stack spacing={2}>
        <ControlledTextField 
          variant="outlined"
          placeholder="Display Name (Optional)" 
          type="text"
          value={displayName}
          setValue={setDisplayName}
          valid={true}
          disabled={submitted}
          helperText="If you don't specify a display name, your username will be used as your display name."
          onEnter={submitLocal}/>
        <ControlledTextField 
          variant="outlined"
          placeholder="Please choose a unique username" 
          type="text"
          value={username}
          preventSpaces
          setValue={setUsername}
          valid={!usernameError}
          disabled={submitted}
          errorMessage={usernameError}
          onEnter={submitLocal}/>
        <ControlledTextField 
          autoComplete="new-password"
          variant="outlined"
          placeholder="Please choose a new password" 
          type={ showPassword ? "text" : "password" }
          value={password}
          preventSpaces
          setValue={setPassword}
          valid={validatePassword(password)}
          disabled={submitted}
          errorMessage={`Please choose a password at least 8 characters long, with at least one uppercase letter, one lowercase letter, one digit and one special character (#?!@$%^&*-]).${showPassword ? "\nKeep this password safe. If lost, you will irretrievably lose access to all chats.": ""}`}
          helperText={showPassword ? "Keep this password safe. If lost, you will irretrievably lose access to all chats." : undefined}
          onEnter={submitLocal}/>
        {!showPassword &&
          <ControlledTextField 
            autoComplete="new-password"
            variant="outlined"
            placeholder="Please re-enter password" 
            type={ "password" }
            value={repeatPassword}
            preventSpaces
            setValue={setRepeatPassword}
            valid={password === repeatPassword}
            disabled={!password || submitted}
            errorMessage="Passwords don't match."
            helperText="Keep this password safe. If lost, you will irretrievably lose access to all chats."
            onEnter={submitLocal}/>
        }
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
        <Button variant="solid"
          onClick={submitLocal} 
          disabled={!canSubmit}>
          <Stack direction="row" spacing={2}>
            <DisableSelectTypography textColor={ !canSubmit ? "black" : "white" }>
              { submitted ? "Creating account..." :"Sign Up" }
            </DisableSelectTypography>
            {submitted &&
              <CircularProgress size="sm" variant="soft"/>
            }
          </Stack>
        </Button>
        {failed &&
        <Alert variant="soft" color="danger" size="sm">
          <DisableSelectTypography color="danger" fontWeight="sm">Sign up failed! Please try again.</DisableSelectTypography>
        </Alert>}
      </Stack>
      <WarnSavePassword open={savePassword && !warned} setWarned={setWarned}/>
    </React.Fragment>
  )
}