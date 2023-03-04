import _ from "lodash";
import { SubmitProps, ControlledTextField, SubmitResponse, StyledSwitch } from "./Common";
import React, { useState, useEffect, createContext, useReducer, Dispatch, useContext } from "react";
import {  } from "@mui/material";
import { FormControl, FormLabel, Stack, Button, CircularProgress, Modal, ModalClose, Sheet, Typography, Alert } from "@mui/joy";
import { Failure } from "../../../shared/commonTypes";
import { match } from "ts-pattern";

type SignUpData = {
  readonly displayName: string;
  readonly username: string;
  readonly usernameValid: boolean;
  readonly usernameError: string;
  readonly password: string;
  readonly passwordValid: boolean;
  readonly repeatPassword: string;
  readonly repeatPasswordValid: boolean;
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
  usernameValid: false,
  usernameError: "",
  password: "",
  passwordValid: false,
  repeatPassword: "",
  repeatPasswordValid: false,
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
    .with("usernameValid", () => ({ ...data, usernameValid: value as boolean }))
    .with("usernameError", () => ({ ...data, usernameError: value as string }))
    .with("password", () => ({ ...data, password: value as string }))
    .with("passwordValid", () => ({ ...data, passwordValid: value as boolean }))
    .with("repeatPassword", () => ({ ...data, repeatPassword: value as string }))
    .with("repeatPasswordValid", () => ({ ...data, repeatPasswordValid: value as boolean }))
    .with("showPassword", () => ({ ...data, showPassword: value as boolean }))
    .with("savePassword", () => ({ ...data, savePassword: value as boolean }))
    .with("submitted", () => ({ ...data, submitted: value as boolean }))
    .with("failed", () => ({ ...data, failed: value as boolean }))
    .with("warned", () => ({ ...data, warned: value as boolean }))
    .otherwise(() => data);    
}

export const SignUpContext = createContext<SignUpContextType>(null);

export default function SignUpForm() {
  const { signUpData: { displayName, username, usernameValid, usernameError, password, passwordValid, repeatPassword, repeatPasswordValid, showPassword, savePassword, failed, submitted, warned, usernameExists, submit }, signUpDispatch } = useContext(SignUpContext);
  const setDisplayName = (displayName: string) => signUpDispatch(signUpAction("displayName", displayName));
  const setUsername = (username: string) => signUpDispatch(signUpAction("username", username));
  const setUsernameValid = (usernameValid: boolean) => signUpDispatch(signUpAction("usernameValid", usernameValid));
  const setUsernameError = (usernameError: string) => signUpDispatch(signUpAction("usernameError", usernameError));
  const setPassword = (password: string) => signUpDispatch(signUpAction("password", password));
  const setPasswordValid = (passwordValid: boolean) => signUpDispatch(signUpAction("passwordValid", passwordValid));
  const setRepeatPassword = (repeatPassword: string) => signUpDispatch(signUpAction("repeatPassword", repeatPassword));
  const setRepeatPasswordValid = (repeatPasswordValid: boolean) => signUpDispatch(signUpAction("repeatPasswordValid", repeatPasswordValid));
  const setShowPassword = (showPassword: boolean) => signUpDispatch(signUpAction("showPassword", showPassword));
  const setSavePassword = (savePassword: boolean) => signUpDispatch(signUpAction("savePassword", savePassword));
  const setFailed = (failed: boolean) => signUpDispatch(signUpAction("failed", failed));
  const setSubmitted = (submitted: boolean) => signUpDispatch(signUpAction("submitted", submitted));
  const setWarned = (warned: boolean) => signUpDispatch(signUpAction("warned", warned));

  function validateUserName(username: string): void {
    if (username.match(/^[a-z][a-z0-9_]{2,14}$/) === null) {
      setUsernameValid(false);
      setUsernameError("Username may contain only lowercase letters, digits and underscores, must start with a letter, and must be between 3 and 15 characters.");
    }
    else {
      setUsernameValid(true);
      setUsernameError("");
      usernameExists(username).then((exists) => {
        if (exists) {
          setUsernameValid(false);
          setUsernameError("Username already exists.");
        }
      }).catch(() => {});
    }
  }

  function validatePassword(password: string): void {
    setPasswordValid(password.match(/^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$/) !== null);
    setRepeatPasswordValid(password === repeatPassword);
  }

  function validateRepeatPassword(repeatPassword: string): void {
    setRepeatPasswordValid(repeatPassword === password);
  }

  async function submitLocal() {
    if (submitted || !usernameValid || !passwordValid || !repeatPasswordValid) return;
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
          validate={validateUserName}
          valid={usernameValid}
          disabled={submitted}
          errorMessage={usernameError}
          onEnter={submitLocal}/>
        <ControlledTextField 
          variant="outlined"
          placeholder="Please choose a new password" 
          type={ showPassword ? "text" : "password" }
          value={password}
          preventSpaces
          setValue={setPassword}
          validate={validatePassword}
          valid={passwordValid}
          disabled={submitted}
          errorMessage="Please choose a password at least 8 characters long, with at least one uppercase letter, one lowercase letter, one digit and one special character (#?!@$%^&*-])."
          onEnter={submitLocal}/>
        <ControlledTextField 
          variant="outlined"
          placeholder="Please re-enter password" 
          type={ showPassword ? "text" : "password" }
          value={repeatPassword}
          preventSpaces
          setValue={setRepeatPassword}
          validate={validateRepeatPassword}
          valid={repeatPasswordValid}
          disabled={!password || submitted}
          errorMessage="Passwords don't match."
          helperText="Keep this password safe. If lost, you will irretrievably lose access to all chats."
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
        <Button variant="solid"
          onClick={submitLocal} 
          disabled={!usernameValid || !passwordValid || !repeatPasswordValid || submitted }>
          <Stack direction="row" spacing={2}>
            <Typography textColor={ !usernameValid || !passwordValid || !repeatPasswordValid || submitted ? "black" : "white" }>
              { submitted ? "Creating account..." :"Sign Up" }
            </Typography>
            {submitted &&
              <CircularProgress size="sm" variant="soft"/>
            }
          </Stack>
        </Button>
        {failed &&
        <Alert variant="soft" color="danger" size="sm">
          <Typography color="danger" fontWeight="sm">Sign up failed! Please try again.</Typography>
        </Alert>}
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
  )
}