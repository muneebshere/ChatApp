import _ from "lodash";
import React, { useState, useRef, useEffect, memo } from "react";
import { Sheet, FormControl, FormLabel, FormHelperText, Input, Switch, Textarea as JoyTextarea, Modal, ModalClose, Typography } from "@mui/joy";
import { styled as joyStyled } from "@mui/joy/styles";
import styled from "@emotion/styled";
import { Failure } from "../../../shared/commonTypes";
import { Theme, useMediaQuery } from "@mui/material";
import { Dialog, DialogContent } from "./Dialog";
import { CloseSharp } from "@mui/icons-material";

export const Item = joyStyled(Sheet)(({ theme }) => ({
  ...theme.typography.body2,
  padding: theme.spacing(1),
  textAlign: 'center',
  color: theme.vars.palette.text.tertiary,
}));

export const StyledSwitch = styled(Switch)`
  input {
    top: 0px;
    left: 0px;
  }`;

export const StyledScrollbar = styled(Item)`
  flex: 1; 
  flex-basis: 0;
  max-height: 100%; 
  overflow-x: clip;
  overflow-y: scroll;
  scroll-behavior: auto !important;
  scrollbar-width: thin;
  scrollbar-color: #afafaf #d1d1d1;

  ::-webkit-scrollbar {
    width: 6px;
  }

  ::-webkit-scrollbar-track {
    background-color: #d1d1d1;
    border-radius: 5px;
    border: 2px solid transparent;
    background-clip: padding-box;
    &:hover {
      border: none 0px;
    }
  }

  ::-webkit-scrollbar-thumb {
    background-color: #afafaf;
    border-radius: 5px;
    box-shadow: inset 0px 0px 5px rgba(0,0,0,0.7);
}`;

export function ControlledTextField(args: ControlledTextFieldProps) {
  const { placeholder, setValue, type, valid, value, disabled, errorMessage, forceInvalid, helperText, label, onEnter, preventSpaces, validate, variant, autoComplete, role } = args;
  const [cursor, setCursor] = useState(0);
  const [touched, setTouched] = useState<boolean>(null);
  const [enterDown, setEnterDown] = useState(false);
  const timeoutRef = useRef<number>(null);
  const ref = useRef<HTMLInputElement>(null);
  const errorText = () => (touched || forceInvalid) && !valid && !!errorMessage;
  useEffect(() => ref?.current?.setSelectionRange?.(cursor, cursor), [ref, cursor, args, value]);

  function onChange(e: React.ChangeEvent<HTMLInputElement>) {
    e.preventDefault();
    setCursor(e.target.selectionStart);
    let newValue = e.target.value;
    if (preventSpaces) newValue = newValue.replace(/\s+/g, "");
    setValue(newValue);
    validate?.(newValue);
  }

  function onBlur(e: React.FocusEvent<HTMLInputElement>) {
    if (touched === false) {
      setTouched(true);
      args?.validate?.(value);
    }
  }

  function onFocus(e: React.FocusEvent<HTMLInputElement>) {
    if (touched === null) setTouched(false);
  }

  function onKey(e: React.KeyboardEvent<HTMLDivElement>, type: "up" | "down") {
    if (timeoutRef.current !== null) {
      window.clearTimeout(timeoutRef.current);
      timeoutRef.current = null;
    }
    if (!e.altKey && !e.ctrlKey && !e.shiftKey && e.key === "Enter") {
      if (type === "down") {
        setEnterDown(true);
        timeoutRef.current = window.setTimeout(() => setEnterDown(false), 200);
      }
      else if (enterDown) {
        onEnter?.();
      }
    }
    else {
      setEnterDown(false);
    }
  }

  return (
    <FormControl sx={{ justifyContent: "stretch", width: "100%" }}>
      {label && 
      <FormLabel sx={{ flexGrow: 1, width: "100%" }}>
        {label}
      </FormLabel>}
      <Input
        ref={ref} 
        autoComplete={autoComplete}
        role={role}
        variant={variant}
        type={type}
        placeholder={placeholder}
        value={value}
        error={ !valid && (forceInvalid || touched) }
        disabled={disabled}
        onChange={onChange}
        onBlur={onBlur}
        onFocus={onFocus}
        onKeyDown={ (e) => onKey(e, "down") }
        onKeyUp={ (e) => onKey(e, "up") }
        sx={{ width: "100%" }}/>
      {(errorText() || helperText) &&
      <FormHelperText sx={{ justifyItems: "flex-start", textAlign: "start", color: !valid && (forceInvalid || touched) ? "var(--joy-palette-danger-outlinedColor)" : "neutral" }}>
        { errorText() ? errorMessage : helperText }
      </FormHelperText>}
    </FormControl>)
}

export function Spacer({ units }: { units: number }) {
  return (
    <React.Fragment>
      { (new Array(units)).fill(null).map((v, i) => <div key={i}><span>&nbsp;</span></div>) }
    </React.Fragment>
  );
}

export function WarnSavePassword_({ open, setWarned }: WarnSavePasswordProps) {  
  const belowXL = useMediaQuery((theme: Theme) => theme.breakpoints.down("xl"));

  return (
    <Modal
      open={open}
      onClose={() => setWarned(true)}
      disableAutoFocus
      sx={{ display: "flex", justifyContent: "center", alignItems: "center" }}>
      <Sheet
        variant="outlined"
        sx={{
          width: belowXL ? "90vw" : "40vw",
          borderRadius: "md",
          p: 3,
          boxShadow: "lg"}}>
        <ModalClose
          variant="outlined"
          sx={{
            top: "calc(-1/4 * var(--IconButton-size))",
            right: "calc(-1/4 * var(--IconButton-size))",
            boxShadow: "0 2px 12px 0 rgba(0 0 0 / 0.2)",
            borderRadius: "50%",
            bgcolor: "background.body"}}/>
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
    </Modal>);
}

const CloseButton = styled.button`
  all: unset;
  position: absolute;
  top: -12px;
  right: -12px;
  width: 26px;
  height: 34px;
  padding-inline: 4px;
  padding-block: 0px;
  box-shadow: 0px 2px 12px 0px rgba(0, 0, 0, 0.2);
  border: 0.8px solid rgb(185, 185, 198);
  border-radius: 50%;
  background-color: #ebebef;

  &:hover {
    color: #131318;
    background-color: rgb(216, 216, 223);#ebebef;
    border-color: #b9b9c6;
  }`;

export function WarnSavePassword({ open, setWarned }: WarnSavePasswordProps) {  
  const belowXL = useMediaQuery((theme: Theme) => theme.breakpoints.down("xl"));

  return (
    <Dialog 
      outsidePress
      overlayBackdrop="opacity(100%) blur(4px)"
      controlledOpen={open} 
      setControlledOpen={(open) => { 
        if (!open) {
          setWarned(true);
        }
      }}>
      <DialogContent>
        <Sheet
          variant="outlined"
          sx={{
            width: belowXL ? "90vw" : "40vw",
            borderRadius: "md",
            p: 3,
            boxShadow: "lg"}}>
          <CloseButton style={{ display: "grid", placeItems: "center" }} 
            onClick={ () => setWarned(true) }>
            <CloseSharp sx={{ fontSize: "1.5rem" }}/>
          </CloseButton>
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
      </DialogContent>
    </Dialog>);
}

export type SubmitResponse = {
  displayName?: string;
  username: string;
  password: string;
  savePassword: boolean;
}

export type SubmitProps = {
  usernameExists: (username: string) => Promise<boolean>;
  submit: (response: SubmitResponse) => Promise<Failure>;
}

type UsernameExists = {
  usernameExists: (username: string) => Promise<boolean>;
}

type ControlledTextFieldProps = {  
  label?: string;
  placeholder: string;
  type: string;
  value: string;
  setValue: (value: string) => void;
  valid: boolean;
  variant?: "plain" | "outlined" | "soft" | "solid";
  helperText?: string;
  validate?: (value: string) => void;
  onEnter?: () => void;
  forceInvalid?: boolean;
  disabled?: boolean;
  errorMessage?: string;
  preventSpaces?: boolean;
  autoComplete?: string;
  role?: React.AriaRole;
}

type WarnSavePasswordProps = {
  open: boolean,
  setWarned: (warned: boolean) => void
}

export const StyledJoyTextarea = styled(JoyTextarea)`

  padding: 0px;
  border-radius: 0px;
  border: 0px none;
  outline: 0px none;
  min-height: fit-content;

  &::before {
    box-shadow: none !important;
  }

  textarea {
    overflow-x: clip;
    overflow-y: scroll;
    scroll-behavior: auto !important;
    scrollbar-width: thin;
    scrollbar-color: #afafaf #d1d1d1;

    ::-webkit-scrollbar {
      width: 3px;
    }

    ::-webkit-scrollbar-track {
      background-color: #d1d1d1;
      border-radius: 4px;
    }

    ::-webkit-scrollbar-thumb {
      background-color: #7c7c7c;
      border-radius: 4px;
    }
  }`;