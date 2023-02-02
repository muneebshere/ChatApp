import _ from "../node_modules/lodash";
import React, { useState, useRef, useEffect } from "../node_modules/react";
import { TextField, Sheet } from "../node_modules/@mui/joy";
import { styled } from "../node_modules/@mui/joy/styles";
import { Failure } from "../../commonTypes";

export const Item = styled(Sheet)(({ theme }) => ({
  ...theme.typography.body2,
  padding: theme.spacing(1),
  textAlign: 'center',
  color: theme.vars.palette.text.tertiary,
}));

export function ControlledTextField(args: ControlledTextFieldProps) {
  const [cursor, setCursor] = useState(0);
  const [touched, setTouched] = useState<boolean>(null);
  const [enterDown, setEnterDown] = useState(false);
  const timeoutRef = useRef<number>(null);
  const ref = useRef<HTMLInputElement>(null);
  const errorText = () => (touched || args.forceInvalid) && !args.valid && !!args.errorMessage;
  useEffect(() => ref?.current?.setSelectionRange?.(cursor, cursor), [ref, cursor, args, args.value]);

  function onChange(e: React.ChangeEvent<HTMLInputElement>) {
    e.preventDefault();
    setCursor(e.target.selectionStart);
    let newValue = e.target.value;
    if (args.preventSpaces) newValue = newValue.replace(/\s+/g, "");
    args.setValue(newValue);
    args.validate?.(newValue);
  }

  function onBlur(e: React.FocusEvent<HTMLInputElement>) {
    if (touched === false) {
      setTouched(true);
      args?.validate?.(args.value);
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
        args.onEnter?.();
      }
    }
    else {
      setEnterDown(false);
    }
  }

  return (
    <TextField variant={args.variant ?? "outlined"} 
      value={args.value} 
      ref={ref} 
      placeholder={args.placeholder} 
      type={args.type}
      error={ !args.valid && (args.forceInvalid || touched) }
      disabled={args.disabled}
      onChange={onChange}
      onBlur={onBlur}
      onFocus={onFocus}
      onKeyDown={ (e) => onKey(e, "down") }
      onKeyUp={ (e) => onKey(e, "up") }
      helperText={ errorText() ? args.errorMessage : args.helperText } sx={{ justifyItems: "flex-start", textAlign: "start" }}/>)
}

export function Spacer({ units }: { units: number }) {
  return (
    <React.Fragment>
      { (new Array(units)).fill(null).map((v, i) => <div key={i}><span>&nbsp;</span></div>) }
    </React.Fragment>
  );
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

export type ControlledTextFieldProps = {  
  label: string;
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
}