import _ from "lodash";
import React, { useState, useRef, useEffect } from "react";
import { Sheet, FormControl, FormLabel, FormHelperText, Input } from "@mui/joy";
import { styled } from "@mui/joy/styles";
import { Failure } from "../../../shared/commonTypes";

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
    <FormControl>
      <FormLabel>
        <Input
          ref={ref} 
          variant={args.variant}
          type={args.type}
          placeholder={args.placeholder}
          value={args.value}
          error={ !args.valid && (args.forceInvalid || touched) }
          disabled={args.disabled}
          onChange={onChange}
          onBlur={onBlur}
          onFocus={onFocus}
          onKeyDown={ (e) => onKey(e, "down") }
          onKeyUp={ (e) => onKey(e, "up") }/>
      </FormLabel>
      {(errorText() || args.helperText) &&
      <FormHelperText sx={{ justifyItems: "flex-start", textAlign: "start" }}>{ errorText() ? args.errorMessage : args.helperText }
        { errorText() ? args.errorMessage : args.helperText };
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