import _ from "lodash";
import React, { useState, useRef, useEffect, memo } from "react";
import { Sheet, FormControl, FormLabel, FormHelperText, Input, Switch } from "@mui/joy";
import { styled as joyStyled } from "@mui/joy/styles";
import styled from "@emotion/styled";

import { Failure } from "../../../shared/commonTypes";

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
    width: 10px;
  }

  ::-webkit-scrollbar-track {
    background-color: #d1d1d1;
    border-radius: 5px;
    border: 5px solid transparent;
    background-clip: padding-box;
    &:hover {
      border: none 0px;
    }
  }

  ::-webkit-scrollbar-thumb {
    background-color: #afafaf;
    border-radius: 5px;
    box-shadow: inset 0px 0px 5px rgba(0,0,0,0.7);
}

  ::-webkit-scrollbar-button:single-button:vertical:decrement {
    height: 10px;
    width: 10px;
    background-repeat: no-repeat;
    background-size: contain;
    background-image: url("data:image/svg+xml;base64,PHN2ZyB4bWxucz0naHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmcnIHN0cm9rZT0nIzZhNmE2YScgZmlsbD0nIzZhNmE2YScgdmlld0JveD0nMCAwIDI0IDI0Jz48cGF0aCBkPSdNMyAxOWgxOGExLjAwMiAxLjAwMiAwIDAgMCAuODIzLTEuNTY5bC05LTEzYy0uMzczLS41MzktMS4yNzEtLjUzOS0xLjY0NSAwbC05IDEzQS45OTkuOTk5IDAgMCAwIDMgMTl6Jz48L3BhdGg+PC9zdmc+");
  }

  ::-webkit-scrollbar-button:single-button:vertical:increment {
    height: 10px;
    width: 10px;
    background-repeat: no-repeat;
    background-size: contain;
    background-image: url("data:image/svg+xml;base64,PHN2ZyB4bWxucz0naHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmcnIHN0cm9rZT0nIzZhNmE2YScgZmlsbD0nIzZhNmE2YScgdmlld0JveD0nMCAwIDI0IDI0Jz48cGF0aCBkPSdNMTEuMTc4IDE5LjU2OWEuOTk4Ljk5OCAwIDAgMCAxLjY0NCAwbDktMTNBLjk5OS45OTkgMCAwIDAgMjEgNUgzYTEuMDAyIDEuMDAyIDAgMCAwLS44MjIgMS41NjlsOSAxM3onPjwvcGF0aD48L3N2Zz4=");
  }`;

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
    <FormControl sx={{ justifyContent: "stretch" }}>
      <FormLabel sx={{ flexGrow: 1, width: "100%" }}>
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
          onKeyUp={ (e) => onKey(e, "up") }
          sx={{ width: "100%" }}/>
      </FormLabel>
      {(errorText() || args.helperText) &&
      <FormHelperText sx={{ justifyItems: "flex-start", textAlign: "start", color: !args.valid && (args.forceInvalid || touched) ? "var(--joy-palette-danger-outlinedColor)" : "neutral" }}>
        { errorText() ? args.errorMessage : args.helperText }
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

export type TextareaProps = {
  rows: number,
  onTextChange: (text: string, width: number) => Promise<void>,
  scrollOn: boolean
}

export const Textarea = memo(NonMemoTextarea, 
  ({ rows: prevRows, scrollOn: prevScroll }, { rows: nextRows, scrollOn: nextScroll }) => prevRows === nextRows && prevScroll === nextScroll);

export const StyledTextarea = styled.textarea`
  border-radius: 0px;
  border: 0px none;
  flex: 1; 
  flex-basis: 0;
  max-height: 100%; 
  overflow-x: clip;
  overflow-y: scroll;
  scroll-behavior: auto !important;
  scrollbar-width: thin;
  scrollbar-color: #afafaf #d1d1d1;

  &:focus {
    outline: 0px none;
  }

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
  }`;

function NonMemoTextarea({ rows, scrollOn, onTextChange }: TextareaProps) {

  function onChange(e: React.ChangeEvent<HTMLTextAreaElement>) {
    const element = e.target;
    onTextChange(element.value, element.clientWidth);
  }

  return(<StyledTextarea
            placeholder="Type a message"
            rows={rows}
            onChange={onChange}
            style={{ resize: "none", fontFamily: "Public Sans", fontSize: "1rem", overflowY: scrollOn ? "scroll" : "clip" }}
        />)
}