import _ from "lodash";
import React, { useState, useRef, useEffect } from "react";
import { FormControl, FormLabel, FormHelperText, Input  } from "@mui/joy";

export type ControlledTextFieldProps = {  
  label?: string;
  placeholder: string;
  type: string;
  defaultValue?: string;
  value: string;
  setValue: (value: string) => void;
  valid: boolean;
  variant?: "plain" | "outlined" | "soft" | "solid";
  helperText?: string;
  onEnter?: () => void;
  forceInvalid?: boolean;
  disabled?: boolean;
  errorMessage?: string;
  preventSpaces?: boolean;
  autoComplete?: string;
  role?: React.AriaRole;
  autoFocus?: boolean;
} & React.HTMLProps<HTMLInputElement>

export default function ControlledTextField(args: ControlledTextFieldProps) {
  const { placeholder, setValue, type, valid, defaultValue, value, disabled, errorMessage, forceInvalid, helperText, label, onEnter, preventSpaces, variant, autoComplete, role, autoFocus } = args;
  const [cursor, setCursor] = useState(0);
  const [touched, setTouched] = useState<boolean>(null);
  const [enterDown, setEnterDown] = useState(false);
  const timeoutRef = useRef<number>(null);
  const ref = useRef<HTMLInputElement>(null);
  const errorText = () => (touched || forceInvalid) && !valid && !!errorMessage;
  useEffect(() => ref?.current?.setSelectionRange?.(cursor, cursor), [ref, cursor, args, value]);

  function onChange(e: React.ChangeEvent<HTMLInputElement>) {
    e.preventDefault();
    setCursor(e?.target?.selectionStart || 0);
    let newValue = e?.target?.value || "";
    if (preventSpaces) newValue = newValue.replace(/\s+/g, "");
    setValue(newValue);
  }

  function onBlur(e: React.FocusEvent<HTMLInputElement>) {
    if (!e) return;
    if (touched === false) {
      setTouched(true);
      if (!e.target?.value) {
        setValue("\u2060");
        setValue("");
      }
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
        autoFocus={autoFocus}
        role={role}
        variant={variant}
        type={type}
        placeholder={placeholder}
        defaultValue={defaultValue}
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