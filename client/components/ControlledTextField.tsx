import _ from "lodash";
import React, { useState, useRef, useEffect, forwardRef } from "react";
import { FormControl, FormLabel, FormHelperText, Input  } from "@mui/joy";
import { SxProps } from "@mui/material";

export type ControlledTextFieldProps = {
  label?: string;
  placeholder: string;
  type: string;
  defaultValue?: string;
  value: string;
  setValue: (value: string) => void;
  valid: boolean;
  variant?: "plain" | "outlined" | "soft" | "solid";
  joyColor?: "primary" | "neutral" | "success" | "warning" | "danger";
  helperText?: string;
  onEnter?: (e: React.KeyboardEvent<HTMLInputElement>) => void;
  forceInvalid?: boolean;
  disabled?: boolean;
  errorMessage?: string;
  preventSpaces?: boolean;
  autoComplete?: string;
  role?: React.AriaRole;
  autoFocus?: boolean;
  forceFocus?: boolean;
  sx?: SxProps;
  highlightColor?: string
} & React.HTMLProps<HTMLInputElement>

export default forwardRef(function(args: ControlledTextFieldProps, ref: React.ForwardedRef<HTMLInputElement>) {
  const { placeholder, setValue, type, valid, defaultValue, value, disabled, errorMessage, forceInvalid, helperText, label, onEnter, preventSpaces, variant, autoComplete, role, autoFocus, forceFocus, joyColor, highlightColor, sx } = args;
  const [cursor, setCursor] = useState(0);
  const [touched, setTouched] = useState<boolean | null>(null);
  const enterRef = useRef(false);
  const timeoutRef = useRef<number | null>(null);
  const errorText = () => (touched || forceInvalid) && !valid && !!errorMessage;
  const localRef = useRef<HTMLInputElement | null>(null);
  useEffect(() => localRef.current?.setSelectionRange?.(cursor, cursor), [cursor, args, value]);

  function onChange(e: React.ChangeEvent<HTMLInputElement>) {
    e.preventDefault();
    let currentCursor = e?.target?.selectionStart || 0;
    const oldValue = e?.target?.value || "";
    let newValue = oldValue;
    if (preventSpaces) newValue = newValue.replace(/\s+/g, "");
    if (currentCursor && newValue !== oldValue) currentCursor -= 1;
    setCursor(currentCursor);
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
    if (forceFocus) e.target?.focus();
  }

  function onFocus(e: React.FocusEvent<HTMLInputElement>) {
    if (touched === null) setTouched(false);
  }

  function onKey(e: React.KeyboardEvent<HTMLInputElement>, type: "up" | "down") {
    if (timeoutRef.current !== null) {
      window.clearTimeout(timeoutRef.current);
      timeoutRef.current = null;
    }
    if (type === "down" && e.key === "Enter" && !e.altKey && !e.ctrlKey && !e.shiftKey) {
      e.stopPropagation();
      enterRef.current = true;
      timeoutRef.current = window.setTimeout(() => enterRef.current = false, 400);
    }
    else if (type === "up" && enterRef.current && e.key === "Enter" && !e.altKey && !e.ctrlKey && !e.shiftKey) {
      e.stopPropagation();
      onEnter?.(e);
      enterRef.current = false;
    }
    else enterRef.current = false;
  }

  return (
    <FormControl sx={{ justifyContent: "stretch", width: "100%" }}>
      {label &&
      <FormLabel sx={{ flexGrow: 1, width: "100%" }}>
        {label}
      </FormLabel>}
      <Input
        ref={(elem: any) => {
          const inputElement = elem?.querySelector("input");
          localRef.current = inputElement;
          if (!ref) return;
          if (typeof ref === "function") ref(inputElement);
          else ref.current = inputElement;
        }}
        autoComplete={autoComplete}
        autoFocus={autoFocus}
        role={role}
        variant={variant}
        color={joyColor}
        type={type}
        placeholder={placeholder}
        defaultValue={defaultValue}
        value={value}
        error={ !valid && (forceInvalid || touched) || false }
        disabled={disabled}
        onChange={onChange}
        onBlur={onBlur}
        onFocus={onFocus}
        onKeyDown={ onEnter ? ((e) => onKey(e, "down")) : undefined }
        onKeyUp={ onEnter ? ((e) => onKey(e, "up")) : undefined }
        sx={{ ...sx, width: "100%", "&::before": highlightColor ? { "--Input-focusedHighlight": highlightColor } : undefined }}/>
      {(errorText() || helperText) &&
      <FormHelperText sx={{ justifyItems: "flex-start", textAlign: "start", color: !valid && (forceInvalid || touched) ? "var(--joy-palette-danger-outlinedColor)" : "neutral" }}>
        { errorText() ? errorMessage : helperText }
      </FormHelperText>}
    </FormControl>)
})