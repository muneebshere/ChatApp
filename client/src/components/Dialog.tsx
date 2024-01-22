import React, { useLayoutEffect, useRef } from "react";
import {
  useFloating,
  useDismiss,
  useRole,
  useInteractions,
  FloatingPortal,
  FloatingFocusManager,
  FloatingOverlay,
  useFloatingNodeId
} from "@floating-ui/react";
import FloatingTreeWrapper from "./FloatingTreeWrapper";

interface DialogOptions {
  outsidePress?: boolean;
  overlayBackdrop?: string;
  open: boolean;
  onDismiss?: () => void;
  keepFocusIn?: readonly [React.RefObject<HTMLElement>, React.MutableRefObject<boolean>];
  children: JSX.Element;
  forceZIndex?: number;
}

export default function Dialog({ children, open, onDismiss, outsidePress, overlayBackdrop, keepFocusIn, forceZIndex }: DialogOptions) {

  const nodeId = useFloatingNodeId();
  const data = useFloating({ nodeId, open, onOpenChange: (open) => open || onDismiss?.() });
  const context = data.context;
  const dismiss = useDismiss(context, outsidePress ? { outsidePressEvent: "mousedown" } : {});
  const role = useRole(context);

  const interactions = useInteractions([dismiss, role]);
  const mainRef = useRef<HTMLDivElement>(null);
  const [focusElement, clickedInside] = keepFocusIn || [];

  const onFocusIn = 
    clickedInside
      ? () => focusElement.current?.focus()
      : null;
  const onClick = 
    clickedInside
      ? () => clickedInside.current = false
      : null;
  const onMouseDown =
    clickedInside
      ? () => {
                clickedInside.current = true;
                focusElement.current?.focus();
              }
      : null;

  useLayoutEffect(() => {
    if (keepFocusIn) {
      focusElement.current?.focus();
      return () => {
      mainRef.current?.removeEventListener("mousedown", onMouseDown, { capture: true });
      mainRef.current?.removeEventListener("click", onClick, { capture: true });
      mainRef.current?.removeEventListener("focusin", onFocusIn, { capture: true });
    }
  }
  }, []);

  return (
    <FloatingTreeWrapper open={open}>
      {(zIndex) => (
        <FloatingPortal>
        <FloatingOverlay className="Dialog-overlay" 
          ref={(elem) => {
            if (!keepFocusIn) return;
            elem?.addEventListener("mousedown", onMouseDown, { capture: true });
            elem?.addEventListener("click", onClick, { capture: true });
            elem?.addEventListener("focusin", onFocusIn, { capture: true });
            mainRef.current = elem;
          }}
          lockScroll
          style={{ backdropFilter: overlayBackdrop, zIndex: forceZIndex || zIndex }}
          onClick={ outsidePress ? onDismiss : undefined }>
          <FloatingFocusManager context={context} returnFocus={true} initialFocus={focusElement}>
            <div
              {...interactions.getFloatingProps({} as React.HTMLProps<HTMLDivElement>)}
              style={{
                position: "absolute",
                top: "0px",
                bottom: "0px",
                left: "0px",
                right: "0px",
                display: "flex", 
                justifyContent: "center", 
                alignItems: "center" }}>
              <div
                style={{
                  height: "fit-content",
                  width: "fit-content",
                  display: "flex", 
                  justifyContent: "center", 
                  alignItems: "center" }}
                onClick={ outsidePress 
                  ? (e) => {
                    e.stopPropagation();
                    return false;
                  }
                  : undefined }>
                {children}
              </div>
            </div>
          </FloatingFocusManager>
        </FloatingOverlay>
      </FloatingPortal>)}
    </FloatingTreeWrapper>);
}