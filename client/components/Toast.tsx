import React, { useState, useEffect, useRef, useId } from "react";
import { useFloating, FloatingFocusManager } from "@floating-ui/react";

type ToastProps = Readonly<{
    trigger: { off?: boolean },
    children: JSX.Element,
    duration?: number,
    containerStyle?: React.CSSProperties
}>;

export default function Toast({ children, trigger, duration = 2000, containerStyle = {} }: ToastProps) {
  const [isOpen, setIsOpen] = useState(false);
  const { refs, floatingStyles, context } = useFloating({ open: isOpen, onOpenChange: setIsOpen });
  const timeoutRef = useRef<number | null>(null);
  const id = useId();

  useEffect(() => {
    setIsOpen(false);
    if (!trigger.off) {
      setTimeout(() => setIsOpen(true), 100);
      window.clearTimeout(timeoutRef.current!);
      timeoutRef.current = window.setTimeout(() => setIsOpen(false), duration);
    }
  }, [trigger]);

  return (
    <>
      {isOpen && (
        <FloatingFocusManager key={id} context={context} modal={false} initialFocus={-1}>
          <div
            className="Toast"
            ref={refs.setFloating}
            tabIndex={-1}
            style={{ ...floatingStyles, ...containerStyle, zIndex: 8 }}>
            {children}
          </div>
        </FloatingFocusManager>
      )}
    </>
  );
}