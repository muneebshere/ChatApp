import React, { ButtonHTMLAttributes, Dispatch, HTMLProps, ReactNode, SetStateAction, cloneElement, createContext, forwardRef, isValidElement, useContext, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import {
  useFloating,
  useClick,
  useDismiss,
  useRole,
  useInteractions,
  useMergeRefs,
  FloatingPortal,
  FloatingFocusManager,
  FloatingOverlay,
  useId
} from "@floating-ui/react";

interface DialogOptions {
  outsidePress?: boolean;
  overlayBackdrop?: string;
  controlledOpen?: boolean;
  setControlledOpen?: (open: boolean) => void;
  changeOpenTo?: boolean;
  notifyChange?: (open: boolean) => void;
  keepFocusIn?: readonly [React.RefObject<HTMLElement>, React.MutableRefObject<boolean>];
}

export function useDialog({
    controlledOpen,
    setControlledOpen,
    changeOpenTo,
    notifyChange,
    outsidePress,
    overlayBackdrop,
    keepFocusIn
}: DialogOptions = {}) {
  const [uncontrolledOpen, setUncontrolledOpen] = useState(!!changeOpenTo);
  const [labelId, setLabelId] = useState<string | undefined>();
  const [descriptionId, setDescriptionId] = useState<
    string | undefined
  >();

  const controlled = controlledOpen !== undefined;
  let open: boolean;
  let setOpen: (open: boolean) => void;

  if (controlled && setControlledOpen) {
    open = controlledOpen;
    setOpen = setControlledOpen;
  }
  else {
    setOpen = notifyChange 
              ? (open) => {
                notifyChange(open);
                setUncontrolledOpen(open);
              }
              : setUncontrolledOpen;
    open = uncontrolledOpen;
  }

  useEffect(() => {
    if (!controlled && changeOpenTo !== undefined) {
      setUncontrolledOpen(changeOpenTo);
    }
  }, [changeOpenTo]);

  const data = useFloating({
    open,
    onOpenChange: setOpen
  });

  const context = data.context;

  const click = useClick(context, {
    enabled: !controlled
  });
  const dismiss = useDismiss(context, outsidePress ? { outsidePressEvent: "mousedown" } : {});
  const role = useRole(context);

  const interactions = useInteractions([click, dismiss, role]);

  return useMemo(
    () => ({
      open,
      setOpen,
      ...interactions,
      ...data,
      labelId,
      descriptionId,
      setLabelId,
      setDescriptionId,
      outsidePress,
      overlayBackdrop,
      keepFocusIn
    }),
    [open, setOpen, outsidePress, interactions, data, labelId, descriptionId, keepFocusIn]
  );
}

type ContextType =
  | (ReturnType<typeof useDialog> & {
      setLabelId: Dispatch<SetStateAction<string | undefined>>;
      setDescriptionId: Dispatch<
        SetStateAction<string | undefined>
      >;
    } & { outsidePress?: boolean, overlayBackdrop?: string, keepFocusIn?: readonly [React.RefObject<HTMLElement>, React.MutableRefObject<boolean>] })
  | null;

const DialogContext = createContext<ContextType>(null);

export const useDialogContext = () => {
  const context = useContext(DialogContext);

  if (context == null) {
    throw new Error("Dialog components must be wrapped in <Dialog />");
  }

  return context;
};

export function Dialog({
  children,
  ...options
}: {
  children: ReactNode;
} & DialogOptions) {
  const dialog = useDialog(options);
  return (
    <DialogContext.Provider value={dialog}>{children}</DialogContext.Provider>
  );
}

interface DialogTriggerProps {
  children: ReactNode;
  asChild?: boolean;
}

export const DialogTrigger = forwardRef<
  HTMLElement,
  HTMLProps<HTMLElement> & DialogTriggerProps
>(function DialogTrigger({ children, asChild = false, ...props }, propRef) {
  const context = useDialogContext();
  const childrenRef = (children as any).ref;
  const ref = useMergeRefs([context.refs.setReference, propRef, childrenRef]);

  // `asChild` allows the user to pass any element as the anchor
  if (asChild && isValidElement(children)) {
    return cloneElement(
      children,
      context.getReferenceProps({
        ref,
        ...props,
        ...(children.props as any),
        "data-state": context.open ? "open" : "closed"
      })
    );
  }

  return (
    <div
      ref={ref}
      // The user can style the trigger based on the state
      data-state={context.open ? "open" : "closed"}
      {...context.getReferenceProps(props)}
    >
      {children}
    </div>
  );
});

export const DialogContent = forwardRef<
  HTMLDivElement,
  HTMLProps<HTMLDivElement>
>(function DialogContent(props, propRef) {
  const { context: floatingContext, ...context } = useDialogContext();
  const ref = useMergeRefs([context.refs.setFloating, propRef]);
  const mainRef = useRef<HTMLDivElement>(null);

  const { overlayBackdrop: backdropFilter, outsidePress, keepFocusIn } = context;
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
    if (keepFocusIn) return () => {
      mainRef.current?.removeEventListener("mousedown", onMouseDown, { capture: true });
      mainRef.current?.removeEventListener("click", onClick, { capture: true });
      mainRef.current?.removeEventListener("focusin", onFocusIn, { capture: true });
    }
  }, [])

  return (
    <FloatingPortal>
      {context.open && (
        <FloatingOverlay className="Dialog-overlay" 
          ref={(elem) => {
            if (!keepFocusIn) return;
            elem?.addEventListener("mousedown", onMouseDown, { capture: true });
            elem?.addEventListener("click", onClick, { capture: true });
            elem?.addEventListener("focusin", onFocusIn, { capture: true });
            mainRef.current = elem;
          }}
          lockScroll 
          style={{ backdropFilter, zIndex: 5 }}
          onClick={ outsidePress ? () => context.setOpen(false) : undefined }>
          <FloatingFocusManager context={floatingContext}>
            <div
              ref={ref}
              aria-labelledby={context.labelId}
              aria-describedby={context.descriptionId}
              {...context.getFloatingProps(props)}
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
                {props.children}
              </div>
            </div>
          </FloatingFocusManager>
        </FloatingOverlay>
      )}
    </FloatingPortal>
  );
});

export const DialogHeading = forwardRef<
  HTMLHeadingElement,
  HTMLProps<HTMLHeadingElement>
>(function DialogHeading({ children, ...props }, ref) {
  const { setLabelId } = useDialogContext();
  const id = useId();

  // Only sets `aria-labelledby` on the Dialog root element
  // if this component is mounted inside it.
  useLayoutEffect(() => {
    setLabelId(id);
    return () => setLabelId(undefined);
  }, [id, setLabelId]);

  return (
    <h2 {...props} ref={ref} id={id}>
      {children}
    </h2>
  );
});

export const DialogDescription = forwardRef<
  HTMLParagraphElement,
  HTMLProps<HTMLParagraphElement>
>(function DialogDescription({ children, ...props }, ref) {
  const { setDescriptionId } = useDialogContext();
  const id = useId();

  // Only sets `aria-describedby` on the Dialog root element
  // if this component is mounted inside it.
  useLayoutEffect(() => {
    setDescriptionId(id);
    return () => setDescriptionId(undefined);
  }, [id, setDescriptionId]);

  return (
    <p {...props} ref={ref} id={id}>
      {children}
    </p>
  );
});

export const DialogClose = forwardRef<
  HTMLButtonElement,
  ButtonHTMLAttributes<HTMLButtonElement>
>(function DialogClose({ children, ...props }, ref) {
  const { setOpen } = useDialogContext();
  return (
    <button type="button" {...props} ref={ref} onClick={() => setOpen(false)}>
      {children}
    </button>
  );
});
