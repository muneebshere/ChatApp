import React, { HTMLProps, ReactNode, cloneElement, createContext, forwardRef, isValidElement, useContext, useEffect, useMemo, useState } from "react";
import {
  useFloating,
  autoUpdate,
  offset,
  flip,
  shift,
  useClick,
  useDismiss,
  useRole,
  useInteractions,
  useMergeRefs,
  Placement,
  FloatingPortal,
  FloatingFocusManager
} from "@floating-ui/react";

interface PopoverOptions {
  placement?: Placement;
  modal?: boolean;
  controlledOpen?: boolean;
  setControlledOpen?: (open: boolean) => void;
};

type ContextType = ReturnType<typeof useFloating> & ReturnType<typeof useInteractions> & { 
  modal: boolean;
  open: boolean;
  setOpen: (open: boolean) => void;
}

const PopoverContext = createContext<ContextType>(null);

const usePopoverContext = () => {
  const context = useContext(PopoverContext);

  if (context == null) {
    throw new Error("Popover components must be wrapped in <Popover/>");
  }

  return context;
};

export default function Popover({
  children,
  modal = false,
  placement = "bottom",
  controlledOpen,
  setControlledOpen,
}: {
  children: ReactNode;
} & PopoverOptions) {
  const [uncontrolledOpen, setUncontrolledOpen] = useState(false);
  const controlled = controlledOpen !== undefined && setControlledOpen !== undefined;
  const open = controlled ? controlledOpen : uncontrolledOpen;
  const setOpen = controlled ? setControlledOpen : setUncontrolledOpen;

  const data = useFloating({
    placement,
    open,
    onOpenChange: setOpen,
    whileElementsMounted: autoUpdate,
    middleware: [
      offset(5),
      flip({
        fallbackAxisSideDirection: "end"
      }),
      shift({ padding: 5 })
    ]
  });

  const context = data.context;
  const click = useClick(context);
  const dismiss = useDismiss(context, { ancestorScroll: true });
  const role = useRole(context);
  const interactions = useInteractions([click, dismiss, role]);

  const popoverContext = useMemo(() => ({ open, setOpen, modal, ...interactions, ...data }),
    [open, setOpen, interactions, data, modal]);

  return (
    <PopoverContext.Provider value={popoverContext}>
      {children}
    </PopoverContext.Provider>
  );
}

interface PopoverTriggerProps {
  children: ReactNode;
  asChild?: boolean;
}

export const PopoverTrigger = forwardRef<
  HTMLElement,
  HTMLProps<HTMLElement> & PopoverTriggerProps
>(function PopoverTrigger({ children, asChild = false, ...props }, propRef) {
  const context = usePopoverContext();
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

export const PopoverContent = forwardRef<
  HTMLDivElement,
  HTMLProps<HTMLDivElement>
>(function PopoverContent(props, propRef) {
  const { context: floatingContext, ...context } = usePopoverContext();
  const ref = useMergeRefs([context.refs.setFloating, propRef]);

  return (
    <FloatingPortal>
      {context.open && (
        <FloatingFocusManager 
          context={floatingContext} 
          modal={context.modal}
          initialFocus={-1}
          returnFocus={true}
          guards={false}>
          <div
            ref={ref}
            style={{
              position: context.strategy,
              top: context.y ?? 0,
              left: context.x ?? 0,
              width: "max-content",
              zIndex: 6,
              ...props.style
            }}
            {...context.getFloatingProps(props)}
          >
            {props.children}
          </div>
        </FloatingFocusManager>
      )}
    </FloatingPortal>
  );
});