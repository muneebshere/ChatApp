import React, { ButtonHTMLAttributes, Dispatch, HTMLProps, ReactNode, SetStateAction, cloneElement, createContext, forwardRef, isValidElement, useContext, useEffect, useLayoutEffect, useMemo, useState } from "react";
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
  FloatingFocusManager,
  useId
} from "@floating-ui/react";

interface PopoverOptions {
  initialOpen?: boolean;
  placement?: Placement;
  modal?: boolean;
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
}

export function usePopover({
  initialOpen = false,
  placement = "bottom",
  modal,
  open: controlledOpen,
  onOpenChange: setControlledOpen
}: PopoverOptions = {}) {
  const [uncontrolledOpen, setUncontrolledOpen] = useState(initialOpen);
  const [labelId, setLabelId] = useState<string | undefined>();
  const [descriptionId, setDescriptionId] = useState<
    string | undefined
  >();

  const controlled = !!controlledOpen && !!setControlledOpen;
  const open = controlled ? controlledOpen : uncontrolledOpen;
  const setOpen = controlled ? setControlledOpen : setUncontrolledOpen;

  useEffect(() => {
    if (!controlled && setControlledOpen) {
      setControlledOpen(open);
    }
  }, [open]);

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

  const click = useClick(context, {
    enabled: !controlled
  });
  const dismiss = useDismiss(context);
  const role = useRole(context);

  const interactions = useInteractions([click, dismiss, role]);

  return useMemo(
    () => ({
      open,
      setOpen,
      ...interactions,
      ...data,
      modal,
      labelId,
      descriptionId,
      setLabelId,
      setDescriptionId
    }),
    [open, setOpen, interactions, data, modal, labelId, descriptionId]
  );
}

type ContextType =
  | (ReturnType<typeof usePopover> & {
      setLabelId: Dispatch<SetStateAction<string | undefined>>;
      setDescriptionId: Dispatch<
        SetStateAction<string | undefined>
      >;
    })
  | null;

const PopoverContext = createContext<ContextType>(null);

export const usePopoverContext = () => {
  const context = useContext(PopoverContext);

  if (context == null) {
    throw new Error("Popover components must be wrapped in <Popover />");
  }

  return context;
};

export function Popover({
  children,
  modal = false,
  ...restOptions
}: {
  children: ReactNode;
} & PopoverOptions) {
  // This can accept any props as options, e.g. `placement`,
  // or other positioning options.
  const popover = usePopover({ modal, ...restOptions });
  return (
    <PopoverContext.Provider value={popover}>
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
        <FloatingFocusManager context={floatingContext} modal={context.modal}>
          <div
            ref={ref}
            style={{
              position: context.strategy,
              top: context.y ?? 0,
              left: context.x ?? 0,
              width: "max-content",
              ...props.style
            }}
            aria-labelledby={context.labelId}
            aria-describedby={context.descriptionId}
            {...context.getFloatingProps(props)}
          >
            {props.children}
          </div>
        </FloatingFocusManager>
      )}
    </FloatingPortal>
  );
});

export const PopoverHeading = forwardRef<
  HTMLHeadingElement,
  HTMLProps<HTMLHeadingElement>
>(function PopoverHeading({ children, ...props }, ref) {
  const { setLabelId } = usePopoverContext();
  const id = useId();

  // Only sets `aria-labelledby` on the Popover root element
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

export const PopoverDescription = forwardRef<
  HTMLParagraphElement,
  HTMLProps<HTMLParagraphElement>
>(function PopoverDescription({ children, ...props }, ref) {
  const { setDescriptionId } = usePopoverContext();
  const id = useId();

  // Only sets `aria-describedby` on the Popover root element
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

export const PopoverClose = forwardRef<
  HTMLButtonElement,
  ButtonHTMLAttributes<HTMLButtonElement>
>(function PopoverClose({ children, ...props }, ref) {
  const { setOpen } = usePopoverContext();
  return (
    <button type="button" {...props} ref={ref} onClick={() => setOpen(false)}>
      {children}
    </button>
  );
});
