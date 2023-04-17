import React, { HTMLProps, ReactNode, cloneElement, createContext, forwardRef, isValidElement, useContext, useMemo, useState } from "react";
import {
  useFloating,
  autoUpdate,
  offset,
  useHover,
  useFocus,
  useDismiss,
  useRole,
  useInteractions,
  useMergeRefs,
  FloatingPortal
} from "@floating-ui/react";
import type { ElementRects, Placement } from "@floating-ui/react";

interface TooltipOptions {
  initialOpen?: boolean;
  placement?: Placement;
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
  offsetFunc?: (rects: ElementRects) => number | { mainAxis?: number, crossAxis?: number, alignmentAxis?: number | null };
}

export function useTooltip({
  initialOpen = false,
  placement = "top",
  open: controlledOpen,
  onOpenChange: setControlledOpen,
  offsetFunc
}: TooltipOptions = {}) {
  const [uncontrolledOpen, setUncontrolledOpen] = useState(initialOpen);

  const open = controlledOpen ?? uncontrolledOpen;
  const setOpen = setControlledOpen ?? setUncontrolledOpen;
  const middleware = offsetFunc ? [offset(({ rects }) => offsetFunc(rects))] : [];

  const data = useFloating({
    placement,
    open,
    onOpenChange: setOpen,
    whileElementsMounted: autoUpdate,
    middleware
  });

  const context = data.context;

  const hover = useHover(context, {
    move: false,
    enabled: controlledOpen == null
  });
  const focus = useFocus(context, {
    enabled: controlledOpen == null
  });
  const dismiss = useDismiss(context);
  const role = useRole(context, { role: "tooltip" });

  const interactions = useInteractions([hover, focus, dismiss, role]);

  return useMemo(
    () => ({
      open,
      setOpen,
      ...interactions,
      ...data
    }),
    [open, setOpen, interactions, data]
  );
}

type ContextType = ReturnType<typeof useTooltip> | null;

const TooltipContext = createContext<ContextType>(null);

export const useTooltipContext = () => {
  const context = useContext(TooltipContext);

  if (context == null) {
    throw new Error("Tooltip components must be wrapped in <Tooltip />");
  }

  return context;
};

export function Tooltip({
  children,
  ...options
}: { children: ReactNode } & TooltipOptions) {
  // This can accept any props as options, e.g. `placement`,
  // or other positioning options.
  const tooltip = useTooltip(options);
  return (
    <TooltipContext.Provider value={tooltip}>
      {children}
    </TooltipContext.Provider>
  );
}

export const TooltipTrigger = forwardRef<
  HTMLElement,
  HTMLProps<HTMLElement> & { asChild?: boolean }
>(function TooltipTrigger({ children, asChild = false, ...props }, propRef) {
  const context = useTooltipContext();
  const childrenRef = (children as any).ref;
  const ref = useMergeRefs([context.refs.setReference, propRef, childrenRef]);

  // `asChild` allows the user to pass any element as the anchor
  if (asChild && isValidElement(children)) {
    return cloneElement(
      children,
      context.getReferenceProps({
        ref,
        ...props,
        ...children.props as any,
        "data-state": context.open ? "open" : "closed"
      })
    );
  }

  return (
    <div
      ref={ref}
      {...context.getReferenceProps(props)}
    >
      {children}
    </div>
  );
});

export const TooltipContent = forwardRef<HTMLDivElement, HTMLProps<HTMLDivElement>>(function TooltipContent(props, propRef) {
  const context = useTooltipContext();
  const ref = useMergeRefs([context.refs.setFloating, propRef]);

  return (
    <FloatingPortal>
      {context.open && (
        <div
          ref={ref}
          style={{
            position: context.strategy,
            top: context.y ?? 0,
            left: context.x ?? 0,
            visibility: context.x == null ? "hidden" : "visible",
            ...props.style
          }}
          {...context.getFloatingProps(props)}
        />
      )}
    </FloatingPortal>
  );
});
