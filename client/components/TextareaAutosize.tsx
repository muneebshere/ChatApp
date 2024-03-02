import React, { ForwardedRef, forwardRef, useCallback, useEffect, useMemo, useRef, useState } from "react";
import PropTypes from "prop-types";
import * as ReactDOM from "react-dom";
import {
  unstable_debounce as debounce,
  unstable_useForkRef as useForkRef,
  unstable_useEnhancedEffect as useEnhancedEffect,
  unstable_ownerWindow as ownerWindow,
} from "@mui/utils";
import styled from "@emotion/styled";

declare module "React" {
  interface TextareaHTMLAttributes<T> extends HTMLAttributes<T> {
    virtualkeyboardpolicy?: "auto" | "manual";
  }
}

interface TextareaAutosizeProps
  extends Omit<React.TextareaHTMLAttributes<HTMLTextAreaElement>, "children" | "rows" | "onSubmit"> {
  ref?: React.Ref<HTMLTextAreaElement>;
  tabbedOutside?: React.MutableRefObject<boolean>;
  /**
   * Maximum number of rows to display.
   */
  maxRows?: string | number;
  /**
   * Minimum number of rows to display.
   * @default 1
   */
  minRows?: string | number;
  /**
   * callback to call when updating height
   */
  onHeightUpdate?: (newHeight: number) => void;
  /**
   * callback to execute when Ctrl+Enter is pressed
   */
  onSubmit?: (value: string) => void;
  /**
   * props for outer border
   */
  outerProps?: Omit<React.HTMLProps<HTMLDivElement>, "as">; 
  
  startDecorator?: JSX.Element;

  startDecoratorStyle?: React.CSSProperties;

  endDecorator?: JSX.Element;

  endDecoratorStyle?: React.CSSProperties;

  openKeyboardManual?: boolean;

  inputModeManual?: boolean;
}

type State = {
  outerHeightStyle: number;
  overflow?: boolean | undefined;
};

function getStyleValue(value: string) {
  return parseInt(value, 10) || 0;
}

const styles: {
  shadow: React.CSSProperties;
} = {
  shadow: {
    // Visibility needed to hide the extra text area on iPads
    visibility: "hidden",
    // Remove from the content flow
    position: "absolute",
    // Ignore the scrollbar width
    overflow: "hidden",
    height: 0,
    top: 0,
    left: 0,
    // Create a new layer, increase the isolation of the computed values
    transform: "translateZ(0)",
  },
};

function isEmpty(obj: State) {
  return (
    obj === undefined ||
    obj === null ||
    Object.keys(obj).length === 0 ||
    (obj.outerHeightStyle === 0 && !obj.overflow)
  );
}

/**
 *
 * Demos:
 *
 * - [Textarea Autosize](https://mui.com/base/react-textarea-autosize/)
 * - [Textarea Autosize](https://mui.com/material-ui/react-textarea-autosize/)
 *
 * API:
 *
 * - [TextareaAutosize API](https://mui.com/base/react-textarea-autosize/components-api/#textarea-autosize)
 */
const TextareaAutosize = forwardRef(function TextareaAutosize(
  props: TextareaAutosizeProps,
  ref: ForwardedRef<Element>,
) {
  const { onChange, onHeightUpdate, maxRows, minRows = 1, style, value, onSubmit, openKeyboardManual, tabbedOutside, onClick, inputModeManual, inputMode, ...other } = props;

  const virtualkeyboardpolicy = openKeyboardManual ? "manual" : "auto";
  const { current: isControlled } = useRef(value != null);
  const inputRef = useRef<HTMLInputElement>(null);
  const handleRef = useForkRef(ref, inputRef);
  const shadowRef = useRef<HTMLTextAreaElement>(null);
  const renders = useRef(0);
  const [state, setState] = useState<State>({
    outerHeightStyle: 0,
  });
  const [inputModeState, setInputModeState] = useState<typeof inputMode>(inputModeManual ? "none" : (inputMode || "text"));

  const getUpdatedState = useCallback(() => {
    const input = inputRef.current!;

    const containerWindow = ownerWindow(input);
    const computedStyle = containerWindow.getComputedStyle(input);

    // If input's width is shrunk and it's not visible, don't sync height.
    if (computedStyle.width === "0px") {
      return {
        outerHeightStyle: 0,
      };
    }

    const inputShallow = shadowRef.current!;

    inputShallow.style.width = computedStyle.width;
    inputShallow.value = input.value || props.placeholder || "x";
    if (inputShallow.value.slice(-1) === "\n") {
      // Certain fonts which overflow the line height will cause the textarea
      // to report a different scrollHeight depending on whether the last line
      // is empty. Make it non-empty to avoid this issue.
      inputShallow.value += " ";
    }

    const boxSizing = computedStyle.boxSizing;
    const padding =
      getStyleValue(computedStyle.paddingBottom) + getStyleValue(computedStyle.paddingTop);
    const border =
      getStyleValue(computedStyle.borderBottomWidth) + getStyleValue(computedStyle.borderTopWidth);

    // The height of the inner content
    const innerHeight = inputShallow.scrollHeight;

    // Measure height of a textarea with a single row
    inputShallow.value = "x";
    const singleRowHeight = inputShallow.scrollHeight;

    // The height of the outer content
    let outerHeight = innerHeight;

    if (minRows) {
      outerHeight = Math.max(Number(minRows) * singleRowHeight, outerHeight);
    }
    if (maxRows) {
      outerHeight = Math.min(Number(maxRows) * singleRowHeight, outerHeight);
    }
    outerHeight = Math.max(outerHeight, singleRowHeight);

    // Take the box sizing into account for applying this value as a style.
    const outerHeightStyle = outerHeight + (boxSizing === "border-box" ? padding + border : 0);
    const overflow = Math.abs(outerHeight - innerHeight) <= 1;

    return { outerHeightStyle, overflow };
  }, [maxRows, minRows, props.placeholder]);

  const updateState = (prevState: State, newState: State) => {
    const { outerHeightStyle, overflow } = newState;
    // Need a large enough difference to update the height.
    // This prevents infinite rendering loop.
    if (
      renders.current < 20 &&
      ((outerHeightStyle > 0 &&
        Math.abs((prevState.outerHeightStyle || 0) - outerHeightStyle) > 1) ||
        prevState.overflow !== overflow)
    ) {
      renders.current += 1;
      onHeightUpdate?.(outerHeightStyle);
      return {
        overflow,
        outerHeightStyle,
      };
    }
    if (process.env.NODE_ENV !== "production") {
      if (renders.current === 20) {
        console.error(
          [
            "MUI: Too many re-renders. The layout is unstable.",
            "TextareaAutosize limits the number of renders to prevent an infinite loop.",
          ].join("\n"),
        );
      }
    }
    return prevState;
  };

  const syncHeight = useCallback(() => {
    const newState = getUpdatedState();

    if (isEmpty(newState)) {
      return;
    }

    setState((prevState) => {
      return updateState(prevState, newState);
    });
  }, [getUpdatedState]);

  const syncHeightWithFlushSycn = () => {
    const newState = getUpdatedState();

    if (isEmpty(newState)) {
      return;
    }

    // In React 18, state updates in a ResizeObserver's callback are happening after the paint which causes flickering
    // when doing some visual updates in it. Using flushSync ensures that the dom will be painted after the states updates happen
    // Related issue - https://github.com/facebook/react/issues/24331
    ReactDOM.flushSync(() => {
      setState((prevState) => {
        return updateState(prevState, newState);
      });
    });
  };

  useEffect(() => {
    const handleResize = debounce(() => {
      renders.current = 0;

      // If the TextareaAutosize component is replaced by Suspense with a fallback, the last
      // ResizeObserver's handler that runs because of the change in the layout is trying to
      // access a dom node that is no longer there (as the fallback component is being shown instead).
      // See https://github.com/mui/material-ui/issues/32640
      if (inputRef.current) {
        syncHeightWithFlushSycn();
      }
    });
    let resizeObserver: ResizeObserver;

    const input = inputRef.current!;
    const containerWindow = ownerWindow(input);

    containerWindow.addEventListener("resize", handleResize);

    if (typeof ResizeObserver !== "undefined") {
      resizeObserver = new ResizeObserver(handleResize);
      resizeObserver.observe(input);
    }

    return () => {
      handleResize.clear();
      containerWindow.removeEventListener("resize", handleResize);
      if (resizeObserver) {
        resizeObserver.disconnect();
      }
    };
  });

  useEnhancedEffect(() => {
    syncHeight();
  });

  useEffect(() => {
    renders.current = 0;
  }, [value]);

  const handleChange = (event: React.ChangeEvent<HTMLTextAreaElement>) => {
    renders.current = 0;

    if (!isControlled) {
      syncHeight();
    }

    if (onChange) {
      onChange(event);
    }
  };

  const handleSubmit = useMemo(() => {
    return onSubmit
      ? (event: React.KeyboardEvent<HTMLTextAreaElement>) => { 
          if (event.ctrlKey && event.key === "Enter") {
            onSubmit(event.currentTarget.value);
            event.stopPropagation();
            return false;
          }
          else if (tabbedOutside && event.key === "Tab") {
            tabbedOutside.current = true;
          }
        }
      : undefined;

  }, [onSubmit]);

  const handleKeyUp = useMemo(() => {
    return tabbedOutside
      ? () => tabbedOutside.current = false
      : undefined;
  }, [tabbedOutside]);

  const onClickKeyboard: React.MouseEventHandler<HTMLTextAreaElement> = 
    inputModeManual
      ? (e) => {
        setInputModeState(inputMode || "text");
        onClick?.(e);
      }
      : (openKeyboardManual
          ? (e) => {
            (navigator as any).virtualKeyboard?.show();
            onClick?.(e);
          }
          : onClick);

  return (
    <React.Fragment>
      <textarea
        value={value}
        onChange={handleChange}
        onKeyDown={handleSubmit}
        onKeyUp={handleKeyUp}
        inputMode={inputModeState}
        virtualkeyboardpolicy={virtualkeyboardpolicy}
        onClick={onClickKeyboard}
        ref={handleRef}
        // Apply the rows prop to get a "correct" first SSR paint
        rows={minRows as number}
        style={{
          height: state.outerHeightStyle,
          // Need a large enough difference to allow scrolling.
          // This prevents infinite rendering loop.
          overflow: state.overflow ? "hidden" : undefined,
          ...style,
        }}
        {...other}
      />
      <textarea
        aria-hidden
        className={props.className}
        readOnly
        ref={shadowRef}
        tabIndex={-1}
        style={{
          ...styles.shadow,
          ...style,
          padding: 0,
        }}
      />
    </React.Fragment>
  );
});

TextareaAutosize.propTypes /* remove-proptypes */ = {
  // ----------------------------- Warning --------------------------------
  // | These PropTypes are generated from the TypeScript type definitions |
  // |     To update them edit TypeScript types and run "yarn proptypes"  |
  // ----------------------------------------------------------------------
  /**
   * @ignore
   */
  className: PropTypes.string,
  /**
   * Maximum number of rows to display.
   */
  maxRows: PropTypes.oneOfType([PropTypes.number, PropTypes.string]),
  /**
   * Minimum number of rows to display.
   * @default 1
   */
  minRows: PropTypes.oneOfType([PropTypes.number, PropTypes.string]),
  /**
   * @ignore
   */
  onChange: PropTypes.func,
  /**
   * @ignore
   */
  placeholder: PropTypes.string,
  /**
   * @ignore
   */
  style: PropTypes.object,
  /**
   * @ignore
   */
  value: PropTypes.oneOfType([
    PropTypes.arrayOf(PropTypes.string),
    PropTypes.number,
    PropTypes.string,
  ]),
} as any;

export default TextareaAutosize;

const TextareaBorder = styled.div`
  width: 100%;
  display: flex; 
  flex-direction: column;
  height: max-content;
  padding: 7px;
  border-radius: 8px;
  outline: 1px solid #d8d8df;
  background-color: white;

  &:hover {
    outline-color: #b9b9c6;
  }

  &:focus-within {
    outline: 2px solid #1f7a1f;
  }`;

const StyledInnerTextarea = styled(TextareaAutosize)`
  padding: 0px;
  border-radius: 0px;
  border: 0px none;
  outline: 0px none;
  resize: none;
  font-family: var(--joy-fontFamily-body);
  font-size: var(--joy-fontSize-md);
  line-height: var(--joy-lineHeight-md);
  overflow-x: clip;
  overflow-y: auto;

  scroll-behavior: auto !important;
  scrollbar-width: thin;
  scrollbar-color: #afafaf #d1d1d1;

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

export const StyledScrollingTextarea = forwardRef(function(props: TextareaAutosizeProps, ref: ForwardedRef<HTMLTextAreaElement>) {
  const { startDecorator, endDecorator, startDecoratorStyle = {}, endDecoratorStyle = {}, outerProps = {}, ...innerProps } = props; 
  return (
  <TextareaBorder {...outerProps}>
    {startDecorator &&
    <div style={startDecoratorStyle}>
      {startDecorator}
    </div>}
    <div style={{ flex: 1, display: "flex", flexWrap: "wrap", justifyContent: "stretch", alignContent: "center" }}>
      <StyledInnerTextarea ref={ref} {...innerProps}/>
      <div style={endDecoratorStyle}>
        {endDecorator}
      </div>
    </div>
  </TextareaBorder>);
  })