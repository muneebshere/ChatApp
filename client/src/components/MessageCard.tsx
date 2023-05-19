import _ from "lodash";
import isEqual from "react-fast-compare";
import React, { createContext, memo, useCallback, useContext, useLayoutEffect, useMemo, useRef, useState } from "react";
import { useUpdateEffect } from "usehooks-ts";
import { Grid, Stack } from "@mui/joy";
import { DoneSharp, DoneAllSharp, HourglassTop } from "@mui/icons-material";
import { Tooltip, TooltipTrigger, TooltipContent } from "./Tooltip";
import { Popover, PopoverTrigger, PopoverContent } from "./Popover";
import { DisableSelectTypography, StyledSheet } from "./CommonElementStyles";
import remarkGfm from "remark-gfm";
import remarkMath from "remark-math";
import twemoji from "../custom_modules/remark-twemoji";
import rehypeRaw from "rehype-raw";
import rehypeKatex from "rehype-katex";
import { DateTime } from "luxon";
import SvgMessageCard from "./SvgMessageCard";
import "katex/dist/katex.min.css";
import { ReplyingToMemo } from "./ReplyingTo";
import { StyledReactMarkdownVariable } from "./CommonElementStyles";
import { MessageDeliveryInfo, DisplayMessage, ReplyingToInfo } from "../../../shared/commonTypes";
import { ElementRects } from "@floating-ui/react";
import useSwipeDrag from "./Hooks/useSwipeDrag";
import { SxProps } from "@mui/material";

interface HTMLDivElementScroll extends HTMLDivElement {
  scrollIntoViewIfNeeded(centerIfNeeded?: boolean): void;
}

export type MessageCardContextData = Readonly<{
  chatWith: string; 
  highlight: string;
  setHighlight: (id: string) => void;
  setReplyTo: (replyingTo: ReplyingToInfo) => void;
  registerMessageRef: (ref: HTMLDivElement) => void;
  toggleScroll?: (scrollOn: boolean) => void;
}>;

export type ViewMessage = Readonly<DisplayMessage & { 
  first: boolean;
}>;

export const MessageCardContext = createContext<MessageCardContextData>(null);

const StyledReactMarkdownBody = StyledReactMarkdownVariable(22);

function StatusButton(deliveryInfo: MessageDeliveryInfo) {
  if (!deliveryInfo.sentByMe) return null;
  const { delivery } = deliveryInfo;
  if (!delivery) {
    return <HourglassTop sx={{ color: "gold", rotate: "-90deg", fontSize: "1rem" }}/>;
  }
  else {
    const { delivered, seen } = delivery;
    const statusIcon = 
    delivered 
      ? (<DoneAllSharp sx={{ color: seen ? "blue" : "gray", fontSize: "1rem", cursor: "pointer" }}/>) 
      : <DoneSharp sx={{ color: "gray", fontSize: "1rem", cursor: "pointer" }}/>;
    const deliveredText = delivered ? DateTime.fromMillis(delivered).toFormat("dd/LL/y, h:mm a") : "Not delivered";
    const seenText = seen ? DateTime.fromMillis(seen).toFormat("dd/LL/y, h:mm a") : "Not seen";
    return (
      <Popover modal={false} placement="bottom-end">
        <PopoverTrigger asChild>
            {statusIcon}
        </PopoverTrigger>
        <PopoverContent>
          <div style={{ position: "relative",
                        zIndex: 5, 
                        borderRadius: 8, 
                        padding: 10, 
                        border: "0.1px solid #d8d8df", 
                        backgroundColor: "rgba(244, 246, 244, 0.8)", 
                        boxShadow: "0px 1px 3px 1.5px #eeeeee", 
                        backdropFilter: "blur(4px)" }}
                tabIndex={-1}
                >
            <Stack direction="row">
              <Stack direction="column" spacing={1.5} sx={{ maxWidth: "fit-content", paddingTop: 0.3 }}>
                <DoneAllSharp sx={{ color: "gray", fontSize: "1rem" }}/>
                <DoneAllSharp sx={{ color: "blue", fontSize: "1rem" }}/>
              </Stack>
              <Stack direction="column" spacing={1} sx={{ maxWidth: "fit-content", paddingLeft: 1.5, paddingRight: 3, alignItems: "start" }}>
                <DisableSelectTypography level="body2">Delivered</DisableSelectTypography>
                <DisableSelectTypography level="body2">Seen</DisableSelectTypography>
              </Stack>
              <Stack direction="column" spacing={1} sx={{ maxWidth: "fit-content" }}>
                <DisableSelectTypography level="body2">{deliveredText}</DisableSelectTypography>
                <DisableSelectTypography level="body2">{seenText}</DisableSelectTypography>
              </Stack>
            </Stack>
          </div>
        </PopoverContent>
      </Popover>)
  }
}

function formatTooltipDate(timestamp: number) {
  const date = DateTime.fromMillis(timestamp);
  return `${date.toFormat("d LLLL ")}'${date.toFormat("yy")}, ${date.toFormat("h:mm a")}`;
}

function MessageCardWithHighlight(message: ViewMessage & MessageCardContextData) {
  const { highlight, setHighlight, setReplyTo, registerMessageRef, chatWith, messageId, content, timestamp, replyingTo, first, toggleScroll, ...deliveryInfo } = message;
  const { sentByMe } = deliveryInfo;
  const [darken, setDarken] = useState(false);
  const scrollRef = useRef<HTMLDivElementScroll>(null);
  const bodyRef = useRef<HTMLSpanElement>(null);
  const statusRef = useRef<HTMLDivElement>(null);
  const floatingRef = useRef<HTMLDivElement>(null);
  const offsetFunc = (rects: ElementRects) => {
    const crossAxis = (-floatingRef.current?.getBoundingClientRect()?.width || 0) + rects.reference.width;
    return { crossAxis }
  }
  const replyingData = useMemo(() => ({ id: messageId, replyToOwn: sentByMe, displayText: content }), []);
  const onClick: React.MouseEventHandler<HTMLDivElement> = (event) => {
    if (event.detail >= 2) {
      setReplyTo(replyingData);
      if (window.navigator.userActivation.isActive) {
        window.navigator.vibrate(20);
      }
    }
    event.stopPropagation();
    return false;
  };
  const action = useCallback(() => setReplyTo(replyingData), []);
  const handlers = useSwipeDrag(scrollRef, 100, 70, action, toggleScroll);

  useUpdateEffect(() => {
    if (highlight === messageId) { 
      scrollRef.current.scrollIntoViewIfNeeded(true);
      setDarken(true);
    } 
  }, [highlight]);

  useUpdateEffect(() => {
    if (!darken) {
      setHighlight("");
    }
  }, [darken]);

  useLayoutEffect(() => {
    const bodyElement = bodyRef.current.querySelector("div.react-markdown > p:last-child");
    const { height, width } = statusRef.current.getBoundingClientRect();
    bodyElement?.insertAdjacentHTML("beforeend", `<div style="float: right; shape-outside: margin-box; width: ${width}px; height: ${height}px; min-width: ${width}px; min-height: ${height}px; margin: 12px 0px 0px 12px;">&nbsp;</div>`);
  });

  const repliedMessage = useMemo(() => {
    const props = replyingTo ? { chatWith, sentByMe, setHighlight, ...replyingTo } : null;
    return replyingTo
      ? <ReplyingToMemo { ...props}/>
      : null

  }, [messageId]);

  const side = sentByMe ? "flex-end" : "flex-start";
  const messageColor = sentByMe ? "#d7fad1" : "white";
  return (
    <Grid container sx={{ display: "flex", flexGrow: 1, justifyContent: side, height: "fit-content", maxWidth: "100%" }} onClick={onClick} ref={scrollRef} {...handlers}>
      <Grid xs={10} sm={8} lg={7} sx={{ display: "flex", flexGrow: 0, justifyContent: side, height: "fit-content" }}>
        <StyledSheet sx={{ width: "100%", display: "flex", flexGrow: 1, justifyContent: side, alignContent: "flex-start", padding: 0, margin: 0 }} ref={registerMessageRef} id={`m${messageId}`}>
          <SvgMessageCard background={messageColor} first={first} sentByMe={sentByMe} shadowColor="#adb5bd" darken={darken} darkenFinished={() => setDarken(false) }>
            <Stack direction="column"
              sx={{ maxWidth: "max-content", width: "fit-content", padding: 1.5, paddingBottom: 0.5, alignContent: "flex-start", textAlign: "start" }}>
                {repliedMessage && repliedMessage}
              <DisableSelectTypography ref={bodyRef} component="span" sx={{ width: "fit-content", maxWidth: "max-content" }}>
                <StyledReactMarkdownBody 
                  className="react-markdown" 
                  children={content} 
                  remarkPlugins={[remarkGfm, remarkMath, twemoji]}
                  rehypePlugins={[rehypeKatex, rehypeRaw]}/>
              </DisableSelectTypography>
              <Stack ref={statusRef} 
                    direction="row" 
                    spacing={1} 
                    sx={{ width: "fit-content", 
                          alignItems: "center",
                          position: "absolute",
                          bottom: "8px",
                          right: "12px" }}>
                <Tooltip placement="bottom-start" offsetFunc={offsetFunc}>
                  <TooltipTrigger>
                    <DisableSelectTypography level="body3">
                      {DateTime.fromMillis(timestamp).toFormat("h:mm a")}
                    </DisableSelectTypography>
                  </TooltipTrigger>
                  <TooltipContent>
                    <div ref={floatingRef} style={{ width: "fit-content",
                                  backgroundColor: "#bebdbc", 
                                  borderColor: "rgba(237, 237, 237, 0.7)", 
                                  boxShadow: "0px 0.5px 4px #e4e4e4",
                                  position: "absolute",
                                  zIndex: 2 }}>
                      <DisableSelectTypography level="body3" noWrap sx={{ color: "black" }}>
                        {formatTooltipDate(timestamp)}
                      </DisableSelectTypography>
                    </div>
                  </TooltipContent>
                </Tooltip>
                <StatusButton {...deliveryInfo}/>
              </Stack>
            </Stack>
          </SvgMessageCard>
        </StyledSheet>        
      </Grid>
    </Grid>
  )
}

const MessageCardMemo = memo(MessageCardWithHighlight, 
  (prev, next) => 
    prev.chatWith === next.chatWith
    && prev.messageId === next.messageId 
    && (!prev.sentByMe || !next.sentByMe || !(prev.delivery || next.delivery) || isEqual(prev.delivery, next.delivery))
    && (next.highlight === next.messageId) === (prev.highlight === prev.messageId));

export default function MessageCard(message: ViewMessage) {
  const context = useContext(MessageCardContext);
  const params = { ...message, ...context };
  return (<MessageCardMemo { ...params }/>)
}