import _ from "lodash";
import  { match } from "ts-pattern";
import React, { ForwardedRef, createContext, forwardRef, memo, useContext, useImperativeHandle, useLayoutEffect, useRef, useState } from "react";
import { useUpdateEffect } from "usehooks-ts";
import { Grid, IconButton, Link, Sheet, Stack, Typography } from "@mui/joy";
import { DoneSharp, DoneAllSharp, HourglassTop } from "@mui/icons-material";
import { Tooltip, TooltipTrigger, TooltipContent } from "./Tooltip";
import { Popover, PopoverTrigger, PopoverContent } from "./Popover";
import { StyledSheet } from "./CommonElementStyles";
import { ReactMarkdownOptions, ReactMarkdown } from "react-markdown/lib/react-markdown";
import remarkGfm from "remark-gfm";
import remarkMath from "remark-math";
import twemoji from "../custom_modules/remark-twemoji";
import rehypeRaw from "rehype-raw";
import rehypeKatex from "rehype-katex";
import { DateTime } from "luxon";
import styled from "@emotion/styled";
import SvgMessageCard from "./SvgMessageCard";
import "katex/dist/katex.min.css"
import { DisplayMessage } from "../../../shared/commonTypes";

interface HTMLDivElementScroll extends HTMLDivElement {
  scrollIntoViewIfNeeded(centerIfNeeded?: boolean): void;
}

const ReactMarkdownMemo = React.memo(ReactMarkdown, (prev, next) => prev.children === next.children);

const StyledReactMarkdownVariableEmojiSize = (emojiSize: number) => styled(ReactMarkdownMemo as unknown as React.ComponentClass<ReactMarkdownOptions, {}>)`
  img.emoji {
    height: ${emojiSize}px;
    width: ${emojiSize}px;
    background-position:center;
    background-repeat:no-repeat;
    background-size:contain;
    display:inline-block;
    vertical-align:middle;
    margin: 0px 1.5px;
  }

  span.onlyEmoji+img.emoji {
    height: 66px;
    width: 66px;
    margin: 0px 1.5px 5px;
  }

  & > p:last-child {
    max-width: 100%;
    padding-bottom: 0px;
    margin-bottom: 0px;
  }`;

const StyledReactMarkdownBody = StyledReactMarkdownVariableEmojiSize(22);

const StyledReactMarkdownReply = StyledReactMarkdownVariableEmojiSize(18);

export type ViewMessage = Readonly<DisplayMessage & { 
  chatWith: string; 
  first: boolean;
  highlight: string;
  setHighlight: (id: string) => void;  }>;

const formatTooltipDate = (timestamp: number) => {
  const date = DateTime.fromMillis(timestamp);
  return `${date.toFormat("d LLLL ")}'${date.toFormat("yy")}, ${date.toFormat("h:mm a")}`;
}

const pendingIcon = <HourglassTop sx={{ color: "gold", rotate: "-90deg", fontSize: "1rem" }}/>;
const sentIcon = <DoneSharp sx={{ color: "gray", fontSize: "1rem" }}/>;
const deliveredIcon = <DoneAllSharp sx={{ color: "gray", fontSize: "1rem" }}/>;
const seenIcon = <DoneAllSharp sx={{ color: "blue", fontSize: "1rem" }}/>;

const MessageCard = forwardRef(function (message: ViewMessage, ref: ForwardedRef<HTMLDivElement>) {
  const { highlight, setHighlight } = message;
  const { chatWith, messageId, content, timestamp, replyingTo, sentByMe, first } = message;
  const [darken, setDarken] = useState(false);
  const scrollRef = useRef<HTMLDivElementScroll>(null);
  const bodyRef = useRef<HTMLSpanElement>(null);
  const statusRef = useRef<HTMLDivElement>(null);

  useUpdateEffect(() => {
    if (highlight === messageId) { 
      scrollRef.current.scrollIntoViewIfNeeded();
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
    bodyElement.insertAdjacentHTML("beforeend", `<div style="float: right; shape-outside: margin-box; width: ${width}px; height: ${height}px; min-width: ${width}px; min-height: ${height}px; margin: 12px 0px 0px 12px;">&nbsp;</div>`);
  });

  let statusButton: JSX.Element = null;
  if (sentByMe) {
    const { delivery } = message;
    if (!delivery) {
      statusButton = pendingIcon;
    }
    else {
      const { delivered, seen } = delivery;
      const statusIcon = delivered ? (seen ? seenIcon : deliveredIcon) : sentIcon;
      const deliveredText = delivered ? DateTime.fromMillis(delivered).toFormat("dd/LL/y, h:mm a") : "Not delivered";
      const seenText = seen ? DateTime.fromMillis(seen).toFormat("dd/LL/y, h:mm a") : "Not seen";
      statusButton = (
        <Popover modal={false}>
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
                  {deliveredIcon}
                  {seenIcon}
                </Stack>
                <Stack direction="column" spacing={1} sx={{ maxWidth: "fit-content", paddingLeft: 1.5, paddingRight: 3, alignItems: "start" }}>
                  <Typography level="body2">Delivered</Typography>
                  <Typography level="body2">Seen</Typography>
                </Stack>
                <Stack direction="column" spacing={1} sx={{ maxWidth: "fit-content" }}>
                  <Typography level="body2">{deliveredText}</Typography>
                  <Typography level="body2">{seenText}</Typography>
                </Stack>
              </Stack>
            </div>
          </PopoverContent>
        </Popover>)
    }
  }

  const repliedMessage = 
    replyingTo ? (() => {
      const { id: replyId, replyToOwn, displayText } = replyingTo;
      const repliedColor = sentByMe ? "#e8fae5" : "#f2f2f2";
      const repliedOutlineColor = replyToOwn ? "#53bdeb" : "#06cf9c";
      const repliedBorderColor = sentByMe ? "#bddcb8" : "#c7c7c7";
      const repliedBorder = `thin solid ${repliedBorderColor}`;
      return (
          <Link component="button" underline="none" onClick={() => setHighlight(replyId) }>
            <Stack direction="row" sx={{ width: "100%", paddingBottom: 0.5 }}>
              <Sheet sx={{ width: "4px", minWidth: "4px", backgroundColor: repliedOutlineColor, borderLeftColor: repliedOutlineColor, borderTopLeftRadius: "10px", borderBottomLeftRadius: "10px" }}/>
              <Sheet variant="soft" sx={{ flexGrow: 1, backgroundColor: repliedColor, padding: 1, borderTopRightRadius: "10px", borderBottomRightRadius: "10px", borderTop: "thin solid transparent", borderBottom: repliedBorder, borderRight: repliedBorder, boxShadow: `1px 0px 2px ${repliedBorderColor}`, "&:hover": { boxShadow: `1px 0px 7px ${repliedBorderColor}` } }}>
                <Stack direction="column" justifyContent="flex-start" sx={{ display: "flex", textAlign: "left" }}>
                  <Typography component="span" level="body3" fontWeight="bold" textColor={repliedOutlineColor}>
                    {replyToOwn ? "You" : chatWith }
                  </Typography>
                  <Typography component="span" level="body3">
                    <StyledReactMarkdownReply 
                      className="react-markdown" 
                      components={{ p: "span" }}
                      children={displayText}
                      remarkPlugins={[remarkGfm, remarkMath, twemoji]}
                      rehypePlugins={[rehypeKatex, rehypeRaw]}/>
                  </Typography>
                </Stack>
              </Sheet>
            </Stack>
          </Link>)
    })() : null;

  const side = sentByMe ? "flex-end" : "flex-start";
  const messageColor = sentByMe ? "#d7fad1" : "white";
  return (
    <Grid container sx={{ display: "flex", flexGrow: 1, justifyContent: side, height: "fit-content", maxWidth: "100%" }}>
      <Grid xs={10} sm={8} lg={7} sx={{ display: "flex", flexGrow: 0, justifyContent: side, height: "fit-content" }} ref={scrollRef}>
        <StyledSheet sx={{ width: "100%", display: "flex", flexGrow: 1, justifyContent: side, alignContent: "flex-start", padding: 0, margin: 0 }} ref={ref} id={`m${messageId}`}>
          <SvgMessageCard background={messageColor} first={first} sentByMe={sentByMe} shadowColor="#adb5bd" darken={darken} darkenFinished={() => setDarken(false) }>
            <Stack direction="column"
              sx={{ maxWidth: "max-content", width: "fit-content", padding: 1.5, paddingBottom: 0.5, alignContent: "flex-start", textAlign: "start" }}>
                {repliedMessage && repliedMessage}
              <Typography ref={bodyRef} component="span" sx={{ width: "fit-content", maxWidth: "max-content" }}>
                <StyledReactMarkdownBody 
                  className="react-markdown" 
                  children={content} 
                  remarkPlugins={[remarkGfm, remarkMath, twemoji]}
                  rehypePlugins={[rehypeKatex, rehypeRaw]}/>
              </Typography>
              <Stack ref={statusRef} 
                    direction="row" 
                    spacing={1} 
                    sx={{ width: "fit-content", 
                          alignItems: "center",
                          position: "absolute",
                          bottom: "8px",
                          right: "12px" }}>
                <Tooltip placement="left" mainAxisOffset={140} crossAxisOffset={-10}>
                  <TooltipTrigger>
                    <Typography level="body3">
                      {DateTime.fromMillis(timestamp).toFormat("h:mm a")}
                    </Typography>
                  </TooltipTrigger>
                  <TooltipContent>
                    <div style={{ width: "fit-content",
                                  backgroundColor: "#f8f7f5", 
                                  borderColor: "rgba(237, 237, 237, 0.7)", 
                                  boxShadow: "0px 0.5px 4px #e4e4e4",
                                  position: "absolute",
                                  zIndex: 2 }}>
                      <Typography level="body3" noWrap>
                        {formatTooltipDate(timestamp)}
                      </Typography>
                    </div>
                  </TooltipContent>
                </Tooltip>
                {statusButton}
              </Stack>
            </Stack>
          </SvgMessageCard>
        </StyledSheet>        
      </Grid>
    </Grid>
  )
})

export const MessageCardMemo = memo(MessageCard, 
  (prev, next) => 
    prev.messageId === next.messageId 
    && (!prev.sentByMe || !next.sentByMe || !(prev.delivery || next.delivery) || _.isEqual(prev.delivery, next.delivery))
    && (next.highlight === next.messageId) === (prev.highlight === prev.messageId));