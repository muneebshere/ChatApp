import _ from "lodash";
import { v4 as uuidv4 } from "uuid";
import React, { createContext, forwardRef, memo, useCallback, useContext, useLayoutEffect, useMemo, useRef, useState } from "react";
import { useEffectOnce, useUpdateEffect } from "usehooks-ts";
import { Grid, Stack } from "@mui/joy";
import { DoneSharp, DoneAllSharp, HourglassTop } from "@mui/icons-material";
import { Tooltip, TooltipTrigger, TooltipContent } from "./Tooltip";
import Popover, { PopoverTrigger, PopoverContent } from "./Popover";
import { DisableSelectTypography, StyledSheet } from "./CommonElementStyles";
import remarkGfm from "remark-gfm";
import remarkMath from "remark-math";
import twemoji from "../custom_modules/remark-twemoji";
import rehypeRaw from "rehype-raw";
import rehypeKatex from "rehype-katex";
import mermaid from "mermaid";
import { DateTime } from "luxon";
import SvgMessageCard from "./SvgMessageCard";
import "katex/dist/katex.min.css";
import { ReplyingToMemo } from "./ReplyingTo";
import { ReactMarkdownLastPara } from "./CommonElementStyles";
import { ReplyingToInfo, DeliveryInfo } from "../../../shared/commonTypes";
import { ElementRects } from "@floating-ui/react";
import useSwipeDrag from "./Hooks/useSwipeDrag";
import { ChatMessage } from "../ChatClasses";
import { useSize } from "./Hooks/useSize";
import styled from "@emotion/styled";
import { logError } from "../../../shared/commonFunctions";
import { CodeComponent } from "react-markdown/lib/ast-to-react";

mermaid.initialize({ startOnLoad: false });

interface HTMLDivElementScroll extends HTMLDivElement {
  scrollIntoViewIfNeeded(centerIfNeeded?: boolean): void;
}

export type MessageCardContextData = Readonly<{
  chatWith: string;
  highlighted: string;
  totalWidth: number;
  highlightReplied: (id: string) => void;
  setReplyTo: (replyingTo: ReplyingToInfo) => void;
  registerMessageRef: (ref: HTMLDivElement) => void;
  displayToast: () => void;
  toggleScroll?: (scrollOn: boolean) => void;
}>;

export const MessageCardContext = createContext<MessageCardContextData>(null);

const ScrollingTypography: typeof DisableSelectTypography = styled(DisableSelectTypography)`
scrollbar-width: thin;
scrollbar-color: #afafaf #d1d1d1;

::-webkit-scrollbar {
  height: 3px;
}
::-webkit-scrollbar-track {
  background-color: #d1d1d1;
  border-radius: 4px;
}
::-webkit-scrollbar-thumb {
  background-color: #7c7c7c;
  border-radius: 4px;
}` as any;

function formatTooltipDate(timestamp: number) {
  const date = DateTime.fromMillis(timestamp);
  return `${date.toFormat("d LLLL ")}'${date.toFormat("yy")}, ${date.toFormat("h:mm a")}`;
}

function modifyOnlyEmojies(text: string) {
  const emojiOnlyInsert = `<span class="onlyEmoji">&#8288;</span>`;
  const isEmojiOnly = !text.replace(/[\p{Extended_Pictographic}\u{1f3fb}\u{1f3fc}\u{1f3fd}\u{1f3fe}\u{1f3ff}]/gmu, "").trim();
  if (isEmojiOnly) return text.replace(/(\p{Extended_Pictographic})/gmu, (match, g1) => `${emojiOnlyInsert}${g1}`);
  else return text;
}

function StatusButton({ delivery }: { delivery: DeliveryInfo }) {
  if (!delivery) {
    return <HourglassTop sx={{ color: "gold", rotate: "-90deg", fontSize: "1rem" }}/>;
  }
  else {
    const { delivered, seen } = delivery
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

function MessageCardWithHighlight(message: { chatMessage: ChatMessage } & MessageCardContextData) {
  const { highlighted, highlightReplied, setReplyTo, displayToast, registerMessageRef, chatWith, toggleScroll, chatMessage, totalWidth } = message;
  const { messageId, text, timestamp, replyingToInfo, sentByMe } = chatMessage.displayMessage;
  const [darken, setDarken] = useState(false);
  const [isFirstOfType, setIsFirstOfType] = useState(chatMessage.isFirstOfType);
  const [delivery, setDelivery] = useState(chatMessage.delivery);
  const scrollRef = useRef<HTMLDivElementScroll>(null);
  const bodyRef = useRef<HTMLSpanElement>(null);
  const statusRef = useRef<HTMLDivElement>(null);
  const floatingRef = useRef<HTMLDivElement>(null);
  const sheetRef = useRef<HTMLDivElement>(null);
  const [statusWidth, statusHeight] = useSize(statusRef, "client");
  const [fixedWidth, setFixedWidth] = useState(0);
  const offsetFunc = (rects: ElementRects) => {
    const crossAxis = (-floatingRef.current?.getBoundingClientRect()?.width || 0) + rects.reference.width;
    return { crossAxis }
  }
  const replyingData = useMemo(() => ({ replyId: messageId, replyToOwn: sentByMe, displayText: text }), []);
  const onReplyClick: React.MouseEventHandler<HTMLDivElement> = (event) => {
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
  const handlers = useSwipeDrag(scrollRef, 100, 70, action, toggleScroll, fixedWidth ? bodyRef : null);

  useEffectOnce(() => {
    chatMessage.subscribe((event) => {
      if (event === "first") {
        setIsFirstOfType(chatMessage.isFirstOfType);
      }
      else {
        setDelivery(chatMessage.delivery);
      }
    });
    return () => chatMessage.unsubscribe();
  })

  useUpdateEffect(() => {
    if (highlighted === messageId) { 
      scrollRef.current.scrollIntoViewIfNeeded(true);
      setDarken(true);
    } 
  }, [highlighted]);

  useUpdateEffect(() => {
    if (!darken) {
      highlightReplied("");
    }
  }, [darken]);

  useLayoutEffect(() => {
    if (!bodyRef.current || totalWidth <= 0) return;
    const maxAllowableWidth = totalWidth - 72;
    setFixedWidth(bodyRef.current.scrollWidth > maxAllowableWidth ? maxAllowableWidth : 0);
  }, [totalWidth])

  useLayoutEffect(() => {
    if (!registerMessageRef) return;
    const seenListener = (ev: any) => {
      chatMessage.signalEvent("seen", ev.detail.timestamp);
      ev.target.removeEventListener("seen" as any, seenListener);
    };
    const messageRef = sheetRef.current;
    if (messageRef) {
      if (!sentByMe && !delivery?.seen) {
        messageRef.addEventListener("seen" as any, seenListener);
      }
      registerMessageRef(messageRef);
    }
    return () => !sentByMe && sheetRef.current?.removeEventListener("seen" as any, seenListener);
  }, []);

  const repliedMessage = useMemo(() => {
    const props = replyingToInfo ? { chatWith, sentByMe, highlightReplied, ...replyingToInfo } : null;
    return replyingToInfo
      ? <ReplyingToMemo { ...props} maxChars={200}/>
      : null

  }, [messageId]);

  const side = sentByMe ? "flex-end" : "flex-start";
  const messageColor = sentByMe ? "#d7fad1" : "white";
  return (
    <Grid container sx={{ display: "flex", flexGrow: 1, justifyContent: side, height: "fit-content", maxWidth: "100%" }} onClick={onReplyClick} ref={scrollRef} {...handlers}>
      <Grid xs={10} sm={8} lg={7} sx={{ display: "flex", flexGrow: 0, justifyContent: side, height: "fit-content" }}>
        <StyledSheet className="MessageCard" sx={{ width: "100%", display: "flex", flexGrow: 1, justifyContent: side, alignContent: "flex-start", padding: 0, margin: 0 }} ref={sheetRef} id={messageId} data-seen={sentByMe ? 10 : delivery?.seen}>
          <SvgMessageCard background={messageColor} first={isFirstOfType} sentByMe={sentByMe} shadowColor="#adb5bd" darken={darken} darkenFinished={() => setDarken(false) }>
            <Stack direction="column"
              sx={{ width: "fit-content", 
                    padding: 1.5, 
                    paddingBottom: 0.5, 
                    alignContent: "flex-start", 
                    textAlign: "start" }}>
                {repliedMessage && repliedMessage}
                <MessageBody {...{ chatWith, messageId, fixedWidth, statusWidth, statusHeight, text, displayToast }} ref={(bodyElem) => bodyRef.current = bodyElem}/>
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
                {sentByMe &&
                  <StatusButton {...{ delivery }}/>
                }
              </Stack>
            </Stack>
          </SvgMessageCard>
        </StyledSheet>        
      </Grid>
    </Grid>
  )
}

type MessageBodyProps = Readonly<{
  chatWith: string,
  messageId: string,
  fixedWidth: number,
  statusWidth: number,
  statusHeight: number,
  text: string,
  displayToast: () => void
}>

const MessageBody = forwardRef<HTMLSpanElement>(function ({ chatWith, messageId, fixedWidth, statusWidth, statusHeight, text, displayToast }: MessageBodyProps, bodyRef: (elem: HTMLSpanElement) => void) {

  function killFootnotes(bodyElem: HTMLSpanElement) {
    bodyRef(bodyElem);
    const links = bodyElem?.querySelectorAll("a") || [];
    for (const link of links) {
      if (link.href.includes("#")) link.removeAttribute("href");
    }
  }

  async function doubleClickCopy(event: React.MouseEvent<HTMLSpanElement, MouseEvent>) {
    if (event.button === 0 && event.detail >= 2) {
      await navigator.clipboard.writeText(text);
      displayToast();
      if (window.navigator.userActivation.isActive) {
        window.navigator.vibrate(10);
      }
      event.stopPropagation();
    }
  }

  const handleMermaidOrCode: CodeComponent = 
    ({ node, inline, className, children, ...props }) => {
      if (className === "language-mermaid" && !inline) {
        const definition = (children as string[])[0];
        async function renderMermaid(elem: HTMLPreElement) {
          const id = `x${uuidv4().split("-")[0]}`;
          try {
            const { svg, bindFunctions } = await mermaid.render(id, definition, elem);
            elem.innerHTML = svg;
            bindFunctions(elem);
            const { height } = elem.getBoundingClientRect();
            document.querySelector(`#scroll-${chatWith.split(" ")[0]}`).scrollBy({ top: height, behavior: "instant" });
          }
          catch(e) {
            logError(e);
          }
        }
        return (<pre className="mermaid" ref={renderMermaid}>
          {definition}
        </pre>);
      }
      else {
        const code = (<code {...props} className={className}>
                        {children}
                      </code>);
        return inline
                  ? code
                  : (<pre className={className}>
                    {code}
                    </pre>);
      }
    }

  return (
    <ScrollingTypography
      id={`${messageId}-body`} 
      ref={killFootnotes}
      component="span"
      sx={{ 
        width: fixedWidth ? `${fixedWidth}px` : "fit-content",
        marginBottom: fixedWidth ? "12px" : undefined,
        paddingBottom: fixedWidth ? "2px" : undefined,
        overflowX: fixedWidth ? "scroll" : "clip",
        overflowY: "clip",
        "--markdown-emoji-size": "22px",
        "--markdown-large-emoji-size": "66px",
        "--markdown-margin-bottom": "8px",
        "--markdown-after-width": `${statusWidth}px`,
        "--markdown-after-height": `${statusHeight}px`,
        "--markdown-after-margin-top": "4px",
        "--markdown-after-margin-left": "16px",
        "::-webkit-scrollbar-button:end:increment": {
          display: "block",
          color: "transparent",
          width: `${statusWidth + 12}px`
        } }}
      onClick={doubleClickCopy}>
      <ReactMarkdownLastPara
        className="react-markdown"
        children={modifyOnlyEmojies(text)} 
        remarkPlugins={[remarkGfm, remarkMath, twemoji]}
        rehypePlugins={[rehypeKatex, rehypeRaw]}
        components={{ pre: "div", code: handleMermaidOrCode }}/>
    </ScrollingTypography>);
})

const MessageCardMemo = memo(MessageCardWithHighlight, 
  (prev, next) => 
    prev.chatWith === next.chatWith
    && prev.totalWidth === next.totalWidth
    && prev.chatMessage === next.chatMessage
    && (next.highlighted === next.chatMessage.messageId) === (prev.highlighted === prev.chatMessage.messageId));

export default function MessageCard(message: { chatMessage: ChatMessage }) {
  const context = useContext(MessageCardContext);
  const params = { ...message, ...context };
  return (<MessageCardMemo { ...params }/>)
}