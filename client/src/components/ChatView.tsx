import _ from "lodash";
import React, { useState, memo, useRef, useLayoutEffect, useEffect, useMemo, useCallback } from "react";
import { useUpdateEffect } from "usehooks-ts";
import styled from "@emotion/styled";
import { Theme, useMediaQuery } from "@mui/material";
import { Avatar, Badge, CircularProgress, IconButton, Stack } from "@mui/joy";
import { SendRounded, ArrowBackSharp, KeyboardDoubleArrowDownOutlined, CachedSharp } from "@mui/icons-material";
import { MessageListMemo } from "./MessageList";
import { useSize } from "./Hooks/useSize";
import { StyledSheet, StyledScrollbar, DisableSelectTypography } from "./CommonElementStyles";
import { StyledScrollingTextarea } from "./TextareaAutosize";
import { chats, truncateText } from "../prvChats";
import { ReplyingToProps, ReplyingToMemo } from "./ReplyingTo";
import { MessageCardContext } from "./MessageCard";
import { ReplyingToInfo } from "../../../shared/commonTypes";
import { Chat, ChatMessageList } from "../client";
import useResizeObserver from "@react-hook/resize-observer";
import { match } from "ts-pattern";
import { flushSync } from "react-dom";

const ScrollDownButton = styled.div`
  display: grid;
  position: fixed;
  bottom: 150px;
  right: 35px;
  height: 45px;
  width: 45px;
  z-index: 10;
  background-color: rgba(244, 244, 244, 0.8);
  border: 1px solid #d2d2d2;
  border-radius: 100%;
  box-shadow: 0px 0px 4px #dadada;
  cursor: pointer;

  :hover {
    filter: brightness(0.9);
  }`;

const orientation = () => window.screen.orientation.type;

export type ScrollState = { id: string, index: number, offset: number, isRatio?: true };

export type OrientationState = {
  lastOrientation: () => OrientationType;
  setNewOrientation: () => void;
}

type ChatViewProps = {
  chat: Chat,
  message: string,
  setMessage: (m: string) => void,
  lastScrolledTo: ScrollState,
  setLastScrolledTo: (lastScrolledTo: ScrollState) => void
}

const getIsScrolledDown = (scrollbar: HTMLDivElement, tolerance = 1) => scrollbar.scrollTop >= scrollbar.scrollHeight - scrollbar.clientHeight - tolerance;

function useOrientationState(): OrientationState {
  const orientationRef = useRef(orientation());
  const orientationState = useMemo<OrientationState>(() => ({
    lastOrientation: () => orientationRef.current,
    setNewOrientation: () => {
      orientationRef.current = orientation();
    }
  }), []);

  return orientationState;
}

type UseReplyingTo = [string, (replyTo: ReplyingToInfo) => void, JSX.Element];

function useReplyingTo(chatWith: string, setHighlight: (highlight: string) => void, belowXL: boolean): UseReplyingTo {
  const [replyTo, setReplyTo] = useState<ReplyingToInfo>(null);

  const replyToElement = useMemo(() => {
    if (!replyTo) return null;
    const { id, displayText: content, replyToOwn } = replyTo;
    const displayText = truncateText(content, belowXL ? 80 : 200);
    const replyData: ReplyingToProps = { chatWith, id, displayText, replyToOwn, sentByMe: false, highlightReplied: setHighlight, renderClose: () => setReplyTo(null) };
    return (<ReplyingToMemo {...replyData}/>);
  }, [replyTo]);

  return [replyTo?.id, setReplyTo, replyToElement];
}

function useScrollRestore(scrollbar: () => HTMLDivElement, 
                          lastScrolledTo: ScrollState, 
                          setLastScrolledTo: (scroll: ScrollState) => void, 
                          orientationState: OrientationState,
                          earliestLoaded: () => number,
                          loadMore: () => void,
                          waitingHighlightRef: React.MutableRefObject<string>,
                          setHighlight: (messageId: string) => void): [() => void, (element: HTMLDivElement) => void] {
  
  const inViewRef = useRef(new Map<string, number>());
  const messagesRef = useRef(new Map<string, [HTMLDivElement, boolean]>());
  const currentScroll = useRef<ScrollState>(lastScrolledTo);
  const observerRef = useRef<IntersectionObserver>(null);
  const selectingRef = useRef(false);

  function registerMessageRef(element: HTMLDivElement) {
    if (!element) return;
    const observer = observerRef.current;
    observer?.observe(element);
    messagesRef.current.set(element.id, [element, false]);
  }

  function onIntersect(entries: IntersectionObserverEntry[]) {
    for (const { isIntersecting, intersectionRatio, time, target, boundingClientRect, intersectionRect } of entries) {
      const { id } = target;
      const [element, visited] = messagesRef.current.get(id);
      if (!visited) {
        messagesRef.current.set(id, [element, true]);
      }
      if (!inViewRef.current.has(id)) {
        if (isIntersecting && intersectionRatio > 0) {
          inViewRef.current.set(id, time);
        }
      }
      const notSeen = Number.isNaN(parseInt((target as HTMLElement).dataset.seen));
      const timestamp = parseInt((target as HTMLElement).dataset.timestamp);
      if (notSeen && intersectionRect.bottom && intersectionRect.bottom <= boundingClientRect.bottom) {
        target.dispatchEvent(new CustomEvent("seen", { detail: { timestamp: Date.now() }}));
      }
      if (timestamp === earliestLoaded() && intersectionRect.top && intersectionRect.top >= boundingClientRect.top) {
        loadMore();
      }
      const waitingHighlight = waitingHighlightRef.current;
      if (waitingHighlight && id === waitingHighlight && intersectionRect.top && intersectionRect.top >= boundingClientRect.top) {
        setTimeout(() => {
          setHighlight(waitingHighlight);
          waitingHighlightRef.current = null;
        }, 50);
      }
    }
  }

  function calculateIsInView(id: string): [boolean, number] {
    const element = messagesRef.current.get(id)?.[0];
    if (!element) return null;
    const elementRect = element.getBoundingClientRect();
    const scrollRect = scrollbar().getBoundingClientRect();
    const topOffset = elementRect.top - scrollRect.top - 8;
    return [elementRect.top < scrollRect.bottom && elementRect.bottom > scrollRect.top + 10, topOffset];
  }

  function selectCurrentElement() {
    if (selectingRef.current) {
      return;
    }
    if (orientation() !== orientationState.lastOrientation()) {
      return;
    }
    selectingRef.current = true;
    if (inViewRef.current.size === 0) {
      currentScroll.current = null;
      selectingRef.current = false;
      return;
    }
    const offsets = Array.from(inViewRef.current.keys()).map((id) => {
      const [isInView, topOffset] = calculateIsInView(id) || [];
      return { id, isInView, topOffset };
    })
    const [inView, notInView] = _.partition(offsets, ({ isInView }) => isInView);
    const closestElement = _.orderBy(inView, [({ topOffset }) => topOffset], ["asc"])[0];
    currentScroll.current = closestElement ? calculateScrollState(closestElement.id) : null;
    notInView.forEach(({ id }) => inViewRef.current.delete(id));
    selectingRef.current = false;
  }

  function containsListTop(listTop: number, element: Element) {
    if (!element) return false;
    const { top, bottom } = element.getBoundingClientRect();
    return listTop >= top && listTop <= bottom;
  }

  function calculateScrollState (id: string): ScrollState {
    const mainElement = messagesRef.current.get(id)?.[0];
    if (!mainElement) return null;
    const scrollRect = scrollbar().getBoundingClientRect();
    const listTop = scrollRect.top;
    const replyElement = mainElement.querySelector("div > div > div > button > div > div > div > span > div > span");
    const paraElements = mainElement.querySelectorAll("div > div > div > span > div > p");
    const elements = [replyElement, ...paraElements];
    const index = elements.findIndex((e) => containsListTop(listTop, e));
    if (index >= 0) {
      const elementRect = elements[index].getBoundingClientRect();
      let offset = elementRect.top - listTop;
      if (index >= 0) {
        offset = offset / elementRect.height;
      }
      return { id, index, offset, isRatio: true };
    }
    else {
      const offsets = _.orderBy([mainElement, ...elements].map((e, i) => ({ i: i - 1, e, o: e?.getBoundingClientRect().top - listTop })), ["o"], ["asc"]);
      let { e: element, i: index, o: offset } = offsets.find(({ o }) => o > 0) || {};
      if (!element) {
        index = -1;
        offset = mainElement.getBoundingClientRect().top - listTop;
      }
      return { id, index, offset };
    }
  }

  function calculateScrollPosition({ id, index, offset, isRatio }: ScrollState) {
    const element = messagesRef.current.get(id)?.[0];
    if (!element) return null;
    const scrollRect = scrollbar().getBoundingClientRect();
    const scrollTop = scrollbar().scrollTop;
    let selectedElement: Element = null;
    if (index < 0) {
      selectedElement = element;
    }
    else if (index === 0) {
      selectedElement = element.querySelector("div > div > div > button > div > div > div > span > div > span");
    }
    else {
      selectedElement = element.querySelector(`div > div > div > span > div > p:nth-child(${index})`);
    }
    const elementRect = selectedElement.getBoundingClientRect();
    const scrollPosition = scrollTop + elementRect.top - scrollRect.top;
    if (isRatio) {
      offset = offset * elementRect.height;
    }
    return scrollPosition - offset;
  }

  function onOrientationChange() {
    const lastScrolledTo = currentScroll.current;
    setTimeout(() => {
      const top = lastScrolledTo && calculateScrollPosition(lastScrolledTo) || scrollbar().scrollHeight;
      scrollbar().scrollTo({ top, behavior: "instant" });
      setTimeout(() => orientationState.setNewOrientation(), 50);
    }, 10);
  }

  useLayoutEffect(() => {
    const threshold = _.range(0, 21).map((n) => n / 20);
    const observer = new IntersectionObserver(onIntersect, { threshold, root: scrollbar() });
    messagesRef.current.forEach(([element, visited], ) => {
      if (!visited) {
        observer.observe(element);
      }
    });
    observerRef.current = observer;
    return () => {
      observer.disconnect();
      observerRef.current = null;
      messagesRef.current.clear();
    }
  }, []);

  useLayoutEffect(() => {
    const top = lastScrolledTo && calculateScrollPosition(lastScrolledTo) || scrollbar().scrollHeight;
    scrollbar().scrollTo({ top, behavior: "instant" });
    window.screen.orientation.addEventListener("change", onOrientationChange);

    return () => {
      window.screen.orientation.removeEventListener("change", onOrientationChange);
      const lastScrolledTo = !getIsScrolledDown(scrollbar()) ? currentScroll.current : null;
      setLastScrolledTo(lastScrolledTo);
    }
  }, []);

  return [selectCurrentElement, registerMessageRef];
}

function useScrollOnResize(scrollbar: () => HTMLDivElement,
                  lastOrientation: () => OrientationType,
                  setIsScrolledDown: (isScrolledDown: boolean) => void) {
  const previousHeightRef = useRef(0);
  const [scrollHeight, setScrollHeight] = useState(0);
  useResizeObserver(scrollbar(), (entry) => setScrollHeight(entry.contentRect.height));

  useUpdateEffect(() => {
    if (previousHeightRef.current === 0) {
      previousHeightRef.current = scrollHeight;
      return;
    }
    const heightDiff = scrollHeight - previousHeightRef.current;
    previousHeightRef.current = scrollHeight; 
    if (orientation() === lastOrientation()) {
      if (heightDiff < 0 || (heightDiff > 0 && !getIsScrolledDown(scrollbar(), 2))) {
        scrollbar().scrollBy({ top: -heightDiff, behavior: "instant" });
      }
    }
    if (scrollbar().scrollHeight <= scrollbar().clientHeight + Number.EPSILON) {
      setIsScrolledDown(true);
    }
  }, [scrollHeight]);
}

const ChatView = function({ chat, message, setMessage, lastScrolledTo, setLastScrolledTo }: ChatViewProps) {
  const { contactDetails: { displayName, contactName, profilePicture } } = chat;
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const messageRef = useRef(message);
  const belowXL = useMediaQuery((theme: Theme) => theme.breakpoints.down("xl"));
  const scrollRef = useRef<HTMLDivElement>(null);
  const scrollbar = () => scrollRef.current;
  const [highlighted, setHighlight] = useState("");
  const [isScrolledDown, setIsScrolledDown] = useState(true);
  const wasScrolledDownRef = useRef(true);
  const orientationState = useOrientationState();
  const [replyId, setReplyTo, replyToElement] = useReplyingTo(displayName, setHighlight, belowXL);
  const [width, ] = useSize(scrollRef);
  const toggleScroll = (scrollOn: boolean) => { 
    scrollbar().style.overflowY = scrollOn ? "scroll" : "hidden";
    scrollbar().style.paddingRight = scrollOn ? "8px" : "14px"
  }
  const [keyboardHeight, setKeyboardHeight] = useState(0);
  const [chatMessageLists, setChatMessageLists] = useState(chat.messages);
  const [isOnline, setIsOnline] = useState(chat.hasRoom);
  const [isOtherTyping, setIsOtherTyping] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const isFocusedRef = useRef(false);
  const waitingHighlightRef = useRef("");
  const [updateCurrentElement, registerMessageRef] = useScrollRestore(scrollbar, lastScrolledTo, setLastScrolledTo, orientationState, () => chat.earliestLoaded, () => chat.canLoadFurther && chat.loadNext(), waitingHighlightRef, setHighlight);
  const highlightReplied = (messageId: string) => {
    if (!messageId || chat.hasMessage(messageId)) {
      setHighlight(messageId);
    }
    else {
      chat.loadUptoId(messageId).then(() => {
        waitingHighlightRef.current = messageId;
        setTimeout(() => scrollbar().scrollTo({ top: 0, behavior: "smooth" }), 10);
      });
    }
  }
  const contextData = useMemo(() => ({ chatWith: displayName, highlighted, highlightReplied, registerMessageRef, setReplyTo, toggleScroll }), [displayName, highlighted]);

  const scrollHandler = (event: Event) => {
    const scrollbar = event.target as HTMLDivElement;
    if (scrollbar.scrollHeight <= scrollbar.clientHeight + Number.EPSILON) {
      setIsScrolledDown(true);
      return;
    }
    setIsScrolledDown(getIsScrolledDown(scrollbar));
    updateCurrentElement();
  }

  const debouncedScrollHandler = _.debounce(scrollHandler, 50, { trailing: true, maxWait: 50 });
  const debouncedSendTyping = _.debounce(() => {
    if (isFocusedRef.current) {
      chat.sendEvent("typing", Date.now());
    }
  }, 1000, { maxWait: 1000, leading: true, trailing: true });
  
  useScrollOnResize(scrollbar, orientationState.lastOrientation, setIsScrolledDown);

  useUpdateEffect(() => {
    wasScrolledDownRef.current = isScrolledDown;
  }, [isScrolledDown]);

  useEffect(() => {
    chat.subscribe((event) => {
      if (event === "room-established") {
        setIsOnline(true);
      }
      else if (event === "room-disconnected") {
        setIsOnline(false);
      }
      else if (event === "typing-change") {
        setIsOtherTyping(chat.isOtherTyping);
      }
      else if (event === "loading-earlier") {
        setLoadingMore(true);
      }
      else if (event === "loaded-earlier") {
        setLoadingMore(false);
      }
      else if (event === "added") {
        setChatMessageLists(chat.messages);
      }
      else if (event === "received-new") {
        if (wasScrolledDownRef.current) {
          window.setTimeout(() => scrollbar().scrollTo({ top: scrollbar().scrollHeight, behavior: "instant" }), 10);
        }
      }
    });
    return () => {
      setMessage(messageRef.current);
      chat.unsubscribe();
    }
  }, []);

  useLayoutEffect(() => {
    const updateHeight = () => setKeyboardHeight((navigator as any).virtualKeyboard.boundingRect.height || 0);
    updateHeight();
    scrollRef.current.addEventListener("scroll", debouncedScrollHandler);
    window.visualViewport.addEventListener("resize", updateHeight);

    return () => {
      debouncedScrollHandler.cancel();
      scrollRef.current.removeEventListener("scroll", debouncedScrollHandler);
      window.visualViewport.removeEventListener("resize", updateHeight);
    }
  }, []);

  const sendMessage = () => {
    const text = messageRef.current;
    if (!text.trim()) return;
    const timestamp = Date.now();
    chat.sendMessage({ text, timestamp, replyId}).then((success) => {
      scrollbar().scrollTo({ top: scrollbar().scrollHeight, behavior: "instant" });
    });
    setReplyTo(null);
    textareaRef.current.value = "";
  }

  return (
    <StyledSheet sx={{ height: "100%", display: "flex", flexDirection: "column", overflow: "clip" }}>
      <Stack direction="column" spacing={1} sx={{ flex: 1, flexBasis: "content", display: "flex", flexDirection: "column", overflow: "clip" }}>
        <div style={{ width: "100%", display: "flex", flexDirection: "row", borderBottom: "1px solid #d1d1d1", paddingBottom: "8px" }}>
          <Stack direction="row" spacing={2} sx={{ flex: 1, justifyContent: "left" }}>
            {belowXL && 
              <IconButton variant="outlined" color="neutral" onClick={() => { window.location.hash = "" }}>
                <ArrowBackSharp sx={{ fontSize: "2rem" }}/>
              </IconButton>}
            <Stack direction="row" spacing={2} sx={{ flexGrow: 1, flexWrap: "wrap", alignContent: "center" }}>
              <Avatar src={profilePicture} size="lg"/>
              <Stack direction="column" sx={{ justifyContent: "center" }}>
                <DisableSelectTypography level="h6" fontWeight="lg" sx={{ width: "fit-content" }}>
                  {contactName || displayName}
                </DisableSelectTypography>
                {isOnline &&
                  <DisableSelectTypography sx={{ fontSize: "14px", color: "#656565", display: "flex", justifyContent: "left" }}>
                    {isOtherTyping ? "typing..." : "online"}
                  </DisableSelectTypography>}
              </Stack>
            </Stack>
          </Stack>
            {belowXL && 
              <IconButton variant="outlined" color="neutral" onClick={() => window.location.reload() }>
                <CachedSharp sx={{ fontSize: "2rem" }}/>
              </IconButton>}
        </div>
        <StyledScrollbar ref={scrollRef} sx={{ paddingBottom: 0 }}>
          {loadingMore &&
            <div style={{ width: "100%", display: "flex", justifyContent: "center", paddingBlock: "4px"}}>
              <CircularProgress size="sm" variant="soft" color="success"/>            
            </div>}
          <MessageCardContext.Provider value={contextData}>
            <MessageListMemo 
              key={displayName} 
              chatMessageLists={chatMessageLists}/>
          </MessageCardContext.Provider>
            {!isScrolledDown &&
          <ScrollDownButton onClick={ () => scrollRef.current.scrollBy({ top: scrollRef.current.scrollHeight, behavior: "instant" }) } style={{ bottom: `${keyboardHeight + 150}px` }}>
            <KeyboardDoubleArrowDownOutlined sx={{ color: "#6e6e6e", fontSize: "2rem", placeSelf: "center" }}/>
          </ScrollDownButton>}
        </StyledScrollbar>
        <Stack
          direction="row" 
          spacing={1} 
          sx={{ 
            width,
            flex: 0, 
            flexBasis: "content", 
            display: "flex", 
            flexDirection: "row", 
            flexWrap: "nowrap",
            borderTopRightRadius: 20,
            borderBottomRightRadius: 20,
            paddingBottom: "8px",
            paddingInline: "2px",
            zIndex: 20 }}>
          <StyledScrollingTextarea
            ref={textareaRef}
            placeholder="Type a message"
            defaultValue={message}
            onChange={(e) => { 
              messageRef.current = e.target.value;
              debouncedSendTyping();
             }}
            onSubmit={sendMessage}
            onFocus={() => {
              isFocusedRef.current = true;
            } }
            onBlur={() => {
              isFocusedRef.current = false;
              chat.sendEvent("stopped-typing", Date.now());
            }}
            minRows={1}
            maxRows={5} 
            style={{ flex: 1 }}
            startDecorator={replyToElement}
            startDecoratorStyle={{ width: "100%", paddingRight: belowXL ? "0px" : "80px", display: "flex", justifyContent: "flex-start", marginBottom: "4px" }}/>
            <IconButton 
              variant="outlined"
              color="success" 
              onClick={sendMessage}
              sx={{ flexGrow: 0, flexBasis: "content", height: "fit-content", alignSelf: "center", borderRadius: 20, backgroundColor: "var(--joy-palette-success-plainHoverBg)" }}>
              <SendRounded sx={{ fontSize: "2rem"}}/>
            </IconButton>
        </Stack>
      </Stack>
    </StyledSheet>);
}

export const ChatViewMemo = memo(ChatView, () => true);