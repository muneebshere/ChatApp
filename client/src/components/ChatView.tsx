import _ from "lodash";
import React, { useState, memo, useRef, useLayoutEffect, useEffect, useMemo, useCallback } from "react";
import { flushSync } from "react-dom";
import { useUpdateEffect } from "usehooks-ts";
import usePreviousValue from "beautiful-react-hooks/usePreviousValue";
import styled from "@emotion/styled";
import { Theme, useMediaQuery } from "@mui/material";
import { IconButton, Stack } from "@mui/joy";
import { SendRounded, ArrowBackSharp, KeyboardDoubleArrowDownOutlined } from "@mui/icons-material";
import { barHeight, isKeyboardOpen, orientation } from "./Main";
import { MessageListMemo } from "./MessageList";
import { useSize } from "./Hooks/useSize";
import { StyledSheet, StyledScrollbar, DisableSelectTypography } from "./CommonElementStyles";
import { StyledScrollingTextarea } from "./TextareaAutosize";
import { chats, truncateText } from "../prvChats";
import { ReplyingToProps, ReplyingToMemo } from "./ReplyingTo";
import { MessageCardContext } from "./MessageCard";
import { ReplyingToInfo } from "../../../shared/commonTypes";
import { Chat } from "../client";

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
  border-radius: 10px;
  box-shadow: 0px 0px 4px #dadada;
  cursor: pointer;

  :hover {
    filter: brightness(0.9);
  }`;

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
  setLastScrolledTo: (lastScrolledTo: ScrollState) => void,
  orientationState: OrientationState;
}

const chatMap = new Map(chats.map(({chatWith, messages}) => ([chatWith, messages])));

const getIsScrolledDown = (scrollbar: HTMLDivElement, tolerance = 1) => scrollbar.scrollTop >= scrollbar.scrollHeight - scrollbar.clientHeight - tolerance;

function useUpdateHeight(scrollbar: () => HTMLDivElement): [number, (newHeight: number) => void] {
  const previousMsgBarHeightRef = useRef(24);
  const [msgBarHeight, setMsgBarHeight] = useState(24);

  function onHeightUpdate(newHeight: number) {
    const heightDiff = newHeight - previousMsgBarHeightRef.current;
    if (heightDiff !== 0) {
      setMsgBarHeight(newHeight);
    }
  };

  useUpdateEffect(() => {
    const heightDiff = msgBarHeight - previousMsgBarHeightRef.current;
    if (heightDiff > 0 || (heightDiff < 0 && !getIsScrolledDown(scrollbar(), 2))) {
      scrollbar().scrollBy({ top: heightDiff, behavior: "instant" });
    }
    previousMsgBarHeightRef.current = msgBarHeight; 
  }, [msgBarHeight]);

  return [msgBarHeight, onHeightUpdate];
}

function useReplyingTo(chatWith: string, setHighlight: (highlight: string) => void, belowXL: boolean): [number, string, (replyTo: ReplyingToInfo) => void, (textarea: HTMLTextAreaElement) => void, JSX.Element] {
  const [replyTo, setReplyTo] = useState<ReplyingToInfo>(null);
  const [replyingToHeight, setReplyingToHeight] = useState(0);
  const previousReplyingToHeightRef = useRef(0);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  function setTextareaRef(textarea: HTMLTextAreaElement) {
    textareaRef.current = textarea;
  }

  function onElementUpdate(newElement: HTMLDivElement) {
    let newHeight = newElement?.getBoundingClientRect()?.height || 0;
    if (newHeight) {
      newHeight += 4;
    }
    const heightDiff = newHeight - previousReplyingToHeightRef.current;
    if (heightDiff !== 0) {
      setReplyingToHeight(newHeight);
      previousReplyingToHeightRef.current = newHeight;
    }
  };

  const replyToElement = useMemo(() => {
    if (!replyTo) return null;
    const { id, displayText: content, replyToOwn } = replyTo;
    const displayText = truncateText(content, belowXL ? 80 : 200);
    const replyData: ReplyingToProps = { chatWith, id, displayText, replyToOwn, sentByMe: false, setHighlight, renderClose: () => setReplyTo(null) };
    return (<ReplyingToMemo ref={onElementUpdate} {...replyData}/>);
  }, [replyTo]);

  return [replyingToHeight, replyTo?.id, setReplyTo, setTextareaRef, replyToElement];
}

function useScrollRestore(scrollbar: () => HTMLDivElement, lastScrolledTo: ScrollState, setLastScrolledTo: (scroll: ScrollState) => void, orientationState: OrientationState): [() => void, (element: HTMLDivElement) => void] {
  
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
    for (const { isIntersecting, intersectionRatio, time, target: { id } } of entries) {
      const [element, visited] = messagesRef.current.get(id);
      if (!visited) {
        messagesRef.current.set(id, [element, true]);
      }
      if (!inViewRef.current.has(id)) {
        if (isIntersecting && intersectionRatio > 0) {
          inViewRef.current.set(id, time);
        }
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
    const top = lastScrolledTo && calculateScrollPosition(lastScrolledTo) || scrollbar().scrollHeight;
    scrollbar().scrollTo({ top, behavior: "instant" });
    orientationState.setNewOrientation();
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
  const lastKeyboardOpenRef = useRef(false);
  const previousUnderbarRef = useRef(barHeight());
  const [underbar, setUnderbar] = useState(false);
  
  function onResize() {
    if (orientation() !== lastOrientation()) {
      return;
    }
    const scrollElement = scrollbar();
    flushSync(() => {
      const lastKeyboardOpen = lastKeyboardOpenRef.current;
      const currentBar = barHeight();
      const barDiff = currentBar - previousUnderbarRef.current;
      const keyboardOpen = isKeyboardOpen();
      let scrollBy = 0;
      if (keyboardOpen && !lastKeyboardOpen) {
        previousUnderbarRef.current = 0;
        setUnderbar(true);
        if (!getIsScrolledDown(scrollElement)) {
          scrollBy += barDiff ? currentBar : -currentBar;
        }
      }
      else if (!keyboardOpen && currentBar > 1e-2) {
        previousUnderbarRef.current = currentBar;
        setUnderbar(false);
        setTimeout(() => scrollElement?.scrollBy({ top: currentBar, behavior: "instant" }), 5);
        if (lastKeyboardOpen) {
          window.scrollTo(0, 0);
          (document.querySelector("#titleBar") as HTMLElement)?.click()
        }
      }
      else {
        setUnderbar(false);
        previousUnderbarRef.current = 0;
        if (!keyboardOpen && barDiff && !getIsScrolledDown(scrollElement)) {
          scrollBy += barDiff;
        }
        else {
          const newHeight = scrollElement.getBoundingClientRect().height
          const heightDiff = newHeight - previousHeightRef.current;
          previousHeightRef.current = newHeight;
          if (heightDiff < 0 || (heightDiff > 0 && !getIsScrolledDown(scrollElement, 2))) {
            scrollBy -= heightDiff;
          }
        }
      }
      scrollElement.scrollBy({ top: scrollBy, behavior: "instant" });
      if (scrollElement.scrollHeight <= scrollElement.clientHeight + Number.EPSILON) {
        setIsScrolledDown(true);
      }
      lastKeyboardOpenRef.current = keyboardOpen;
    })
  }

  useLayoutEffect(() => {
    previousHeightRef.current = scrollbar().getBoundingClientRect().height;
    window.addEventListener("resize", onResize);

    return () => {
      window.removeEventListener("resize", onResize);
    }
  }, []);

  return underbar;
}

function useAdjustbar(scrollbar: () => HTMLDivElement, underbar: boolean, msgBarHeight: number) { 
  const [adjustBar, setAdjustBar] = useState<number>(null);
  const prevMsgBar = usePreviousValue(msgBarHeight);

  const adjust = useCallback(() => {
    const currentBar = barHeight();
    if (underbar) {
      if (msgBarHeight > prevMsgBar && adjustBar === null && getIsScrolledDown(scrollbar())) {
        setAdjustBar(currentBar);
        setTimeout(() => scrollbar().scrollBy({ top: currentBar, behavior: "instant" }), 5);
      }
      else if (msgBarHeight < prevMsgBar && adjustBar) {
        setAdjustBar(0);
        if (getIsScrolledDown(scrollbar(), 2)) {
          setTimeout(() => scrollbar().scrollTo({ top: scrollbar().scrollHeight, behavior: "instant" }), 5);
        }
      }
    }
    else {
      setAdjustBar(null);
      if (getIsScrolledDown(scrollbar(), 57)) {
        scrollbar().scrollTo({ top: scrollbar().scrollHeight, behavior: "instant" })
      }
    }
  }, [adjustBar, msgBarHeight, underbar, prevMsgBar]);

  useUpdateEffect(adjust, [msgBarHeight, underbar]);

  return adjustBar;
}

const ChatView = function({ chat, message, setMessage, lastScrolledTo, setLastScrolledTo, orientationState }: ChatViewProps) {
  const { messages, contactDetails: { displayName } } = chat;
  const [, triggerRerender] = useState(2);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const belowXL = useMediaQuery((theme: Theme) => theme.breakpoints.down("xl"));
  const scrollRef = useRef<HTMLDivElement>(null);
  const scrollbar = () => scrollRef.current;
  const [highlight, setHighlight] = useState("");
  const [isScrolledDown, setIsScrolledDown] = useState(true);
  const underbar = useScrollOnResize(scrollbar, orientationState.lastOrientation, setIsScrolledDown);
  const [msgBarHeight, onHeightUpdate] = useUpdateHeight(scrollbar);
  const adjustBar = useAdjustbar(scrollbar, underbar, msgBarHeight);
  const [replyingToHeight, replyToId, setReplyTo, setTextareaRef, replyToElement] = useReplyingTo(displayName, setHighlight, belowXL);
  const [updateCurrentElement, registerMessageRef] = useScrollRestore(scrollbar, lastScrolledTo, setLastScrolledTo, orientationState);
  const [width, ] = useSize(scrollRef);
  const toggleScroll = (scrollOn: boolean) => { 
    scrollbar().style.overflowY = scrollOn ? "scroll" : "hidden";
    scrollbar().style.paddingRight = scrollOn ? "8px" : "14px"
  }
  const contextData = useMemo(() => ({ chatWith: displayName, highlight, setHighlight, registerMessageRef, setReplyTo, toggleScroll }), [highlight]);
  const [isTyping, setIsTyping] = useState(false);

  const scrollHandler = (event: Event) => {
    const scrollbar = event.target as HTMLDivElement;
    if (scrollbar.scrollHeight <= scrollbar.clientHeight + Number.EPSILON) {
      setIsScrolledDown(true);
      return;
    }
    const scrollFinished = getIsScrolledDown(scrollbar);
    setIsScrolledDown(scrollFinished);
    updateCurrentElement();
  }

  const debouncedScrollHandler = _.debounce(scrollHandler, 50, { trailing: true, maxWait: 50 });

  useEffect(() => {
    chat.subscribe("chatview", () => triggerRerender((rerender) => 10 / rerender));
    return () => {
      chat.unsubscribe("chatview");
      setMessage(textareaRef.current.value);
    }
  },[])

  useLayoutEffect(() => {
    scrollRef.current.addEventListener("scroll", debouncedScrollHandler);

    return () => {
      debouncedScrollHandler.cancel();
      scrollRef.current.removeEventListener("scroll", debouncedScrollHandler);
    }
  }, []);

  const sendMessage = () => {
    chat.sendMessage(textareaRef.current.value, Date.now(), replyToId).then((success) => {
      scrollbar().scrollTo({ top: scrollbar().scrollHeight, behavior: "instant" });
    });
    textareaRef.current.value = "";
  }

  return (
    <StyledSheet sx={{ height: "100%", display: "flex", flexDirection: "column", overflow: "clip" }}>
      <Stack direction="column" spacing={1} sx={{ flex: 1, flexBasis: "content", display: "flex", flexDirection: "column", overflow: "clip" }}>
        <Stack direction="row" spacing={2}>
          {belowXL && 
            <IconButton variant="outlined" color="neutral" onClick={() => { window.location.hash = "" }}>
              <ArrowBackSharp sx={{ fontSize: "2rem" }}/>
            </IconButton>}
          <DisableSelectTypography level="h5" sx={{ textAlign: "left", flex: 0, flexBasis: "content", display: "flex", flexWrap: "wrap", alignContent: "center" }}>
            {displayName}
          </DisableSelectTypography>
        </Stack>       
        <StyledScrollbar ref={scrollRef} sx={{ paddingBottom: 0 }}>
          <MessageCardContext.Provider value={contextData}>
            <MessageListMemo 
              key={displayName} 
              messages={messages}/>
          </MessageCardContext.Provider>
            {!isScrolledDown &&
          <ScrollDownButton onClick={ () => scrollRef.current.scrollBy({ top: scrollRef.current.scrollHeight, behavior: "instant" }) }>
            <KeyboardDoubleArrowDownOutlined sx={{ color: "#6e6e6e", fontSize: "2rem", placeSelf: "center" }}/>
          </ScrollDownButton>}
        </StyledScrollbar>
        <div style={{ height: msgBarHeight + replyingToHeight + (adjustBar || 0), width: "100%", backgroundColor: "white", marginBottom: 8 }}/>
        <Stack
          direction="row" 
          spacing={1} 
          sx={{ 
            position: "fixed",
            bottom: 0,
            width,
            flex: 0, 
            flexBasis: "content", 
            display: "flex", 
            flexDirection: "row", 
            flexWrap: "nowrap",
            borderTopRightRadius: 20,
            borderBottomRightRadius: 20,
            paddingBottom: "8px",
            zIndex: 20 }}>
          <StyledScrollingTextarea
            ref={(elem) => {
              textareaRef.current = elem;
              setTextareaRef(elem);
            }}
            placeholder="Type a message"
            defaultValue={message}
            onHeightUpdate={onHeightUpdate}
            onSubmit={sendMessage}
            minRows={1}
            maxRows={5} 
            style={{ flex: 1 }}
            autoFocus={isTyping}
            onFocus={() => setIsTyping(true) }
            onBlur={() => setIsTyping(false) }
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