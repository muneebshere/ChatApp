import _ from "lodash";
import React, { useState, memo, useRef, useLayoutEffect, useEffect, useMemo, RefObject } from "react";
import { useUpdateEffect } from "usehooks-ts";
import styled from "@emotion/styled";
import { Theme, useMediaQuery } from "@mui/material";
import { CircularProgress, IconButton, Stack } from "@mui/joy";
import { SendRounded, KeyboardDoubleArrowDownOutlined } from "@mui/icons-material";
import { MessageListMemo } from "./MessageList";
import { useSize } from "./Hooks/useSize";
import { StyledSheet, StyledScrollbar, DisableSelectTypography } from "./CommonElementStyles";
import { StyledScrollingTextarea } from "./TextareaAutosize";
import { ReplyingToProps, ReplyingToMemo } from "./ReplyingTo";
import { MessageCardContext, MessageCardContextData } from "./MessageCard";
import { ReplyingToInfo } from "../../../shared/commonTypes";
import { Chat } from "../ChatClasses";
import { truncateText } from "../../../shared/commonFunctions";
import { ChatHeaderMemo } from "./ChatHeader";
import Toast from "./Toast";

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
  changed: () => boolean;
}

type ChatViewProps = {
  chat: Chat,
  message: string,
  setMessage: (m: string) => void,
  lastScrolledTo: ScrollState,
  setLastScrolledTo: (lastScrolledTo: ScrollState) => void,
  allowLeaveFocus: React.RefObject<boolean>,
  giveBackFocus: React.MutableRefObject<() => void>
}

const getIsScrolledDown = (scrollElement: HTMLDivElement, tolerance = 1) => scrollElement.scrollTop >= scrollElement.scrollHeight - scrollElement.clientHeight - tolerance;

function useOrientationState(): OrientationState {
  const orientationRef = useRef(orientation());
  const orientationState = useMemo<OrientationState>(() => ({
    lastOrientation: () => orientationRef.current,
    setNewOrientation: () => {
      orientationRef.current = orientation();
    },
    changed: () => orientation() !== orientationState.lastOrientation()
  }), []);

  return orientationState;
}

type UseReplyingTo = [string, (replyTo: ReplyingToInfo) => void, JSX.Element];

function useReplyingTo(chatWith: string, setHighlight: (highlight: string) => void, belowXL: boolean, focus: () => void): UseReplyingTo {
  const [replyTo, setReplyTo] = useState<ReplyingToInfo>(null);

  const replyToElement = useMemo(() => {
    if (!replyTo) return null;
    const { replyId, displayText: content, replyToOwn } = replyTo;
    const displayText = truncateText(content, belowXL ? 80 : 200);
    const replyData: ReplyingToProps = { chatWith, replyId, displayText, replyToOwn, sentByMe: false, highlightReplied: setHighlight, renderClose: () => setReplyTo(null) };
    return (<ReplyingToMemo {...replyData}/>);
  }, [replyTo]);

  const setReply = (replyTo: ReplyingToInfo) => {
    setReplyTo(replyTo);
    focus();
  }

  return [replyTo?.replyId, setReply, replyToElement];
}

function useScrollRestore(scrollRef: RefObject<HTMLDivElement>, 
                          lastScrolledTo: ScrollState, 
                          setLastScrolledTo: (scroll: ScrollState) => void, 
                          orientationState: OrientationState): [() => void, (element: HTMLDivElement) => void, boolean] {
  
  const inViewRef = useRef(new Map<string, number>());
  const messagesRef = useRef(new Map<string, [HTMLDivElement, boolean]>());
  const currentScroll = useRef<ScrollState>(lastScrolledTo);
  const observerRef = useRef<IntersectionObserver>(null);
  const selectingRef = useRef(false);
  const [rendered, setRendered] = useState(false);

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
      if (notSeen && intersectionRect.bottom && intersectionRect.bottom <= boundingClientRect.bottom) {
        target?.dispatchEvent(new CustomEvent("seen", { detail: { timestamp: Date.now() }}));
      }
    }
  }

  function calculateIsInView(id: string): [boolean, number] {
    const element = messagesRef.current.get(id)?.[0];
    if (!element) return null;
    const elementRect = element.getBoundingClientRect();
    const scrollRect = scrollRef.current.getBoundingClientRect();
    const topOffset = elementRect.top - scrollRect.top - 8;
    return [elementRect.top < scrollRect.bottom && elementRect.bottom > scrollRect.top + 10, topOffset];
  }

  function selectCurrentElement() {
    if (selectingRef.current) {
      return;
    }
    if (orientationState.changed()) {
      return;
    }
    selectingRef.current = true;
    if (inViewRef.current.size === 0 || getIsScrolledDown(scrollRef.current)) {
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
    const scrollRect = scrollRef.current.getBoundingClientRect();
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
    const scrollRect = scrollRef.current.getBoundingClientRect();
    const scrollTop = scrollRef.current.scrollTop;
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
    setTimeout(() => {
      const lastScrolledTo = currentScroll.current && calculateScrollPosition(currentScroll.current);
      const scrollElement = scrollRef.current;
      const top = lastScrolledTo || scrollElement.scrollHeight;
      scrollElement.scrollTo({ top, behavior: "instant" });
      setTimeout(() => orientationState.setNewOrientation(), 50);
    }, 10);
  }

  useLayoutEffect(() => {
    const threshold = _.range(0, 21).map((n) => n / 20);
    const observer = new IntersectionObserver(onIntersect, { threshold, root: scrollRef.current });
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
    let top = lastScrolledTo && calculateScrollPosition(lastScrolledTo);
    setTimeout(() => {
      const scrollElement = scrollRef.current;
      top ||= scrollElement.scrollHeight;
      scrollElement.scrollTo({ top, behavior: "instant" });
      setRendered(true);
    }, 200);
    window.screen.orientation.addEventListener("change", onOrientationChange);

    return () => {
      window.screen.orientation.removeEventListener("change", onOrientationChange);
      const lastScrolledTo = !getIsScrolledDown(scrollRef.current) ? currentScroll.current : null;
      setLastScrolledTo(lastScrolledTo);
    }
  }, []);

  return [selectCurrentElement, registerMessageRef, rendered];
}

function useScrollOnResize(scrollRef: RefObject<HTMLDivElement>,
                  lastOrientation: () => OrientationType,
                  setIsScrolledDown: (isScrolledDown: boolean) => void) {
  const previousHeightRef = useRef(0);
  const [, scrollHeight] = useSize(scrollRef, "content");

  useUpdateEffect(() => {
    if (previousHeightRef.current === 0) {
      previousHeightRef.current = scrollHeight;
      return;
    }
    const scrollElement = scrollRef.current;
    const heightDiff = scrollHeight - previousHeightRef.current;
    previousHeightRef.current = scrollHeight; 
    if (orientation() === lastOrientation()) {
      if (heightDiff < 0 || (heightDiff > 0 && !getIsScrolledDown(scrollElement, 2))) {
        scrollRef.current.scrollBy({ top: -heightDiff, behavior: "instant" });
      }
    }
    if (scrollElement.scrollHeight <= scrollElement.clientHeight + Number.EPSILON) {
      setIsScrolledDown(true);
    }
  }, [scrollHeight]);
}

const ChatView = function({ chat, message, setMessage, lastScrolledTo, setLastScrolledTo, allowLeaveFocus, giveBackFocus }: ChatViewProps) {
  const belowXL = useMediaQuery((theme: Theme) => theme.breakpoints.down("xl"));
  const mutationRef = useRef<MutationObserver>(null);
  const mainRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const messageRef = useRef(message);
  const wasScrolledDownRef = useRef(true);
  const waitingHighlightRef = useRef("");
  const [chatDetails, setChatDetails] = useState(chat.details);
  const { displayName } = chatDetails;
  const [highlighted, setHighlight] = useState("");
  const [isScrolledDown, setIsScrolledDown] = useState(true);
  const [keyboardHeight, setKeyboardHeight] = useState(0);
  const [chatMessageLists, setChatMessageLists] = useState(chat.messages);
  const [loadingMore, setLoadingMore] = useState(false);
  const [toastTrigger, triggerToast] = useState<{ off?: boolean }>({ off: true });
  const orientationState = useOrientationState();
  const [replyId, setReplyTo, replyToElement] = useReplyingTo(displayName, setHighlight, belowXL, () => textareaRef.current.focus());
  const [width, ] = useSize(scrollRef, "content");
  const [updateCurrentElement, registerMessageRef, rendered] = useScrollRestore(scrollRef, lastScrolledTo, setLastScrolledTo, orientationState);
  const notRenderedCSS: React.CSSProperties = useMemo(() => 
    !rendered
      ? { visibility: "hidden" }
      : {}, [rendered]);
  const toggleScroll = (scrollOn: boolean) => { 
    scrollRef.current.style.overflowY = scrollOn ? "scroll" : "hidden";
    scrollRef.current.style.paddingRight = scrollOn ? "8px" : "14px"
  }

  const highlightReplied = (messageId: string) => {
    if (!messageId && waitingHighlightRef.current) {
      waitingHighlightRef.current = ""; 
    }
    if (!messageId || chat.hasMessage(messageId)) {
      window.setTimeout(() => setHighlight(messageId), 50);
    }
    else {
      waitingHighlightRef.current = messageId;
      setLoadingMore(true);
      setTimeout(() => {
        scrollRef.current.scrollTo({ top: 0, behavior: "smooth" });
        mutationRef.current.observe(scrollRef.current, { attributes: false, characterData: false, childList: true, subtree: true });
        chat.loadUptoId(messageId);
      }, 10);
    }
  }
  const contextData = useMemo<MessageCardContextData>(() => ({ chatWith: displayName, highlighted, highlightReplied, registerMessageRef, setReplyTo, toggleScroll, displayToast: () => triggerToast({}) }), [displayName, highlighted]);

  const scrollHandler = (event: Event) => {
    const scrollbar = event.target as HTMLDivElement;
    if (scrollbar.scrollTop < 1 && chat.canLoadFurther) {
      scrollbar.scrollTo({ top: 1, behavior: "instant" });
      if (!waitingHighlightRef.current && !orientationState.changed()) chat.loadNext();
    }
    if (scrollbar.scrollHeight <= scrollbar.clientHeight + Number.EPSILON) {
      setIsScrolledDown(true);
      return;
    }
    setIsScrolledDown(getIsScrolledDown(scrollbar, 2));
    updateCurrentElement();
  }

  const debouncedScrollHandler = _.debounce(scrollHandler, 50, { trailing: true, maxWait: 50 });

  const mutationCallback: MutationCallback = (records) => {
    if (!waitingHighlightRef.current) return;
    for (const { addedNodes } of records) {
      for (const node of addedNodes) {
        for (const childNode of (node as Element).querySelectorAll(".MessageCard")) {
          const element = childNode as Element;
          if (element.id === waitingHighlightRef.current) {
            mutationRef.current.disconnect();
            window.setTimeout(() => setHighlight(waitingHighlightRef.current), 50);
          }
          else if (element.getBoundingClientRect().top < scrollRef.current.getBoundingClientRect().top) {
            element.scrollIntoView({ behavior: "smooth", block: "start" });
          }
        }
      }
    }
  };

  const debouncedSendTyping = _.debounce(() => {
    if (chatDetails.isOnline) {
      chat.sendTyping("typing", Date.now());
    }
  }, 1000, { maxWait: 1000, leading: true, trailing: true });

  useEffect(() => () => debouncedScrollHandler.cancel());
  
  useScrollOnResize(scrollRef, orientationState.lastOrientation, setIsScrolledDown);

  useUpdateEffect(() => {
    wasScrolledDownRef.current = isScrolledDown;
  }, [isScrolledDown]);

  useEffect(() => {
    chat.lastDraft = null;
    chat.subscribe((event) => {
      if (event === "details-change") {
        setChatDetails(chat.details);
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
          setTimeout(() => {
            scrollRef.current.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "instant" });
          }, 10);
        }
      }
    });
    return () => {
      chat.lastDraft = messageRef.current;
      setMessage(messageRef.current);
      chat.unsubscribe();
    }
  }, []);

  useLayoutEffect(() => {
    const updateHeight = () => setKeyboardHeight((navigator as any).virtualKeyboard.boundingRect.height || 0);
    updateHeight();
    scrollRef.current.addEventListener("scroll", debouncedScrollHandler);
    window.visualViewport.addEventListener("resize", updateHeight);
    mutationRef.current = new MutationObserver(mutationCallback);
    giveBackFocus.current = () => textareaRef.current?.focus();

    return () => {
      scrollRef.current?.removeEventListener("scroll", debouncedScrollHandler);
      window.visualViewport.removeEventListener("resize", updateHeight);
      mutationRef.current?.disconnect();
      mutationRef.current = null;
      giveBackFocus.current = null;
    }
  }, []);

  const sendMessage = () => {
    const text = messageRef.current;
    if (!text.trim()) return;
    const timestamp = Date.now();
    chat.sendMessage({ text, timestamp, replyId}).then((success) => {
      scrollRef.current.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "instant" });
    });
    chat.sendTyping("stopped-typing", Date.now());
    setReplyTo(null);
    messageRef.current = "";
    textareaRef.current.value = "";
  }

  return (
    <StyledSheet ref={mainRef} sx={{ height: "100%", display: "flex", flexDirection: "column", overflow: "clip" }}>
      <Stack direction="column" spacing={1} sx={{ flex: 1, flexBasis: "content", display: "flex", flexDirection: "column", overflow: "clip" }}>
        <ChatHeaderMemo {...{ belowXL, chatDetails }}/>
        {(!rendered || loadingMore) &&
          <div style={{ width: "100%", display: "flex", justifyContent: "center", paddingBlock: "4px"}}>
            <CircularProgress size="sm" variant="soft" color="success"/>
          </div>}
        <StyledScrollbar ref={scrollRef} sx={{ paddingBottom: 0, paddingTop: chat.canLoadFurther ? "1px" : 0, ...notRenderedCSS }}>
          <MessageCardContext.Provider value={contextData}>
            <MessageListMemo 
              key={displayName}
              chatMessageLists={chatMessageLists}/>
          </MessageCardContext.Provider>
            {!isScrolledDown &&
          <ScrollDownButton onClick={ () => scrollRef.current.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "instant" }) } style={{ bottom: `${keyboardHeight + 150}px` }}>
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
            paddingInline: "2px" }}>
          <StyledScrollingTextarea
            openKeyboardManual
            autoFocus={true}
            ref={textareaRef}
            placeholder="Type a message"
            defaultValue={message}
            onChange={(e) => { 
              messageRef.current = e?.target?.value || "";
              debouncedSendTyping();
             }}
            onSubmit={sendMessage}
            onBlur={(e) => {
              chatDetails.isOnline && chat.sendTyping("stopped-typing", Date.now());
              if (!allowLeaveFocus.current) e.target.focus();
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
      <Toast 
        trigger={toastTrigger}
        containerStyle={{ 
          position: "fixed",
          top: undefined,
          left: undefined,
          bottom: "150px",
          right: `${(width)/2 - (belowXL ? 0 : 10)}px`,
          width: "80px", 
          height: "30px", 
          borderRadius: "15px",
          display: "flex",
          backgroundColor: "#d2d2d2",
          boxShadow: "0px 0px 2px 1px #d6d6d6" }}>
        <DisableSelectTypography sx={{ margin: "auto", width: "fit-content", height: "fit-content", fontWeight: "bold", fontSize: "13px", color: "#696969" }}>
          Copied!
        </DisableSelectTypography>
      </Toast>
    </StyledSheet>);
}

export const ChatViewMemo = memo(ChatView, () => true);