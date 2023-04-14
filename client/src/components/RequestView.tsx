import _ from "lodash";
import React, { useState, memo, useRef, useLayoutEffect, useEffect, useCallback } from "react";
import { flushSync } from "react-dom";
import { useUpdateEffect } from "usehooks-ts";
import { useInView } from "react-intersection-observer";
import styled from "@emotion/styled";
import { Theme, useMediaQuery } from "@mui/material";
import { IconButton, Stack, Typography } from "@mui/joy";
import { SendRounded, ArrowBackSharp, KeyboardDoubleArrowDownOutlined } from "@mui/icons-material";
import { MessageListMemo } from "./MessageList";
import { useSize } from "./Hooks/useSize";
import { StyledSheet, StyledScrollbar } from "./CommonElementStyles";
import { StyledScrollingTextarea } from "./TextareaAutosize";
import { chats } from "../prvChats";

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

  :hover {
    filter: brightness(0.9);
  }`;

export type ScrollState = { id: string, index: number, offset: number, isRatio?: true };

type ChatViewProps = {
  chatWith: string,
  message: string,
  setMessage: (m: string) => void,
  lastScrolledTo: ScrollState,
  setLastScrolledTo: (lastScrolledTo: ScrollState) => void
}

type ScrollRestoreReturnType = [() => void, (element: HTMLDivElement) => void, () => OrientationType];

const chatMap = new Map(chats.map(({chatWith, messages}) => ([chatWith, messages])));

const minKeyboard = 300;
const barHeight = () => document.querySelector("#viewportHeight").clientHeight - window.innerHeight;
const keyboardHeight = () => document.querySelector("#viewportHeight").clientHeight - window.visualViewport.height;
const isKeyboardOpen = () => keyboardHeight() > minKeyboard;
const orientation = () => window.screen.orientation.type;
const getIsScrolledDown = (scrollbar: HTMLDivElement, tolerance = 1) => scrollbar.scrollTop >= scrollbar.scrollHeight - scrollbar.clientHeight - tolerance;

function useUpdateHeight(scrollbar: () => HTMLDivElement): [number, (newHeight: number) => void] {
  const previousMsgBarHeightRef = useRef(24);
  const [msgBarHeight, setMessageBarHeight] = useState(24);

  function onHeightUpdate(newHeight: number) {
    const heightDiff = newHeight - previousMsgBarHeightRef.current;
    if (heightDiff !== 0) {
      setMessageBarHeight(newHeight);
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

function useScrollRestore(scrollbar: () => HTMLDivElement, lastScrolledTo: ScrollState, setLastScrolledTo: (scroll: ScrollState) => void): ScrollRestoreReturnType {
  
  const inViewRef = useRef(new Map<string, number>());
  const messagesRef = useRef(new Map<string, [HTMLDivElement, boolean]>());
  const currentScroll = useRef<ScrollState>(lastScrolledTo);
  const observerRef = useRef<IntersectionObserver>(null);
  const orientationRef = useRef(orientation());
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
    if (orientation() !== orientationRef.current) {
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
    currentScroll.current = calculateScrollState(closestElement.id);
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
    orientationRef.current = orientation();
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
      setLastScrolledTo(currentScroll.current);
    }
  }, []);

  return [selectCurrentElement, registerMessageRef, () => orientationRef.current];
}

function useResize(scrollbar: () => HTMLDivElement,
                  lastOrientation: () => OrientationType) {
  const previousHeightRef = useRef(0);
  const lastKeyboardOpenRef = useRef(false);
  const previousUnderbarRef = useRef(barHeight());
  const [underbar, setUnderbar] = useState(previousUnderbarRef.current);
  const [first, setFirst] = useState(true);
  const { ref: titleRef } = useInView({ 
    threshold: 0.9, 
    initialInView: true, 
    onChange: (inView, { isIntersecting, intersectionRatio }) => {
      const currentBar = barHeight();
      if (currentBar > 1e-2 && !lastKeyboardOpenRef.current && !first) {
        setUnderbar(inView && isIntersecting && intersectionRatio >= 0.5 ? currentBar : 0);
      }
      else { 
        setFirst(false);
      }
    } 
  });

  useEffect(() => { titleRef(document.querySelector("#titleBar")); }, []);
  
  function onResize() {
    if (orientation() !== lastOrientation()) {
      return;
    }
    flushSync(() => {
      const lastKeyboardOpen = lastKeyboardOpenRef.current;
      const currentBar = barHeight();
      const barDiff = currentBar - previousUnderbarRef.current;
      const keyboardOpen = isKeyboardOpen();
      let scrollBy = 0;
      if (keyboardOpen && !lastKeyboardOpen) {
        setUnderbar(0);
        if (!getIsScrolledDown(scrollbar())) {
          scrollBy += barDiff ? currentBar : -currentBar;
        }
      }
      else if (!keyboardOpen && currentBar > 1e-2) {
        setUnderbar(currentBar);
        setTimeout(() => scrollbar().scrollBy({ top: currentBar, behavior: "instant" }), 5);
        if (lastKeyboardOpen) {
          window.scrollTo(0, 0);
          (document.querySelector("#titleBar") as HTMLElement)?.click()
        }
      }
      else {
        setUnderbar(0);
        if (!keyboardOpen && barDiff && !getIsScrolledDown(scrollbar())) {
          scrollBy += barDiff;
        }
        else {
          const newHeight = scrollbar().getBoundingClientRect().height
          const heightDiff = newHeight - previousHeightRef.current;
          previousHeightRef.current = newHeight;
          if (heightDiff < 0 || (heightDiff > 0 && !getIsScrolledDown(scrollbar(), 2))) {
            scrollBy -= heightDiff;
          }
        }
      }
      scrollbar().scrollBy({ top: scrollBy, behavior: "instant" });
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

  useUpdateEffect(() => {
    previousUnderbarRef.current = underbar;
  }, [underbar]);

  return underbar;
}

const ChatView = function({ chatWith, message, setMessage, lastScrolledTo, setLastScrolledTo }: ChatViewProps) {
  const messages = chatMap.get(chatWith);
  const scrollRef = useRef<HTMLDivElement>(null);
  const scrollbar = () => scrollRef.current;
  const [isScrolledDown, setIsScrolledDown] = useState(false);
  const [msgBarHeight, onHeightUpdate] = useUpdateHeight(scrollbar);
  const [updateCurrentElement, registerMessageRef, lastOrientation] = useScrollRestore(scrollbar, lastScrolledTo, setLastScrolledTo);
  const underbar = useResize(scrollbar, lastOrientation);
  const belowXL = useMediaQuery((theme: Theme) => theme.breakpoints.down("xl"));
  const [width, ] = useSize(scrollRef);

  const scrollHandler = (event: Event) => {
    const scrollFinished = getIsScrolledDown(event.target as HTMLDivElement);
    setIsScrolledDown(scrollFinished);
    updateCurrentElement();
  }

  const debouncedScrollHandler = _.debounce(scrollHandler, 50, { trailing: true, maxWait: 50 });

  useLayoutEffect(() => {
    scrollRef.current.addEventListener("scroll", debouncedScrollHandler);

    return () => {
      debouncedScrollHandler.cancel();
      scrollRef.current.removeEventListener("scroll", debouncedScrollHandler);
    }
  }, []);

  return (
    <StyledSheet sx={{ height: "100%", display: "flex", flexDirection: "column", overflow: "clip" }}>
      <Stack direction="column" spacing={1} sx={{ flex: 1, flexBasis: "content", display: "flex", flexDirection: "column", overflow: "clip" }}>
        <Stack direction="row" spacing={2}>
          {belowXL && 
            <IconButton variant="outlined" color="neutral" onClick={() => { window.location.hash = "" }}>
              <ArrowBackSharp sx={{ fontSize: "2rem" }}/>
            </IconButton>}
          <Typography level="h5" sx={{ textAlign: "left", flex: 0, flexBasis: "content", display: "flex", flexWrap: "wrap", alignContent: "center" }}>
            {chatWith}
          </Typography>
        </Stack>       
        <StyledScrollbar ref={scrollRef} sx={{ paddingBottom: 0 }}>
          <MessageListMemo 
            key={chatWith} 
            messages={messages} 
            chatWith={chatWith}
            registerMessageRef={registerMessageRef}/>
            {!isScrolledDown &&
          <ScrollDownButton onClick={ () => scrollRef.current.scrollBy({ top: scrollRef.current.scrollHeight, behavior: "instant" }) }>
            <KeyboardDoubleArrowDownOutlined sx={{ color: "#6e6e6e", fontSize: "2rem", placeSelf: "center" }}/>
          </ScrollDownButton>}
        </StyledScrollbar>
        <div style={{ height: msgBarHeight + underbar, width: "100%", backgroundColor: "white", marginBottom: 8 }}/>
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
            placeholder="Type a message"
            defaultValue={message}
            onChange={ (e) => setMessage(e.target.value) }
            onHeightUpdate={onHeightUpdate}
            minRows={1}
            maxRows={5} 
            style={{ flex: 1 }}/>
            <IconButton 
              variant="outlined"
              color="success" 
              sx={{ flexGrow: 0, flexBasis: "content", height: "fit-content", alignSelf: "center", borderRadius: 20, backgroundColor: "var(--joy-palette-success-plainHoverBg)" }}>
              <SendRounded sx={{ fontSize: "2rem"}}/>
            </IconButton>
        </Stack>
      </Stack>
    </StyledSheet>);
}

export const ChatViewMemo = memo(ChatView, ({ chatWith: prevChat, message: prevMess }, { chatWith: nextChat, message: nextMess }) => prevChat === nextChat && prevMess === nextMess);