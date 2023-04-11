import _ from "lodash";
import React, { useState, memo, useRef, useLayoutEffect, useEffect, useCallback } from "react";
import { useEffectOnce, useIsFirstRender, useUpdateEffect } from "usehooks-ts";
import { useInView } from "react-intersection-observer";
import { IconButton, Stack, Typography } from "@mui/joy";
import { SendRounded, ArrowBackSharp, KeyboardDoubleArrowDownOutlined } from "@mui/icons-material";
import { MessageListMemo } from "./MessageList";
import { Item, StyledScrollbar, useSize } from "./Common";
import styled from "@emotion/styled";
import { Theme, useMediaQuery } from "@mui/material";
import { StyledScrollingTextarea } from "./TextareaAutosize/TextareaAutosize";
import { chats } from "./prvChats";
import { flushSync } from "react-dom";

export type ScrollState = { id: string, index: number, offset: number, isRatio?: true };

type ChatViewProps = {
  chatWith: string,
  message: string,
  setMessage: (m: string) => void,
  lastScrolledTo: ScrollState,
  setLastScrolledTo: (lastScrolledTo: ScrollState) => void
}

type Scroller = {
  getRect: () => DOMRect;
  getScroll: () => number;
  setScroll: (scroll: number) => void;
  incScroll: (by: number) => void;
  element: () => HTMLDivElement;
}

type ScrollRestoreReturnType = [() => void, (element: HTMLDivElement) => void, () => OrientationType];

const chatMap = new Map(chats.map(({chatWith, messages}) => ([chatWith, messages])));

const minKeyboard = 300;
const barHeight = () => document.querySelector("#viewportHeight").clientHeight - window.innerHeight;
const keyboardHeight = () => document.querySelector("#viewportHeight").clientHeight - window.visualViewport.height;
const isKeyboardOpen = () => keyboardHeight() > minKeyboard;
const orientation = () => window.screen.orientation.type;
const createScroller = (scrollRef: React.MutableRefObject<HTMLDivElement>) => {
  const getRect = () => scrollRef.current.getBoundingClientRect();
  const getScroll = () => scrollRef.current.scrollTop;
  const setScroll = (scroll: number) => { scrollRef.current.scrollTop = scroll || scrollRef.current.scrollHeight; };
  const incScroll = (by: number) => { scrollRef.current.scrollTop += by; };
  const element = () => scrollRef.current;
  return { getRect, getScroll, setScroll, incScroll, element };

} 
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

function useIsScrolledDown(): [(event: Event) => void, () => boolean] {
  const [isScrolledDown, setIsScrolledDown] = useState(false);
  
  const scrollHandler = (event: Event) => {
    const scrollbar = event.target as HTMLDivElement;
    const scrollFinished = scrollbar.scrollTop >= scrollbar.scrollHeight - scrollbar.clientHeight - 1;
    setIsScrolledDown(scrollFinished);
  }

  return [scrollHandler, useCallback(() => isScrolledDown, [isScrolledDown])];

}

function useUpdateHeight(scroller: Scroller, isScrolledDown: () => boolean): [number, (newHeight: number) => void] {
  const previousMsgBarHeightRef = useRef(24);
  const [msgBarHeight, setMessageBarHeight] = useState(24);

  const onHeightUpdate = (newHeight: number) => {
    const heightDiff = newHeight - previousMsgBarHeightRef.current;
    if (heightDiff !== 0) {
      setMessageBarHeight(newHeight);
    }
  };

  useUpdateEffect(() => {
    const heightDiff = msgBarHeight - previousMsgBarHeightRef.current;
    if (heightDiff > 0 || (heightDiff < 0 && !isScrolledDown())) {
      scroller.incScroll(heightDiff);
    }
    previousMsgBarHeightRef.current = msgBarHeight; 
  }, [msgBarHeight]);

  return [msgBarHeight, onHeightUpdate];
}

function useResize(scroller: Scroller, 
                  isScrolledDown: () => boolean, 
                  lastOrientation: () => OrientationType, 
                  currentDistance: () => number): [number, () => boolean, (distance: number) => void] {
  const previousDistance = useRef(0);
  const lastKeyboardOpenRef = useRef(false);
  const previousUnderbarRef = useRef(barHeight());
  const [underbar, setUnderbar] = useState(previousUnderbarRef.current);
  const [first, setFirst] = useState(true);
  const [isResizing, setIsResizing] = useState(false);
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

  const setDistance = (distance: number) => {
    previousDistance.current = distance;
    console.log(`Current distance: ${distance}`);
  }

  useEffect(() => { titleRef(document.querySelector("#titleBar")); }, []);
  
  const onResize = () => {
    if (orientation() !== lastOrientation()) {
      return;
    }
    flushSync(() => {
      setIsResizing(true);
      const lastKeyboardOpen = lastKeyboardOpenRef.current;
      const currentBar = barHeight();
      const barDiff = currentBar - previousUnderbarRef.current;
      const keyboardOpen = isKeyboardOpen();
      let scrollBy = 0;
      if (keyboardOpen && !lastKeyboardOpen) {
        setUnderbar(0);
        if (!isScrolledDown()) {
          scrollBy += barDiff ? currentBar : -currentBar;
        }
      }
      else if (!keyboardOpen && currentBar > 1e-2) {
        setUnderbar(currentBar);
        setTimeout(() => { scrollBy += currentBar; }, 5)
        if (lastKeyboardOpen) {
          window.scrollTo(0, 0);
          (document.querySelector("#titleBar") as HTMLElement)?.click()
        }
      }
      else {
        setUnderbar(0);
        if (!keyboardOpen && barDiff && !isScrolledDown()) {
          scrollBy += barDiff;
        }
        else {
          const newDistance = currentDistance();
          const distanceDiff = newDistance - previousDistance.current;
          setDistance(newDistance);
          if (distanceDiff < 0 || (distanceDiff > 0 && !isScrolledDown())) {
            scrollBy += distanceDiff;
          }
        }
      }
      lastKeyboardOpenRef.current = keyboardOpen;
      setIsResizing(false);
      scroller.incScroll(scrollBy);
    })
  }

  const debouncedResizeHandler = _.debounce(onResize, 50, { trailing: true, maxWait: 50 });

  useLayoutEffect(() => {
    setDistance(currentDistance());
    window.addEventListener("resize", debouncedResizeHandler);

    return () => {
      debouncedResizeHandler.cancel();
      window.removeEventListener("resize", debouncedResizeHandler);
    }
  }, []);

  useUpdateEffect(() => {
    previousUnderbarRef.current = underbar;
  }, [underbar]);

  return [underbar, useCallback(() => isResizing, [isResizing]), setDistance];
}

function useScrollRestore(scroller: Scroller, lastScrolledTo: ScrollState, setLastScrolledTo: (scroll: ScrollState) => void): ScrollRestoreReturnType {
  
  const inViewRef = useRef(new Map<string, number>());
  const messagesRef = useRef(new Map<string, [HTMLDivElement, boolean]>());
  const currentScroll = useRef<ScrollState>(lastScrolledTo);
  const observerRef = useRef<IntersectionObserver>(null);
  const orientationRef = useRef(orientation());
  const selectingRef = useRef(false);

  const registerMessageRef = (element: HTMLDivElement) => {
    if (!element) return;
    const observer = observerRef.current;
    observer?.observe(element);
    messagesRef.current.set(element.id, [element, false]);
  }

  const onIntersect = (entries: IntersectionObserverEntry[]) => {
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

  const calculateIsInView = (id: string): [boolean, number] => {
    const element = messagesRef.current.get(id)?.[0];
    if (!element) return null;
    const elementRect = element.getBoundingClientRect();
    const scrollRect = scroller.getRect();
    const topOffset = elementRect.top - scrollRect.top - 8;
    return [elementRect.top < scrollRect.bottom && elementRect.bottom > scrollRect.top + 10, topOffset];
  }

  const selectCurrentElement = () => {
    if (selectingRef.current) {
      return;
    }
    if (orientation() !== orientationRef.current) {
      return;
    }
    selectingRef.current = true;
    if (inViewRef.current.size === 0) {
      currentScroll.current = null;
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

  const containsListTop = (listTop: number, element: Element) => {
    if (!element) return false;
    const { top, bottom } = element.getBoundingClientRect();
    return listTop >= top && listTop <= bottom;
  }

  const calculateScrollState = (id: string): ScrollState => {
    const mainElement = messagesRef.current.get(id)?.[0];
    if (!mainElement) return null;
    const scrollRect = scroller.getRect();
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

  const calculateScrollPosition = ({ id, index, offset, isRatio }: ScrollState) => {
    const element = messagesRef.current.get(id)?.[0];
    if (!element) return null;
    const scrollRect = scroller.getRect();
    const scrollTop = scroller.getScroll();
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

  const onOrientationChange = () => {
    const lastScrolledTo = currentScroll.current;
    scroller.setScroll(lastScrolledTo && calculateScrollPosition(lastScrolledTo));
    orientationRef.current = orientation();
  }

  useLayoutEffect(() => {
    const threshold = _.range(0, 21).map((n) => n / 20);
    const observer = new IntersectionObserver(onIntersect, { threshold, root: scroller.element() });
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
    scroller.setScroll(lastScrolledTo && calculateScrollPosition(lastScrolledTo));
    window.screen.orientation.addEventListener("change", onOrientationChange);

    return () => {
      window.screen.orientation.removeEventListener("change", onOrientationChange);
      setLastScrolledTo(currentScroll.current);
    }
  }, []);

  return [selectCurrentElement, registerMessageRef, () => orientationRef.current];
}

const ChatView = function({ chatWith, message, setMessage, lastScrolledTo, setLastScrolledTo }: ChatViewProps) {
  const messages = chatMap.get(chatWith);
  const scrollRef = useRef<HTMLDivElement>(null);
  const baseLineRef = useRef<HTMLDivElement>(null);
  const currentDistance = () => (baseLineRef.current?.getBoundingClientRect()?.bottom || 0) - (scrollRef.current?.getBoundingClientRect()?.bottom || 0);
  const scroller = createScroller(scrollRef)
  const [updateScrolledDown, isScrolledDown] = useIsScrolledDown();
  const [updateCurrentElement, registerMessageRef, lastOrientation] = useScrollRestore(scroller ,lastScrolledTo, setLastScrolledTo);
  const [underbar, isResizing, setDistance] = useResize(scroller, isScrolledDown, lastOrientation, currentDistance);
  const [msgBarHeight, onHeightUpdate] = useUpdateHeight(scroller, isScrolledDown);
  const belowXL = useMediaQuery((theme: Theme) => theme.breakpoints.down("xl"));
  const [width, ] = useSize(scrollRef);

  const scrollHandler = (event: Event) => {
    if (!isResizing()) {
      setDistance(currentDistance());
      updateScrolledDown(event);
      updateCurrentElement();
    }
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
    <Item sx={{ height: "100%", display: "flex", flexDirection: "column", overflow: "clip" }}>
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
            {!isScrolledDown() &&
          <ScrollDownButton onClick={ () => scrollRef.current.scrollTop = scrollRef.current.scrollHeight }>
            <KeyboardDoubleArrowDownOutlined sx={{ color: "#6e6e6e", fontSize: "2rem", placeSelf: "center" }}/>
          </ScrollDownButton>}
          <div id="baseLine" ref={baseLineRef} style={{ minWidth: "100%", maxHeight: "2px" }}>&nbsp;</div>
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
    </Item>);
}

export const ChatViewMemo = memo(ChatView, ({ chatWith: prevChat, message: prevMess }, { chatWith: nextChat, message: nextMess }) => prevChat === nextChat && prevMess === nextMess);