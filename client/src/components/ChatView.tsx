import _ from "lodash";
import React, { useState, memo, useRef, useLayoutEffect, useEffect } from "react";
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

const chatMap = new Map(chats.map(({chatWith, messages}) => ([chatWith, messages])));

const minKeyboard = 300;
const barHeight = () => document.querySelector("#viewportHeight").clientHeight - window.innerHeight;
const keyboardHeight = () => window.screen.height - window.visualViewport.height;
const isKeyboardOpen = () => keyboardHeight() > minKeyboard;
const orientation = () => window.screen.orientation.type;

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

export type ScrollState = { id: string, offsetRatio: number };

type ChatViewProps = {
  chatWith: string,
  message: string,
  setMessage: (m: string) => void,
  lastScrolledTo: ScrollState,
  setLastScrolledTo: (lastScrolledTo: ScrollState) => void
}

const ChatView = function({ chatWith, message, setMessage, lastScrolledTo, setLastScrolledTo }: ChatViewProps) {
  const messages = chatMap.get(chatWith);
  const belowXL = useMediaQuery((theme: Theme) => theme.breakpoints.down("xl"));
  const inViewRef = useRef(new Map<string, number>());
  const messagesRef = useRef(new Map<string, [HTMLDivElement, boolean]>());
  const currentScroll = useRef<ScrollState>(lastScrolledTo);
  const observerRef = useRef<IntersectionObserver>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const [showScrollDown, setShowScrollDown] = useState(false);
  const [width, ] = useSize(scrollRef);
  const previousHeightRef = useRef(24);
  const previousScrollHeightRef = useRef(0);
  const showScrollDownRef = useRef(false);
  const previousUnderbarRef = useRef(barHeight());
  const lastKeyboardOpenRef = useRef(false);
  const orientationRef = useRef(orientation());
  const selectingRef = useRef(false);
  const [messageBarHeight, setMessageBarHeight] = useState(24);
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

  const calculateIsInView = (element: DOMRect, scroll: DOMRect) => element.top <= scroll.bottom && element.bottom >= scroll.top;

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
    const sortedInViewList = _.orderBy(Array.from(inViewRef.current.keys())
      .map((id) => ({ id, ...calculateScrollLocation(id) })), 
      [({ offsetRatio }) => Math.abs(offsetRatio)], ["asc"]);
    const [inView, notInView] = _.partition(sortedInViewList, ({ isInView }) => isInView);
    const { id, offsetRatio, scrollPosition } = inView[0];
    currentScroll.current = { id, offsetRatio };
    console.log(`Element ${id} with offsetRatio ${offsetRatio} selected with scrollPosition ${scrollPosition}`);
    if (inView.length > 0) {
      notInView.forEach(({ id }) => inViewRef.current.delete(id));
    }
    selectingRef.current = false;
  }

  const calculateScrollLocation = (id: string) => {
    const element = messagesRef.current.get(id)?.[0];
    if (!element) return null;
    const elementRect = element.getBoundingClientRect();
    const scrollRect = scrollRef.current.getBoundingClientRect();
    const height = scrollRect.height;
    const scrollTop = scrollRef.current.scrollTop;
    const scrollPosition = scrollTop + elementRect.top - scrollRect.top - 8;
    const topOffset = elementRect.top - scrollRect.top;
    const offsetRatio = topOffset / height
    const isInView = calculateIsInView(elementRect, scrollRect);
    return { scrollPosition, height, topOffset, offsetRatio, isInView };
  }

  const calculateScrollTo = ({ id, offsetRatio }: ScrollState) => {
    let { scrollPosition, height } = calculateScrollLocation(id) || {};
    if (!scrollPosition) return null;
    const offset = offsetRatio * height - 8;
    return [scrollPosition, scrollPosition - offset];
  }
  
  const scrollHandler = (event: Event) => {
    selectCurrentElement();
    const scrollbar = event.target as HTMLDivElement;
    const scrollFinished = scrollbar.scrollTop >= scrollbar.scrollHeight - scrollbar.clientHeight - 1;
    showScrollDownRef.current = !scrollFinished;
    setShowScrollDown(!scrollFinished);
  }

  const debouncedScrollHandler = _.debounce(scrollHandler, 50, { trailing: true, maxWait: 50 });

  const onOrientationChange = () => {
    const scrollbar = scrollRef.current;
    const lastScrolledTo = currentScroll.current;
    const [scrollPosition, scrollTop] = lastScrolledTo && calculateScrollTo(lastScrolledTo) || [];
    scrollbar.scrollTop = scrollTop || scrollbar.scrollHeight;
    console.log(`Scroll set to ${scrollbar.scrollTop} for ${lastScrolledTo.id} at ${lastScrolledTo.offsetRatio} and scrollPosition ${scrollPosition}`);
    orientationRef.current = orientation();
  }

  useLayoutEffect(() => {
    const scrollbar = scrollRef.current;
    const [, scrollTop] = lastScrolledTo && calculateScrollTo(lastScrolledTo) || [];
    scrollbar.scrollTop = scrollTop || scrollbar.scrollHeight;
    console.log(`Scroll set to ${scrollbar.scrollTop}`);
    previousScrollHeightRef.current = scrollbar.clientHeight;
    scrollbar.addEventListener("scroll", debouncedScrollHandler);
    window.screen.orientation.addEventListener("change", onOrientationChange);

    return () => {
      debouncedScrollHandler.cancel();
      scrollRef.current.removeEventListener("scroll", debouncedScrollHandler);
      window.screen.orientation.removeEventListener("change", onOrientationChange);
      setLastScrolledTo(currentScroll.current);
    }
  }, []);
  
  const onResize = () => {
    if (orientation() !== orientationRef.current) {
      return;
    }
    flushSync(() => {
      const scrollbar = scrollRef.current;
      const lastKeyboardOpen = lastKeyboardOpenRef.current;
      const showScrollDown = showScrollDownRef.current;
      const currentBar = barHeight();
      const barDiff = currentBar - previousUnderbarRef.current;
      const keyboardOpen = isKeyboardOpen();
      if (keyboardOpen && !lastKeyboardOpen) {
        setUnderbar(0);
        if (showScrollDown) {
          scrollbar.scrollTop += barDiff ? currentBar : -currentBar;
        }
      }
      else if (!keyboardOpen && currentBar > 1e-2) {
        setUnderbar(currentBar);
        setTimeout(() => { scrollbar.scrollTop += currentBar; }, 5);
        if (lastKeyboardOpen) {
          window.scrollTo(0, 0);
          (document.querySelector("#titleBar") as HTMLElement)?.click()
        }
      }
      else {
        setUnderbar(0);
        if (!keyboardOpen && barDiff && showScrollDown) {
          scrollbar.scrollTop += barDiff;
        }
        else {
          const newHeight = scrollbar.clientHeight;
          const heightDiff = newHeight - previousScrollHeightRef.current;
          if (heightDiff < 0 || (heightDiff > 0 && showScrollDown)) {
            scrollbar.scrollTop -= heightDiff;
          }
        }
      }
      lastKeyboardOpenRef.current = keyboardOpen;
    })
  }

  useLayoutEffect(() => {
    window.addEventListener("resize", onResize);

    return () => window.removeEventListener("resize", onResize);
  }, []);

  useLayoutEffect(() => {
    const observer = new IntersectionObserver((entries) => {
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
    }, 
    { threshold: _.range(0, 21).map((n) => n / 20), root: scrollRef.current });
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
  }, [])

  const onHeightUpdate = (newHeight: number) => {
    const heightDiff = newHeight - previousHeightRef.current;
    if (heightDiff !== 0) {
      setMessageBarHeight(newHeight);
    }
  };

  useUpdateEffect(() => {
    const heightDiff = messageBarHeight - previousHeightRef.current;
    if (heightDiff > 0 || (heightDiff < 0 && showScrollDownRef.current)) {
      scrollRef.current.scrollTop += heightDiff;
    }
    previousHeightRef.current = messageBarHeight; 
  }, [messageBarHeight]);

  useUpdateEffect(() => {
    previousUnderbarRef.current = underbar;
  }, [underbar]);

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
            registerMessageRef={(element) => {
              if (!element) return;
              const observer = observerRef.current;
              observer?.observe(element);
              messagesRef.current.set(element.id, [element, false]);
            }}/>
            {showScrollDown &&
          <ScrollDownButton onClick={ () => scrollRef.current.scrollTop = scrollRef.current.scrollHeight }>
            <KeyboardDoubleArrowDownOutlined sx={{ color: "#6e6e6e", fontSize: "2rem", placeSelf: "center" }}/>
          </ScrollDownButton>}
        </StyledScrollbar>
        <div style={{ height: messageBarHeight + underbar, width: "100%", backgroundColor: "white", marginBottom: 8 }}/>
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