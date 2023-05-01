import React, { useState, useRef, useEffect, useLayoutEffect, useMemo } from "react";
import { useEffectOnce } from "usehooks-ts";
import { useInView } from "react-intersection-observer";
import { Alert, Grid, IconButton, LinearProgress, Stack } from "@mui/joy";
import { useMediaQuery, Theme, SxProps } from "@mui/material";
import { ReplayCircleFilledSharp, ReportProblem } from "@mui/icons-material";
import { DisableSelectTypography, StyledSheet } from "./CommonElementStyles";
import Sidebar from "./Sidebar";
import { ChatViewMemo, OrientationState, ScrollState } from "./ChatView";
import { ChatRequest, Client } from "../client";
import { chats } from "../prvChats";
import { ChatRequestView } from "./ChatRequestView";
import { flushSync } from "react-dom";

const minKeyboard = 300;
export const barHeight = () => document.querySelector("#viewportHeight").clientHeight - window.innerHeight;
export const keyboardHeight = () => document.querySelector("#viewportHeight").clientHeight - window.visualViewport.height;
export const isKeyboardOpen = () => keyboardHeight() > minKeyboard;
export const orientation = () => window.screen.orientation.type;

const sampleRequest = new ChatRequest({ sessionId: "xyz", addressedTo: "", timestamp: 0, initialMessage: null, myPublicDHIdentityKey: null, myPublicEphemeralKey: null, myVerifyingIdentityKey: null, yourSignedPreKeyVersion: 1, yourOneTimeKeyIdentifier: "" }, { async rejectRequest() { return false; }, async respondToRequest() { return false; }}, { firstMessage: "Hey! I'd like to chat with you.", profile: { displayName: "Someone", username: "someone", profilePicture: "" }, timestamp: Date.now() });

const chatWithList = new Map<string, "Chat" | ChatRequest>(chats.map((c) => [c.chatWith, "Chat"]));
chatWithList.set("Someone", sampleRequest);

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

function useUnderbar(lastOrientation: () => OrientationType) {
  const lastKeyboardOpenRef = useRef(false);
  const [underbar, setUnderbar] = useState(barHeight());
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

  useEffect(() => { 
    titleRef(document.querySelector("#titleBar")); 
    return () => titleRef(null);
  }, []);
  
  function onResize() {
    if (orientation() !== lastOrientation()) {
      return;
    }
    flushSync(() => {
      const lastKeyboardOpen = lastKeyboardOpenRef.current;
      const currentBar = barHeight();
      const keyboardOpen = isKeyboardOpen();
      if (keyboardOpen && !lastKeyboardOpen) {
        setUnderbar(0);
      }
      else if (!keyboardOpen && currentBar > 1e-2) {
        setUnderbar(currentBar);
      }
      else {
        setUnderbar(0);
      }
      lastKeyboardOpenRef.current = keyboardOpen;
    })
  }

  useLayoutEffect(() => {
    window.addEventListener("resize", onResize);

    return () => {
      window.removeEventListener("resize", onResize);
    }
  }, []);

  return underbar;
}

type MainProps = { 
  connected: boolean, 
  retrying: boolean, 
  displayName: string, 
  client: Client 
};

export default function Main({ connected, retrying, displayName, client }: MainProps) {
  const [currentChatWith, setCurrentChatWith] = useState("");
  const belowXL = useMediaQuery((theme: Theme) => theme.breakpoints.down("xl"));
  const typedMessages = useRef(new Map<string, string>());
  const lastScrollPositions = useRef(new Map<string, ScrollState>());
  const orientationState = useOrientationState();
  const underbar = useUnderbar(orientationState.lastOrientation);
  
  useEffectOnce(() => {
    const currentChatWith = window.history.state?.currentChatWith || "";
    window.history.replaceState({ currentChatWith }, "", `#${currentChatWith}`);
    setCurrentChatWith(currentChatWith);
    const popStateListener = (event: PopStateEvent) => setCurrentChatWith(event.state?.currentChatWith || "");
    window.addEventListener("popstate", popStateListener);
    return () => window.removeEventListener("popstate", popStateListener);
  });

  function openChat(chat: string) {
    window.history.pushState({ currentChatWith: chat }, "", `#${chat}`);
    setCurrentChatWith(chat);
  }

  function getView(currentChatWith: string) {
    const chat = chatWithList.get(currentChatWith);
    return chat === "Chat"
      ? (
        <ChatViewMemo 
          key={currentChatWith ?? ""}
          orientationState={orientationState}
          chatWith={currentChatWith ?? ""}
          message={typedMessages.current.get(currentChatWith) || ""}
          setMessage={(message: string) => {
            if (currentChatWith) {
              typedMessages.current.set(currentChatWith, message)
            }}}
          lastScrolledTo={ lastScrollPositions.current.get(currentChatWith) }
          setLastScrolledTo={(lastScrolledTo) => {
            if (currentChatWith) {
              lastScrollPositions.current.set(currentChatWith, lastScrolledTo);
            }
          }}/>)
      : chat 
        ? (<ChatRequestView chatRequest={chat}/>)
        : null;
  }

  return (
  <Grid container direction="column" sx={{ flex: 1, flexBasis: "content", display: "flex", flexDirection: "column" }}>
    <DisconnectedAlert connected={connected} retrying={retrying} client={client}/>
    <Grid xs={12} sx={{ flex: 0, flexBasis: "content" }}>
      <StyledSheet id="titleBar">
        <DisableSelectTypography level="h4" sx={{ textAlign: "center" }}>
          {displayName}
        </DisableSelectTypography>
      </StyledSheet>
    </Grid>
    <Grid 
      container 
      xs={12} 
      sx={{ flex: 1, flexBasis: 0, minHeight: 0 }}>
      {(!belowXL || !currentChatWith) &&
      <Grid xs={12} xl={3} sx={{ minHeight: 0, maxHeight: "100%", display: "flex", flexDirection: "column" }}>
        <Sidebar currentChatWith={currentChatWith} chatsList={Array.from(chatWithList.keys())} openChat={openChat} client={client} belowXL={belowXL}/>
      </Grid>}
      {(!belowXL || currentChatWith) &&
      <Grid xs={12} xl={9} sx={{ minHeight: 0, maxHeight: "100%" }}>
        {getView(currentChatWith)}
      </Grid>}
    </Grid>
    <div style={{ height: underbar, width: "100%", backgroundColor: "white", marginBottom: 8 }}/>
  </Grid>)
}

function DisconnectedAlert({ connected, retrying, client }: Pick<MainProps, "connected" | "retrying" | "client">) {
  const fuseBorder: SxProps = retrying ? { borderBottomRightRadius: 0, borderBottomLeftRadius: 0 } : {};
  return !connected
    ? (<Grid xs={12} sx={{ flex: 0, flexBasis: "content" }}>
        <StyledSheet>
          <Stack direction="column" sx={{ justifyContent: "stretch", justifySelf: "center" }}>
            <Alert 
              variant="soft" 
              size="lg"
              sx={{ justifyContent: "center", ...fuseBorder }} 
              color="danger" 
              startDecorator={<ReportProblem sx={{ fontSize: "3rem" }}/>}>
              <Stack direction="row" spacing={3}>
                <DisableSelectTypography color="danger" textAlign="center" sx={{ display: "flex", flexWrap: "wrap", alignContent: "center" }}>
                  Disconnected. {retrying ? "Reconnecting..." : ""}
                </DisableSelectTypography>
                {!retrying && 
                  <IconButton color="danger" sx={{ width: "fit-content", placeContent: "center", padding: "4px" }} onClick={ () => client.establishSession() }>
                    <Stack direction="column" spacing={0.2} sx={{ flexWrap: "wrap", alignItems: "center" }}>
                      <ReplayCircleFilledSharp sx={{ fontSize: "2rem" }}/>
                      <DisableSelectTypography textAlign="center" color="danger" level="body3" sx={{ width: "min-content" }}>
                        Retry connecting
                      </DisableSelectTypography>
                  </Stack>
                  </IconButton>}
              </Stack>
            </Alert>
            {retrying &&
              <LinearProgress variant="soft" color="danger" 
              sx={{ borderTopRightRadius: 0, borderTopLeftRadius: 0 }} />}
         </Stack>
        </StyledSheet>
      </Grid>)
    : null;
}