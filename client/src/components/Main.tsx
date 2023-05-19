import React, { useState, useRef, useEffect, useLayoutEffect, useMemo } from "react";
import { useEffectOnce } from "usehooks-ts";
import { useInView } from "react-intersection-observer";
import { Alert, Grid, IconButton, LinearProgress, Stack } from "@mui/joy";
import { useMediaQuery, Theme, SxProps } from "@mui/material";
import { ReplayCircleFilledSharp, ReportProblem } from "@mui/icons-material";
import { DisableSelectTypography, StyledSheet } from "./CommonElementStyles";
import Sidebar from "./Sidebar";
import { ChatViewMemo, OrientationState, ScrollState } from "./ChatView";
import { AwaitedRequest, ChatRequest, Client } from "../client";
import { chats } from "../prvChats";
import { ChatRequestView } from "./ChatRequestView";
import { flushSync } from "react-dom";
import { AwaitedRequestView } from "./AwaitedRequestView";

type MainProps = { 
  connected: boolean, 
  retrying: boolean, 
  displayName: string, 
  client: Client 
};

export default function Main({ connected, retrying, displayName, client }: MainProps) {
  const [currentChatWith, setCurrentChatWith] = useState(null);
  const belowXL = useMediaQuery((theme: Theme) => theme.breakpoints.down("xl"));
  const typedMessages = useRef(new Map<string, string>());
  const lastScrollPositions = useRef(new Map<string, ScrollState>());
  const [, triggerRerender] = useState(2);
  
  useEffect(() => {
    let currentChatWith = window.history.state?.currentChatWith || window.location.hash.slice(1);
    if (!client.chatsList.find((c) => currentChatWith === c)) {
      currentChatWith = null;
      window.location.hash = ""
    }
    window.history.replaceState({ currentChatWith }, "", currentChatWith ? `#${currentChatWith}` : "");
    setCurrentChatWith(currentChatWith);
    const popStateListener = (event: PopStateEvent) => setCurrentChatWith(event.state?.currentChatWith);
    window.addEventListener("popstate", popStateListener);
    client.subscribeChange(() => triggerRerender((rerender) => 10 / rerender));
    return () => window.removeEventListener("popstate", popStateListener);
  }, []);

  function openChat(chat: string) {
    window.history.pushState({ currentChatWith: chat }, "", `#${chat}`);
    setCurrentChatWith(chat);
  }

  function getView(currentChatWith: string) {
    const chat = client.getChatByUser(currentChatWith);
    if (chat?.type === "Chat") {
      return (<ChatViewMemo 
        key={currentChatWith ?? ""}
        chat={chat}
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
        }}/>);
    }
    else if (chat?.type === "ChatRequest") {
      return (<ChatRequestView key={currentChatWith ?? ""} chatRequest={chat}/>);
    }
    else if (chat?.type === "AwaitedRequest") {
      return (<AwaitedRequestView key={currentChatWith ?? ""} awaitedRequest={chat}/>);
    }
    return null;
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
        <Sidebar currentChatWith={currentChatWith} openChat={openChat} client={client} belowXL={belowXL}/>
      </Grid>}
      {(!belowXL || currentChatWith) &&
      <Grid xs={12} xl={9} sx={{ minHeight: 0, maxHeight: "100%" }}>
        {getView(currentChatWith)}
      </Grid>}
    </Grid>
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