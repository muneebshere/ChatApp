import React, { useState, useRef } from "react";
import { useEffectOnce } from "usehooks-ts";
import { Alert, Grid, LinearProgress, Stack, Typography } from "@mui/joy";
import { useMediaQuery, Theme } from "@mui/material";
import { ReportProblem } from "@mui/icons-material";
import { StyledSheet } from "./CommonElementStyles";
import Sidebar from "./Sidebar";
import { ChatViewMemo, ScrollState } from "./ChatView";
import { Client } from "../client";
import { chats } from "../prvChats";

const chatWithList = chats.map((c) => c.chatWith);

export default function Main({ connected, displayName, client }: { connected: boolean, displayName: string, client: Client }) {
  const [currentChatWith, setCurrentChatWith] = useState("");
  const belowXL = useMediaQuery((theme: Theme) => theme.breakpoints.down("xl"));
  const typedMessages = useRef(new Map<string, string>());
  const lastScrollPositions = useRef(new Map<string, ScrollState>());
  
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

  return (
  <Grid container direction="column" sx={{ flex: 1, flexBasis: "content", display: "flex", flexDirection: "column" }}>
    <DisconnectedAlert connected={connected}/>
    <Grid xs={12} sx={{ flex: 0, flexBasis: "content" }}>
      <StyledSheet id="titleBar">
        <Typography level="h4" sx={{ textAlign: "center" }}>
          {displayName}
        </Typography>
      </StyledSheet>
    </Grid>
    <Grid 
      container 
      xs={12} 
      sx={{ flex: 1, flexBasis: 0, minHeight: 0 }}>
      {(!belowXL || !currentChatWith) &&
      <Grid xs={12} xl={3} sx={{ minHeight: 0, maxHeight: "100%", display: "flex", flexDirection: "column" }}>
        <Sidebar currentChatWith={currentChatWith} chatsList={chatWithList} openChat={openChat} client={client} belowXL={belowXL}/>
      </Grid>}
      {(!belowXL || currentChatWith) &&
      <Grid xs={12} xl={9} sx={{ minHeight: 0, maxHeight: "100%" }}>
        <ChatViewMemo 
          key={currentChatWith ?? ""}
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
          }}/>
      </Grid>}
    </Grid>
  </Grid>)
}

function DisconnectedAlert({ connected }: { connected: boolean }) {
  return !connected
    ? (<Grid xs={12} sx={{ flex: 0, flexBasis: "content" }}>
        <StyledSheet>
          <Stack direction="column" sx={{ justifyContent: "stretch", justifySelf: "center" }}>
            <Alert 
              variant="soft" 
              size="lg"
              sx={{ justifyContent: "center", borderBottomRightRadius: 0, borderBottomLeftRadius: 0 }} 
              color="danger" 
              startDecorator={<ReportProblem/>}>
              <Typography sx={{ textAlign: "center" }}>
                Disconnected. Reconnecting...
              </Typography>
            </Alert>
            <LinearProgress variant="soft" color="danger" 
              sx={{ borderTopRightRadius: 0, borderTopLeftRadius: 0 }} />
         </Stack>
        </StyledSheet>
      </Grid>)
    : null;
}