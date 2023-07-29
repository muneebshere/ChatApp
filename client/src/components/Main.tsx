import React, { useState, useRef, useEffect } from "react";
import { Grid } from "@mui/joy";
import { useMediaQuery, Theme } from "@mui/material";
import Sidebar from "./Sidebar";
import { ChatViewMemo, ScrollState } from "./ChatView";
import Client, { ConnectionStatus } from "../Client";
import { ChatRequestView } from "./ChatRequestView";
import { AwaitedRequestView } from "./AwaitedRequestView";
import DisconnectedAlert, { DisconnectedStatus } from "./DisconnectedAlert";

export type ClientConnectionStatus = Exclude<ConnectionStatus, "NotLoaded" | "NotLoggedIn" | "LoggingOut">;

export type MainProps = Readonly<{
  client: Client;
  status: ClientConnectionStatus;
  currentChatWith: string;
  setCurrentChatWith: (chatWith: string) => void;
}>;

function disconnected(status: ClientConnectionStatus): status is DisconnectedStatus {
  return status !== "Online";
}

export default function Main({ client, status, currentChatWith, setCurrentChatWith }: MainProps) {
  const belowXL = useMediaQuery((theme: Theme) => theme.breakpoints.down("xl"));
  const typedMessages = useRef(new Map<string, string>());
  const lastScrollPositions = useRef(new Map<string, ScrollState>());
  const [chats, setChats] = useState(client.chatsList);
  const allowLeaveFocus = useRef(false);
  const giveBackFocus = useRef<() => void>(null);
  
  useEffect(() => {
    const popStateListener = (event: PopStateEvent) => setCurrentChatWith(event.state?.currentChatWith);
    window.addEventListener("popstate", popStateListener);
    client.subscribeChange(() => setChats(Array.from(client.chatsList)));
    return () => window.removeEventListener("popstate", popStateListener);
  }, []);

  function openChat(chat: string) {
    window.history.pushState({ currentChatWith: chat }, "", chat ? `#${chat}`: "");
    setCurrentChatWith(chat);
  }

  function getView() {
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
        }}
        allowLeaveFocus={allowLeaveFocus}
        giveBackFocus={giveBackFocus}/>);
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
  <Grid container direction="column" sx={{ flex: 1, flexBasis: "content", display: "flex", flexDirection: "column", paddingTop: "12px" }}>
    {disconnected(status) && 
      <Grid xs={12} sx={{ flex: 0, flexBasis: "content" }}>
        <DisconnectedAlert 
          status={status}
          countdownTick={{
            subscribe: (ticker) => client.subscribeCountdownTick(ticker),
            pause: () => client.pauseCountdownTick(),
            resume: () => client.resumeCountdownTick()
          }}
          forceReconnect={ () => client.forceReconnect() }/>
      </Grid>}
    <Grid 
      container 
      xs={12} 
      sx={{ flex: 1, flexBasis: 0, minHeight: 0 }}>
      {(!belowXL || !currentChatWith) &&
      <Grid xs={12} xl={3} sx={{ minHeight: 0, maxHeight: "100%", display: "flex", flexDirection: "column" }}>
        <Sidebar 
          currentChatWith={currentChatWith} 
          chats={chats} 
          openChat={openChat} 
          client={client} 
          belowXL={belowXL}
          allowLeaveFocus={allowLeaveFocus}
          giveBackFocus={giveBackFocus}/>
      </Grid>}
      {(!belowXL || currentChatWith) &&
      <Grid xs={12} xl={9} sx={{ minHeight: 0, maxHeight: "100%" }}>
        {getView()}
      </Grid>}
    </Grid>
  </Grid>)
}