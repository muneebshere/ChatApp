import React, { useState, useRef, useEffect } from "react";
import { Grid } from "@mui/joy";
import { useMediaQuery, Theme } from "@mui/material";
import Sidebar from "./Sidebar";
import { ChatViewMemo, ScrollState } from "./ChatView";
import Client, { ConnectionStatus } from "../Client";
import { ReceivedChatRequestView } from "./ReceivedChatRequestView";
import { SentChatRequestView } from "./SentChatRequestView";
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
  const [profile, setProfile] = useState(client.profile);
  const allowLeaveFocus = useRef(false);
  const giveBackFocus = useRef<() => void>(null);
  
  useEffect(() => {
    const popStateListener = (event: PopStateEvent) => switchToChat(event.state?.currentChatWith);
    window.addEventListener("popstate", popStateListener);
    const currentChatUrl = [...window.location.pathname.matchAll(/^\/chat\/([a-z][a-z0-9_]{2,14})$/g)][0]?.[1] || "";
    if (switchToChat(currentChatUrl)) setState(currentChatUrl, true);
    else setState("", true);
    client.subscribeChange(() => {
      setChats(client.chatsList);
      setProfile(client.profile);
    });
    return () => window.removeEventListener("popstate", popStateListener);
  }, []);

  function switchToChat(otherUser: string) {
    const chat = client.getChatByUser(otherUser);
    if (chat) {
      setCurrentChatWith(otherUser);
      chat.activate();
    }
    else setCurrentChatWith("");
    return !!chat;
  }

  function setState(currentChatWith: string, replace = false) {
    const url = currentChatWith ? `/chat/${currentChatWith}` : "/";
    if (replace) window.history.replaceState({ currentChatWith }, "", url);
    else window.history.pushState({ currentChatWith }, "", url);
  }

  function openChat(otherUser: string) {
    if (otherUser === currentChatWith) return;
    if (switchToChat(otherUser)) setState(otherUser);
    else setState("");
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
    else if (chat?.type === "ReceivedRequest") {
      return (<ReceivedChatRequestView key={currentChatWith ?? ""} receivedChatRequest={chat}/>);
    }
    else if (chat?.type === "SentRequest") {
      return (<SentChatRequestView key={currentChatWith ?? ""} sentChatRequest={chat}/>);
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
          profile={profile}
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