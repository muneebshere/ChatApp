import React, { useState, useRef, memo, useCallback } from "react";
import { Alert, Grid, IconButton, Input, LinearProgress, List, ListItem, ListItemButton, Stack, Typography } from "@mui/joy";
import { useMediaQuery, Theme } from "@mui/material";
import { ReportProblem, PersonAddAltOutlined, Search, ClearSharp } from "@mui/icons-material";
import { Item, StyledScrollbar } from "./Common";
import { ChatView } from "./ChatView";
import { useEffectOnce } from "usehooks-ts";
import { Client } from "../client";
import { chats } from "./prvChats";

const chatMap = chats.map((c) => c.chatWith);

export default function Main({ connected, displayName, client }: { connected: boolean, displayName: string, client: Client }) {
  const [currentChatWith, setCurrentChatWith] = useState("");
  const [search, setSearch] = useState("");
  const belowXL = useMediaQuery((theme: Theme) => theme.breakpoints.down("xl"));
  const typedMessages = useRef(new Map<string, string>());
  const onSearchChange = (e: any) => setSearch(e.target.value);
  
  useEffectOnce(() => {
    const currentChatWith = window.history.state?.currentChatWith || "";
    window.history.replaceState({ currentChatWith }, "", currentChatWith || `#${currentChatWith}`);
    setCurrentChatWith(currentChatWith);
    const popStateListener = (event: PopStateEvent) => setCurrentChatWith(event.state?.currentChatWith || "");
    window.addEventListener("popstate", popStateListener);
    return () => window.removeEventListener("popstate", popStateListener);
  });

  function openChat(chat: string) {
    window.history.pushState({ currentChatWith: chat }, "", `#${chat}`);
    setCurrentChatWith(chat);
  }

  const disconnectedAlert = (
    connected ||
    <Grid xs={12} sx={{ flex: 0, flexBasis: "content" }}>
      <Item>
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
      </Item>
    </Grid>);

  return (
  <Grid container direction="column" sx={{ flex: 1, flexBasis: "content", display: "flex", flexDirection: "column" }}>
    <React.Fragment>
      {disconnectedAlert}
    </React.Fragment>
    <Grid xs={12} sx={{ flex: 0, flexBasis: "content" }}>
      <Item>
        <Typography level="h4" sx={{ textAlign: "center" }}>
          {displayName}
        </Typography>
      </Item>
    </Grid>
    <Grid 
      container 
      xs={12} 
      sx={{ flex: 1, flexBasis: 0, minHeight: 0 }}>
      {(!belowXL || !currentChatWith) &&
      <Grid xs={12} xl={3} sx={{ minHeight: 0, maxHeight: "100%", display: "flex", flexDirection: "column" }}>
        <Stack direction="column" style={{ height: "100%" }}>
          <div style={{ display: "flex" }}>
            <div style={{ display: "flex", flex: 1, flexWrap: "wrap", justifyContent: "flex-start", alignContent: "center", paddingLeft: 20 }}>
              <Typography level="h4" fontWeight="md">
                Chats
              </Typography>
            </div>
            <div style={{ display: "flex", flex: 1, flexWrap: "wrap", justifyContent: "flex-end", alignContent: "center", paddingRight: 40 }}>
              <PersonAddAltOutlined color="success" sx={{ fontSize: "1.5rem" }}/>
            </div>
          </div>
          <div style={{ display: "flex", alignContent: "center", justifyContent: "stretch", paddingBlock: 10, paddingInline: 15 }}>
            <Input 
              placeholder="Search for chat"
              value={search}
              style={{ width: "100%" }}
              onChange={onSearchChange}
              endDecorator={
                search 
                  ? (<IconButton variant="soft" color="neutral" onClick={() => setSearch("")}><ClearSharp sx={{ fontSize: "1.2rem" }}/></IconButton>)
                  : (<Search sx={{ fontSize: "1.2rem" }}/>) 
              }/>
          </div>
          <StyledScrollbar>
            <List variant="plain" color="neutral">
              {chatMap.filter((chatWith) => !search || chatWith.toLowerCase().includes(search.toLowerCase())).map((chatWith) =>
              <ListItem key={chatWith}>
                <ListItemButton 
                  onClick={() => openChat(chatWith)} 
                  selected={currentChatWith === chatWith} 
                  sx={{ borderRadius: "10px" }}
                  variant={currentChatWith === chatWith ? "soft" : "plain"}
                  color="success">
                  {chatWith}
                </ListItemButton>
              </ListItem>)}
            </List>            
          </StyledScrollbar>
        </Stack>
      </Grid>}
      {(!belowXL || currentChatWith) &&
      <Grid xs={12} xl={9} sx={{ minHeight: 0, maxHeight: "100%" }}>
        <Item sx={{ height: "100%", display: "flex", flexDirection: "column" }}>
          <ChatView 
            key={currentChatWith ?? ""}
            chatWith={currentChatWith ?? ""}
            message={typedMessages.current.get(currentChatWith) ?? ""}
            setMessage={(message: string) => {
              if (currentChatWith) {
                typedMessages.current.set(currentChatWith, message)
              }
            }}/>
        </Item>
      </Grid>}
    </Grid>
  </Grid>)
}