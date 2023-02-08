import React, { useState, useRef } from "react";
import { Alert, Grid, LinearProgress, List, ListItem, ListItemButton, Stack, Theme, Typography } from "@mui/joy";
import { useMediaQuery } from "@mui/material";
import { ReportProblem } from "@mui/icons-material";
import { Item, StyledScrollbar } from "./Common";
import { chats } from "./prvChats";
import ChatView from "./ChatView";
import { useEffectOnce } from "usehooks-ts";

export default function Main({ connected, displayName }: { connected: boolean, displayName: string }) {
  const [currentFocus, setCurrentFocus] = useState<string>(null);
  const [currentChatIndex, setCurrentChatIndex] = useState<number>(null);
  const belowXL = useMediaQuery((theme: Theme) => theme.breakpoints.down("xl"));

  const currentChat = currentChatIndex ? chats[currentChatIndex] : null;
  
  useEffectOnce(() => {
    const currentIndex = window.history.state?.currentIndex ?? null;
    window.history.replaceState({ currentIndex }, "", "");
    setCurrentChatIndex(currentIndex);
    const popStateListener = (event: PopStateEvent) => setCurrentChatIndex(event.state?.currentIndex);
    window.addEventListener("popstate", popStateListener);
    return () => window.removeEventListener("popstate", popStateListener);
  });

  const disconnectedAlert = (
    connected ||
    <Grid xs={12} sx={{ flex: 0, flexBasis: "content" }}>
      <Item>
        <Stack direction="column" sx={{ justifyContent: "stretch", justifySelf: "center" }}>
          <Alert 
            variant="soft" 
            size="lg"
            sx={{ justifyContent: "center"}} 
            color="danger" 
            startDecorator={<ReportProblem/>}>
            <Typography sx={{ textAlign: "center" }}>
              Disconnected. Reconnecting...
            </Typography>
          </Alert>
          <LinearProgress variant="soft" color="danger"/>
        </Stack>
      </Item>
    </Grid>);

  function openChat(index: number) {
    window.history.pushState({ currentIndex: index }, "", `#${chats[index].with}`);
    setCurrentChatIndex(index);
  }

  return (
  <Grid container direction="column" sx={{ flex: 1, flexBasis: "content", display: "flex", flexDirection: "column" }}>
    <React.Fragment>
      {disconnectedAlert}
    </React.Fragment>
    <Grid xs={12} sx={{ flex: 0, flexBasis: "content" }}>
      <Item>
        <Typography sx={{ textAlign: "center" }}>
          {displayName}
        </Typography>
      </Item>
    </Grid>
    <Grid 
      container 
      xs={12} 
      sx={{ flex: 1, flexBasis: 0, minHeight: 0 }}>
      {(!belowXL || currentChatIndex === null) &&
      <Grid xs={12} xl={3} sx={{ minHeight: 0, maxHeight: "100%", display: "flex", flexDirection: "column" }}>
          <StyledScrollbar>
            <List variant="plain" color="neutral">
              {chats.map((c, i) =>
              <ListItem key={i}>
                <ListItemButton 
                  onClick={() => openChat(i)} 
                  selected={currentChatIndex === i} 
                  sx={{ borderRadius: "10px" }}
                  variant={currentChatIndex === i ? "soft" : "plain"}
                  color="neutral">
                  {c.with}
                </ListItemButton>
              </ListItem>)}
            </List>            
          </StyledScrollbar>
      </Grid>}
      <Grid xs={12} xl={9} sx={{ minHeight: 0, maxHeight: "100%" }}>
        <Item sx={{ height: "100%", display: "flex", flexDirection: "column" }}>
          <ChatView 
            currentChat={currentChat}/>
        </Item>
      </Grid>
    </Grid>
  </Grid>)
}