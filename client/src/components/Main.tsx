import React, { useState } from "react";
import { Alert, Grid, LinearProgress, List, ListItem, ListItemButton, Stack, Theme, Typography } from "@mui/joy";
import { useMediaQuery } from "@mui/material";
import { ReportProblem } from "@mui/icons-material";
import { Item } from "./Common";
import { chats } from "./prvChats";
import ChatView from "./ChatView";
import { useEffectOnce } from "usehooks-ts";
import { SxProps } from "@mui/joy/styles/types";

export default function Main({ connected, displayName }: { connected: boolean, displayName: string }) {
  const [currentFocus, setCurrentFocus] = useState<string>(null);
  const [currentChat, setCurrentChat] = useState<number>(null);
  const belowXL = useMediaQuery((theme: Theme) => theme.breakpoints.down("xl"));
  
  useEffectOnce(() => {
    const currentIndex = window.history.state?.currentIndex ?? null;
    window.history.replaceState({ currentIndex }, "", "");
    setCurrentChat(currentIndex);
    const popStateListener = (event: PopStateEvent) => setCurrentChat(event.state.currentIndex);
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
    setCurrentChat(index);
  }

  const fitOverflow: SxProps = { minHeight: 0, maxHeight: "100%", overflowX: "clip", overflowY: "auto" };

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
      <Grid xs={12} xl={3} sx={{ minHeight: 0, maxHeight: "100%" }}>
        {(!belowXL || currentChat === null) &&
        <Item sx={fitOverflow}>
          <List variant="plain" color="neutral">
            {chats.map((c, i) =>
              <ListItem key={i}>
                <ListItemButton 
                  onClick={() => openChat(i)} 
                  selected={currentChat === i} 
                  sx={{ borderRadius: "10px" }}
                  variant={currentChat === i ? "soft" : "plain"}
                  color="neutral">
                  {c.with}
                </ListItemButton>
              </ListItem>
            )}
          </List>
        </Item>}
      </Grid>
      <Grid xs={12} xl={9} sx={{ minHeight: 0, maxHeight: "100%" }}>
        <Item sx={fitOverflow}>
          <ChatView currentChat={currentChat ? chats[currentChat] : null}/>
        </Item>
      </Grid>
    </Grid>
  </Grid>)
}