import React, { useState } from "react";
import { Alert, Grid, LinearProgress, List, ListItem, ListItemButton, Stack, Theme, Typography } from "@mui/joy";
import { useMediaQuery } from "@mui/material";
import { ReportProblem } from "@mui/icons-material";
import { Item } from "./Common";
import { chats } from "./prvChats";
import ChatView from "./ChatView";

export default function Main({ connected, displayName }: { connected: boolean, displayName: string }) {
  const [currentFocus, setCurrentFocus] = useState<string>(null);
  const [currentChat, setCurrentChat] = useState<number>(null);
  const belowXL = useMediaQuery((theme: Theme) => theme.breakpoints.down("xl"));

  const disconnectedAlert = (
    connected ||
    <Grid xs={12} sx={{ justifyContent: "stretch", justifySelf: "center" }}>
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
  return (
  <Grid container direction="column" sx={{ flexGrow: 1 }}>
    <React.Fragment>
      {disconnectedAlert}
    </React.Fragment>
    <Grid xs={12} sx={{ justifyContent: "center", justifySelf: "center" }}>
      <Item>
        <Typography sx={{ textAlign: "center" }}>
          {displayName}
        </Typography>
      </Item>
    </Grid>
    <Grid 
      container 
      xs={12} 
      sx={{ justifyContent: "flex-end", alignSelf: "stretch", flexGrow: 1 }}>
      <Grid xs={12} xl={3}>
        {(!belowXL || currentChat === null) &&
        <Item>
          <List variant="plain" color="neutral">
            {chats.map((c, i) =>
              <ListItem key={i}>
                <ListItemButton 
                  onClick={() => setCurrentChat(i)} 
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
      <Grid xs={12} xl={9}>
        <Item>
          <ChatView currentChat={currentChat ? chats[currentChat] : null}/>
        </Item>
      </Grid>
    </Grid>
  </Grid>)
}