import React, { useState } from "react";
import { Alert, Grid, LinearProgress, List, ListItem, ListItemButton, Stack, Theme, Typography } from "@mui/joy";
import { useMediaQuery } from "@mui/material";
import { ReportProblem } from "@mui/icons-material";
import { Item } from "./Common";
import { FocusContext, SenderContext } from "./MessageCard";
import MessageList, { ListMessage } from "./MessageList";
import { DateTime } from "luxon";
import { chats } from "./prvChats";

type ChatViewProps = {
  currentChat: { with: string, messages: ListMessage[] };
}

export default function ChatView({ currentChat }: ChatViewProps) {
  const [currentFocus, setCurrentFocus] = useState<string>(null);

  return (
    currentChat
      ? (
        <SenderContext.Provider value={{ sender: currentChat.with }}>
          <FocusContext.Provider value={{ currentFocus, clearFocus: () => setCurrentFocus(null) }} >
            <MessageList
              messages={currentChat.messages} 
              repliedClicked={
              (id) => {
                setCurrentFocus(id);
              }}/>
          </FocusContext.Provider>
        </SenderContext.Provider>)
      : (<div/>)
  );
}