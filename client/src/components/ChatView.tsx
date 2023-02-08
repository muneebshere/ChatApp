import React, { useState } from "react";
import { IconButton, Stack, Textarea, Typography } from "@mui/joy";
import { SendRounded } from "@mui/icons-material";
import { FocusContext, SenderContext } from "./MessageCard";
import MessageList, { ListMessage } from "./MessageList";

type ChatViewProps = {
  currentChat: { with: string, messages: ListMessage[] };
}

export default function ChatView({ currentChat }: ChatViewProps) {
  const [currentFocus, setCurrentFocus] = useState<string>(null);
  const [message, setMessage] = useState("");

  return (
    currentChat && currentChat.messages.length > 0
      ? (
        <Stack direction="column" spacing={1} sx={{ flex: 1, flexBasis: "content", display: "flex", flexDirection: "column" }}>
          <Typography sx={{ textAlign: "left", flex: 0, flexBasis: "content" }}>
            {currentChat.with}
          </Typography>
          <SenderContext.Provider value={{ sender: currentChat.with }}>
            <FocusContext.Provider value={{ currentFocus, clearFocus: () => setCurrentFocus(null) }} >
            <MessageList
            messages={currentChat.messages} 
            repliedClicked={
            (id) => {
            setCurrentFocus(id);
            }}/>
            </FocusContext.Provider>
          </SenderContext.Provider>
          <Stack direction="row" spacing={1} sx={{ flex: 0, flexBasis: "content", display: "flex", flexDirection: "row", flexWrap: "nowrap" }}>
            <Textarea 
              value={message}
              color="success"
              placeholder="Type a message"
              minRows={1} 
              maxRows={5} 
              onChange={(event) => setMessage(event.target.value)}
              sx={{ flexGrow: 1, flexBasis: "content", color: "black" }}/>
            <IconButton 
              variant="outlined"
              color="success" 
              sx={{ flexGrow: 0, flexBasis: "content", height: "fit-content", alignSelf: "center", borderRadius: 20 }}>
              <SendRounded sx={{ fontSize: "2rem"}}/>
            </IconButton>
          </Stack>
        </Stack>)
      : (<div/>)
  );
}