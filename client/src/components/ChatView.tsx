import React, { useState, useCallback, memo } from "react";
import { useEffectOnce } from "usehooks-ts";
import { IconButton, Stack, Typography } from "@mui/joy";
import { SendRounded, ArrowBackSharp } from "@mui/icons-material";
import { FocusContext, ChatContext } from "./MessageCard";
import { MessageListMemo } from "./MessageList";
import { StyledJoyTextarea } from "./Common";
import styled from "@emotion/styled";
import { Theme, useMediaQuery } from "@mui/material";

type ChatViewProps = {
  chatWith: string,
  message: string,
  setMessage: (m: string) => void
}

const TextareaBorder = styled.div`
  flex: 1;
  display: flex;
  justify-content: stretch;
  align-content: center;
  padding: 7px;
  border-radius: 8px;
  outline: 1px solid #d8d8df;

  &:hover {
    outline-color: #b9b9c6;
  }

  &:focus-within {
    outline: 2px solid #096bde;
  }
`;

const ChatView = function({ chatWith, message, setMessage }: ChatViewProps) {
  const [currentFocus, setCurrentFocus] = useState<string>(null);
  const belowXL = useMediaQuery((theme: Theme) => theme.breakpoints.down("xl"));

  const repliedClicked = useCallback((id: string) => setCurrentFocus(id), [currentFocus]);

  return (
    <Stack direction="column" spacing={1} sx={{ flex: 1, flexBasis: "content", display: "flex", flexDirection: "column" }}>
      <Stack direction="row" spacing={2}>
        {belowXL && 
          <IconButton variant="outlined" color="neutral" onClick={() => { window.location.hash = "" }}>
            <ArrowBackSharp sx={{ fontSize: "2rem" }}/>
          </IconButton>}
        <Typography level="h5" sx={{ textAlign: "left", flex: 0, flexBasis: "content", display: "flex", flexWrap: "wrap", alignContent: "center" }}>
          {chatWith}
        </Typography>
      </Stack>
      <ChatContext.Provider value={{ chatWith }}>
        <FocusContext.Provider value={{ currentFocus, clearFocus: () => setCurrentFocus(null) }} >
        <MessageListMemo
          repliedClicked={repliedClicked}/>
        </FocusContext.Provider>
      </ChatContext.Provider>
      <Stack direction="row" spacing={1} sx={{ flex: 0, flexBasis: "content", display: "flex", flexDirection: "row", flexWrap: "nowrap" }}>
        <TextareaBorder>
          <StyledJoyTextarea 
            placeholder="Type a message"
            defaultValue={message}
            onChange={ (e) => setMessage(e.target.value) }
            minRows={1} 
            maxRows={5} 
            style={{ flex: 1 }}/>
        </TextareaBorder>
        <IconButton 
          variant="outlined"
          color="success" 
          sx={{ flexGrow: 0, flexBasis: "content", height: "fit-content", alignSelf: "center", borderRadius: 20 }}>
          <SendRounded sx={{ fontSize: "2rem"}}/>
        </IconButton>
      </Stack>
    </Stack>);
}

export const ChatViewMemo = memo(ChatView, ({ chatWith: prevChat, message: prevMess }, { chatWith: nextChat, message: nextMess }) => prevChat === nextChat && prevMess === nextMess);