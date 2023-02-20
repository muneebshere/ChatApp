import React, { useState, useRef, useCallback } from "react";
import { useEffectOnce } from "usehooks-ts";
import { IconButton, Stack, Typography } from "@mui/joy";
import { SendRounded } from "@mui/icons-material";
import { FocusContext, ChatContext } from "./MessageCard";
import { MessageList } from "./MessageList";
import { StyledJoyTextarea } from "./Common";
import styled from "@emotion/styled";

type ChatViewProps = {
  chatWith: string, 
  length: number,
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
  border: 1px solid grey;

  &:focus-within {
    border: 2px solid black;
  }
`;

export default function ChatView({ chatWith, length, message, setMessage }: ChatViewProps) {
  const [currentFocus, setCurrentFocus] = useState<string>(null);

  const repliedClicked = useCallback((id: string) => setCurrentFocus(id), [currentFocus]);

  return (
    length > 0
      ? (
        <Stack direction="column" spacing={1} sx={{ flex: 1, flexBasis: "content", display: "flex", flexDirection: "column" }}>
          <Typography sx={{ textAlign: "left", flex: 0, flexBasis: "content" }}>
            {chatWith}
          </Typography>
          <ChatContext.Provider value={{ chatWith }}>
            <FocusContext.Provider value={{ currentFocus, clearFocus: () => setCurrentFocus(null) }} >
            <MessageList
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
        </Stack>)
      : (<div/>)
  );
}