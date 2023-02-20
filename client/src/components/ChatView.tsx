import React, { useState, useRef } from "react";
import { IconButton, Stack, Typography } from "@mui/joy";
import { SendRounded } from "@mui/icons-material";
import { FocusContext, ChatContext } from "./MessageCard";
import { MessageList } from "./MessageList";
import { Textarea } from "./Common";
import styled from "@emotion/styled";

type ChatViewProps = {
  chatWith: string, 
  length: number
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

export default function ChatView({ chatWith, length }: ChatViewProps) {
  const [currentFocus, setCurrentFocus] = useState<string>(null);
  const prevLines = useRef(1);
  const [rows, setRows] = useState(1);
  const [scrollOn, setScrollOn] = useState(false);
  const messageRef = useRef("");
  const canvasContext = useRef(createCanvas());
  const maxRows = 5;

  function createCanvas() {
    const canvas = document.createElement("canvas");
    const context = canvas.getContext("2d");
    context.font = `1rem "Public Sans"`;
    return context;
  }

  function calculateLines(line: string, width: number) {
    const measure = (s: string) => canvasContext.current.measureText(s).width / width;
    const totalFraction = measure(line);
    if (totalFraction < 1) return 1;
    let cursor = line.length;
    while (measure(line.slice(0, cursor)) >= 1) {
      cursor = Math.ceil(cursor / 2);
    }
    while(measure(line.slice(0, cursor)) < 1) {
      cursor++;
    }
    return calculateLines(line.slice(cursor - 1), width) + 1;
  }

  async function onTextChange(text: string, width: number) {
    messageRef.current = text;
    const lines = text.split(/\r\n|\r|\n/);
    const noOfLines = lines.map((l) => calculateLines(l, width)).reduce((p, c) => p + c);
    if (noOfLines > prevLines.current) {
      if (prevLines.current < maxRows) {
        setRows(noOfLines > maxRows ? maxRows : noOfLines);
      }
      if (noOfLines > maxRows) {
        setScrollOn(true);
      }
    }
    else if (noOfLines < prevLines.current) {
      if (noOfLines <= maxRows) {
        setScrollOn(false);
      }
      if (noOfLines < maxRows) {
        setRows(noOfLines);
      }
    }
    prevLines.current = noOfLines;
  }

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
              repliedClicked={ (id) => { setCurrentFocus(id); }}/>
            </FocusContext.Provider>
          </ChatContext.Provider>
          <Stack direction="row" spacing={1} sx={{ flex: 0, flexBasis: "content", display: "flex", flexDirection: "row", flexWrap: "nowrap" }}>
            <TextareaBorder>
              <Textarea rows={rows} scrollOn={scrollOn} onTextChange={onTextChange}/>
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