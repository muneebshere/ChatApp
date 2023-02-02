import React, { useState } from "react";
import { Alert, Grid, LinearProgress, Stack, Typography } from "@mui/joy";
import { ReportProblem } from "@mui/icons-material";
import { Item } from "./Common";
import { ViewMessage, FocusContext } from "./MessageCard";
import MessageList, { ListMessage } from "./MessageList";
import { DateTime } from "luxon";
import { messages } from "./prvMessagesList";

const timestamplr = DateTime.now().minus({ days: 1}).toMillis();
const message1lr = {
  id: `${timestamplr}`,
  content: "This is the message you're replying to. It's *really* long, isn't it? Could you make it shorter? It would look better that way.",
  timestamp: timestamplr,
  status: "pending"
}
const message1l = {
  id: `${Date.now()}`,
  content: `This is a **test** *message*. ~I needed to make it longer, so typing more here~.\n\nThis is a *test* **message**.\n\nContinuing message in a new paragraph, which is supposed to be the last paragraph now.`,
  timestamp: Date.now(),
  replyingTo: { id: `${timestamplr}` },
  status: null
}

function truncateText(text: string) {
  const maxChar = 250;
  if (!text) return null;
  const lineText = text.replace(/[\s]*?[\n]+/, " ");
  if (lineText.length <= maxChar) return lineText;
  const truncate = lineText.indexOf(" ", maxChar);
  return `${ lineText.slice(0, truncate) } ...`;
}

function transformMessage(message: Omit<ListMessage, "replyingTo"> & { replyingTo: { id: string } }): ListMessage {
  const { replyingTo, ...rest } = message;
  const repliedTo = !!replyingTo ? messages.find((m) => m.id === replyingTo.id) : null;
  if (!repliedTo) return { ...rest };
  const { id } = replyingTo;
  const { status, content } = repliedTo;
  const text = truncateText(content);
  const sentByMe = status !== null;
  return { replyingTo: { id, text, sentByMe }, ...rest };
}
const message1: ViewMessage = {
  id: "",
  content: `This is a **test** *message*. ~I needed to make it longer, so typing more here~.\n\nThis is a *test* **message**.\n\nContinuing message in a new paragraph, which is supposed to be the last paragraph now.`,
  timestamp: Date.now(),
  replyingTo: { click: () => alert("Clicked Replied."), sender: null, text: "This is the message you're replying to. It's *really* long, isn't it? Could you make it shorter? It would look better that way." },
  status: "delivered",
  first: true
}

const listMessages = messages.map(transformMessage);

export default function Main({ connected, displayName }: { connected: boolean, displayName: string }) {
  const [currentFocus, setCurrentFocus] = useState<string>(null);
  const message2: ViewMessage = {
    id: "",
    content: listMessages[1].content,
    timestamp: listMessages[1].timestamp,
    replyingTo: { text: truncateText(listMessages[1].replyingTo.text), sender: "Sir Kabir", click: () => {} },
    status: "delivered",
    first: true
  }
  return (
  <Grid container direction="column" sx={{ flexGrow: 1 }}>
    <React.Fragment>
      {connected ||
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
      </Grid>}
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
      <Grid xs={10}>
        <Item>
          <FocusContext.Provider value={{ currentFocus, clearFocus: () => setCurrentFocus(null) }} >
            <MessageList 
              chatWith="Sir Kabir Rizvi WHALES"
              messages={listMessages} 
              repliedClicked={
              (id) => {
                setCurrentFocus(id);
              }}/>
          </FocusContext.Provider>
        </Item>
      </Grid>
    </Grid>
  </Grid>)
}