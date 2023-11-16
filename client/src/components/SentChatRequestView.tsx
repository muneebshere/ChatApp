import _ from "lodash";
import React from "react";
import { Theme, useMediaQuery } from "@mui/material";
import { Stack } from "@mui/joy";
import { DayCard } from "./MessageList";
import { StyledSheet, DisableSelectTypography } from "./CommonElementStyles";
import MessageCard from "./MessageCard";
import { DateTime } from "luxon";
import { SentChatRequest } from "../ChatClasses";
import { ChatHeaderMemo } from "./ChatHeader";


type SentChatRequestViewProps = {
  sentChatRequest: SentChatRequest;
}

export function SentChatRequestView({ sentChatRequest }: SentChatRequestViewProps) {
  const { details: chatDetails, chatMessage, otherUser } = sentChatRequest;
  const { lastActivity: { timestamp: lastActive } } = chatDetails;
  const belowXL = useMediaQuery((theme: Theme) => theme.breakpoints.down("xl"));

  return (
    <StyledSheet sx={{ height: "100%", 
                      display: "flex", 
                      flexDirection: "column", 
                      overflow: "clip" }}>
      <Stack direction="column" spacing={2}>
        <ChatHeaderMemo {...{ belowXL, chatDetails }}/>
        <div style={{ width: "100%", display: "flex", justifyContent: "center" }}>
          <DayCard date={DateTime.fromMillis(lastActive).toISODate()} forceInline={true}/>
        </div>
        <DisableSelectTypography level="body2" sx={{ width: "100%", textAlign: "center", color: "lightgrey" }}>
          You sent a chat request to @{otherUser}. Wait for them to respond.
        </DisableSelectTypography>
        <MessageCard chatMessage={chatMessage}/>
      </Stack>
    </StyledSheet>);
}