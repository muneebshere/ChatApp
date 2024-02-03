import _ from "lodash";
import React, { useLayoutEffect } from "react";
import { Theme, useMediaQuery } from "@mui/material";
import { Button, Stack } from "@mui/joy";
import { DayCard } from "./MessageList";
import { StyledSheet, DisableSelectTypography } from "./CommonElementStyles";
import MessageCard from "./MessageCard";
import { DateTime } from "luxon";
import { ReceivedChatRequest } from "../ChatClasses";
import { ChatHeaderMemo } from "./ChatHeader";


type ReceivedChatRequestViewProps = {
  receivedChatRequest: ReceivedChatRequest;
}

export function ReceivedChatRequestView({ receivedChatRequest }: ReceivedChatRequestViewProps) {
  const { details: chatDetails, chatMessage, otherUser } = receivedChatRequest;
  const { lastActivity: { timestamp: lastActive } } = chatDetails;
  const belowXL = useMediaQuery((theme: Theme) => theme.breakpoints.down("xl"));

  useLayoutEffect(() => receivedChatRequest.markVisited(), []);

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
        <DisableSelectTypography level="body-lg" sx={{ width: "100%", textAlign: "center", color: "lightgrey" }}>
          You have received a chat request from @{otherUser}. Accept chat request to reply.
        </DisableSelectTypography>
        <MessageCard chatMessage={chatMessage}/>
      </Stack>
      <Stack direction="column" spacing={1.5} sx={{ flexGrow: 1, display: "flex", flexWrap: "wrap", justifyContent: "center", alignContent: "center" }}>
        <Stack direction="row" spacing={2}>
          <Button variant="solid" color="success" onClick={() => receivedChatRequest.respondToRequest(Date.now())} style={{ width: "100px" }}>
            Accept
          </Button>
          <DisableSelectTypography level="body-md" sx={{ width: "100%", textAlign: "start", color: "lightgrey" }} style={{ marginBlock: "auto" }}>
            Your profile details will be sent to @{otherUser}.
          </DisableSelectTypography>
        </Stack>
        <Stack direction="row" spacing={2}>
          <Button variant="solid" color="danger" onClick={() => receivedChatRequest.rejectRequest()} style={{ width: "100px" }}>
            Reject 
          </Button>
          <DisableSelectTypography level="body-md" sx={{ width: "100%", textAlign: "start", color: "lightgrey" }} style={{ marginBlock: "auto" }}>
            @{otherUser} will not be notified.
          </DisableSelectTypography>
        </Stack>
      </Stack>
    </StyledSheet>);
}