import _ from "lodash";
import React from "react";
import { Theme, useMediaQuery } from "@mui/material";
import { Button, IconButton, Stack } from "@mui/joy";
import { ArrowBackSharp } from "@mui/icons-material";
import { DayCard } from "./MessageList";
import { StyledSheet, DisableSelectTypography } from "./CommonElementStyles";
import MessageCard from "./MessageCard";
import { DateTime } from "luxon";
import { ChatRequest } from "../chatClasses";


type ChatRequestViewProps = {
  chatRequest: ChatRequest;
}

export function ChatRequestView({ chatRequest }: ChatRequestViewProps) {
  const { contactDetails: { displayName }, lastActive: lastActivity, chatMessage, otherUser } = chatRequest;
  const belowXL = useMediaQuery((theme: Theme) => theme.breakpoints.down("xl"));

  return (
    <StyledSheet sx={{ height: "100%", 
                      display: "flex", 
                      flexDirection: "column", 
                      overflow: "clip" }}>
      <Stack direction="column" spacing={2}>
        <Stack direction="row" spacing={2}>
          {belowXL && 
            <IconButton variant="outlined" color="neutral" onClick={() => { window.location.hash = "" }}>
              <ArrowBackSharp sx={{ fontSize: "2rem" }}/>
            </IconButton>}
          <DisableSelectTypography level="h5" sx={{ textAlign: "left", flex: 0, flexBasis: "content", display: "flex", flexWrap: "wrap", alignContent: "center" }}>
            {displayName}
          </DisableSelectTypography>
        </Stack>
        <div style={{ width: "100%", display: "flex", justifyContent: "center" }}>
          <DayCard date={DateTime.fromMillis(lastActivity).toISODate()}/>
        </div>
        <DisableSelectTypography level="body2" sx={{ width: "100%", textAlign: "center", color: "lightgrey" }}>
          You have received a chat request from @{otherUser}. Accept chat request to reply.
        </DisableSelectTypography>
        <MessageCard chatMessage={chatMessage}/>
      </Stack>
      <Stack direction="column" spacing={1.5} sx={{ flexGrow: 1, display: "flex", flexWrap: "wrap", justifyContent: "center", alignContent: "center" }}>
        <Stack direction="row" spacing={2}>
          <Button variant="solid" color="success" onClick={() => chatRequest.respondToRequest(Date.now())} style={{ width: "100px" }}>
            Accept
          </Button>
          <DisableSelectTypography level="body2" sx={{ width: "100%", textAlign: "start", color: "lightgrey" }} style={{ marginBlock: "auto" }}>
            Your profile details will be sent to @{otherUser}.
          </DisableSelectTypography>
        </Stack>
        <Stack direction="row" spacing={2}>
          <Button variant="solid" color="danger" onClick={() => chatRequest.rejectRequest()} style={{ width: "100px" }}>
            Reject 
          </Button>
          <DisableSelectTypography level="body2" sx={{ width: "100%", textAlign: "start", color: "lightgrey" }} style={{ marginBlock: "auto" }}>
            @{otherUser} will not be notified.
          </DisableSelectTypography>
        </Stack>
      </Stack>
    </StyledSheet>);
}