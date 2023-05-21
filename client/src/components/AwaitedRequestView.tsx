import _ from "lodash";
import React, { useState, memo, useRef, useLayoutEffect, useEffect, useCallback } from "react";
import { flushSync } from "react-dom";
import { useUpdateEffect } from "usehooks-ts";
import { useInView } from "react-intersection-observer";
import styled from "@emotion/styled";
import { Theme, useMediaQuery } from "@mui/material";
import { Button, IconButton, Stack, Typography } from "@mui/joy";
import { SendRounded, ArrowBackSharp, KeyboardDoubleArrowDownOutlined } from "@mui/icons-material";
import { DayCard } from "./MessageList";
import { useSize } from "./Hooks/useSize";
import { StyledSheet, StyledScrollbar, DisableSelectTypography } from "./CommonElementStyles";
import { StyledScrollingTextarea } from "./TextareaAutosize";
import { chats } from "../prvChats";
import { AwaitedRequest, ChatRequest } from "../client";
import MessageCard from "./MessageCard";
import { DateTime } from "luxon";


type AwaitedRequestViewProps = {
  awaitedRequest: AwaitedRequest;
}

export function AwaitedRequestView({ awaitedRequest }: AwaitedRequestViewProps) {
  const { lastActive: lastActivity, chatMessage, otherUser } = awaitedRequest;
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
            {otherUser}
          </DisableSelectTypography>
        </Stack>
        <div style={{ width: "100%", display: "flex", justifyContent: "center" }}>
          <DayCard date={DateTime.fromMillis(lastActivity).toISODate()}/>
        </div>
        <DisableSelectTypography level="body2" sx={{ width: "100%", textAlign: "center", color: "lightgrey" }}>
          You sent a chat request to @{otherUser}. Wait for them to respond.
        </DisableSelectTypography>
        <MessageCard chatMessage={chatMessage}/>
      </Stack>
    </StyledSheet>);
}