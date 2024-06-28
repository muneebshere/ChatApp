import _ from "lodash";
import React, { memo } from "react";
import { Avatar, IconButton, Stack } from "@mui/joy";
import { ArrowBackSharp, CachedSharp } from "@mui/icons-material";
import { DisableSelectTypography } from "./CommonElementStyles";
import { ChatDetails } from "../ChatClasses";

type ChatHeaderProps = Readonly<{
  chatDetails: ChatDetails;
  closeChat: () => void;
  belowXL: boolean;
}>;

const ChatHeader = function({ chatDetails, belowXL, closeChat }: ChatHeaderProps) {
  const { displayName, contactName, profilePicture, isOnline, isOtherTyping } = chatDetails;

  return (
    <div style={{ width: "100%", display: "flex", flexDirection: "row", borderBottom: "1px solid #d1d1d1", paddingBottom: "8px" }}>
      <Stack direction="row" spacing={2} sx={{ flex: 1, justifyContent: "left" }}>
        {belowXL && 
          <IconButton variant="outlined" color="neutral" onClick={closeChat}>
            <ArrowBackSharp sx={{ fontSize: "2rem" }}/>
          </IconButton>}
        <Stack direction="row" spacing={2} sx={{ flexGrow: 1, flexWrap: "wrap", alignContent: "center" }}>
          <Avatar src={profilePicture} size="lg"/>
          <Stack direction="column" sx={{ justifyContent: "center" }}>
            <DisableSelectTypography level="h4" fontWeight="lg" sx={{ width: "fit-content" }}>
              {contactName || displayName}
            </DisableSelectTypography>
            {isOnline &&
              <DisableSelectTypography sx={{ fontSize: "14px", color: "#656565", display: "flex", justifyContent: "left" }}>
                {isOtherTyping ? "typing..." : "online"}
              </DisableSelectTypography>}
          </Stack>
        </Stack>
      </Stack>
        {belowXL && 
          <IconButton variant="outlined" color="neutral" onClick={() => window.location.reload() }>
            <CachedSharp sx={{ fontSize: "2rem" }}/>
          </IconButton>}
    </div>);
}

export const ChatHeaderMemo = memo(ChatHeader, (prev, next) => _.isEqual(prev, next));