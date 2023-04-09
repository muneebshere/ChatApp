import _ from "lodash";
import React, { useState, useContext, memo, useRef, useMemo, useEffect, useCallback, useLayoutEffect } from "react";
import { Card, List, ListItem, ListSubheader, Stack, Typography } from "@mui/joy";
import { DateTime } from "luxon";
import { Tooltip, TooltipTrigger, TooltipContent } from "./Tooltip";
import { MessageCardMemo, ViewMessage } from "./MessageCard";
import { DisplayMessage } from "../../../shared/commonTypes";
import { useEffectOnce } from "usehooks-ts";

type MessageListProps = {
  chatWith: string;
  messages: DisplayMessage[];
  registerMessageRef: (ref: HTMLDivElement) => void;
}

function formatDate(date: string): string {
  const dt = DateTime.fromISO(date);
  const diff = -(dt.diffNow("day").as("day"));
  if (diff < 4) return dt.toRelativeCalendar();
  if (diff < 7) return dt.weekdayLong;
  return dt.toFormat("dd/LL/y");
}

function labelFirsts(chatWith: string, messages: DisplayMessage[]): Omit<ViewMessage, "highlight" | "setHighlight">[] {
  const result: Omit<ViewMessage, "highlight" | "setHighlight">[] = [];
  let lastByMe : boolean = null;
  for (const { messageId, sentByMe, ...rest } of messages) { 
    const first = lastByMe !== sentByMe;
    lastByMe = sentByMe;
    result.push({ chatWith, messageId, sentByMe, first, ...rest });
  }
  return result;
}

const MessageList = function({ chatWith, messages, registerMessageRef }: MessageListProps) {
  const [highlight, setHighlight] = useState("");

  const convertedMessages = _.chain(messages)
    .orderBy((m) => m.timestamp, "asc")
    .groupBy((m) => DateTime.fromMillis(m.timestamp).toISODate())
    .map((messages, date) => ({ date, messages: labelFirsts(chatWith, messages) }))
    .value();

  const dayCard = (date: string) => (  
    <Card 
    variant="outlined" 
    sx={{ padding: 1, backgroundColor: "rgba(235, 234, 232, 0.7)", backdropFilter: "blur(30px)", textTransform: "capitalize" }}>
    <Typography level="body3" >
      {formatDate(date)}
    </Typography>
  </Card>);

  return (
    <List>
      {convertedMessages.map(({ date, messages }) => (
        <ListItem nested key={date} sx={{ display: "grid" }}>
          <ListSubheader sticky sx={{ display: "flex", justifyContent: "center", backgroundColor: "transparent", width: "fit-content", justifySelf: "center" }}>
            { formatDate(date).search(/^\d{1,2}\/\d{1,2}\/\d{4}$/) === -1
              ?(<Tooltip placement="left" mainAxisOffset={95} crossAxisOffset={-10}>
                  <TooltipTrigger>
                    {dayCard(date)}
                  </TooltipTrigger>
                  <TooltipContent>
                    <div style={{ width: "fit-content",
                                  backgroundColor: "#f8f7f5", 
                                  borderColor: "rgba(237, 237, 237, 0.7)", 
                                  boxShadow: "0px 0.5px 4px #e4e4e4",
                                  position: "absolute",
                                  zIndex: 2 }}>
                      <Typography level="body3" noWrap>
                        {DateTime.fromISO(date).toFormat("d LLLL y")}
                      </Typography>
                    </div>
                  </TooltipContent>
                </Tooltip>)
              : dayCard(date) }
          </ListSubheader>
          <List component="ol" sx={{ "--List-gap": 5 }}>
            {messages.map((message) => (
              <ListItem key={message.timestamp} sx={{ display: "flex", flexDirection: "row" }}>
                <MessageCardMemo {...message} ref={registerMessageRef} highlight={highlight} setHighlight={setHighlight}/>
              </ListItem>
            ))}
          </List>
        </ListItem>
      ))}
    </List>
  )
}

export const MessageListMemo = memo(MessageList, 
  (prev, next) => prev.chatWith === next.chatWith &&  _.isEqual(prev.messages, next.messages));