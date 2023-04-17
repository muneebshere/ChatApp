import _ from "lodash";
import isEqual from "react-fast-compare";
import React, { memo, useRef } from "react";
import { Card, List, ListItem, ListSubheader, Typography } from "@mui/joy";
import { DateTime } from "luxon";
import { Tooltip, TooltipTrigger, TooltipContent } from "./Tooltip";
import MessageCard, { ViewMessage } from "./MessageCard";
import { DisplayMessage } from "../../../shared/commonTypes";
import { ElementRects } from "@floating-ui/react";

type MessageListProps = {
  messages: DisplayMessage[];
}

function formatDate(date: string): string {
  const dt = DateTime.fromISO(date);
  const diff = -(dt.diffNow("day").as("day"));
  if (diff < 4) return dt.toRelativeCalendar();
  if (diff < 7) return dt.weekdayLong;
  return dt.toFormat("dd/LL/y");
}

function labelFirsts(messages: DisplayMessage[]): Omit<ViewMessage, "highlight" | "setHighlight">[] {
  const result: Omit<ViewMessage, "highlight" | "setHighlight">[] = [];
  let lastByMe : boolean = null;
  for (const { messageId, sentByMe, ...rest } of messages) { 
    const first = lastByMe !== sentByMe;
    lastByMe = sentByMe;
    result.push({ messageId, sentByMe, first, ...rest });
  }
  return result;
}

export function DayCard({ date }: { date: string }) {
  const floatingRef = useRef<HTMLDivElement>(null);
  const offsetFunc = (rects: ElementRects) => {
    const crossAxis = (-floatingRef.current?.getBoundingClientRect()?.width || 0) - 10;
    const mainAxis = (-rects.reference.height / 2) - ((floatingRef.current?.getBoundingClientRect()?.height || 0) / 2);
    return { crossAxis, mainAxis }
  }

  return (
    <Tooltip placement="bottom-start" offsetFunc={offsetFunc}>
      <TooltipTrigger>
        <Card
          variant="outlined" 
          sx={{ padding: 1, backgroundColor: "rgba(235, 234, 232, 0.7)", backdropFilter: "blur(30px)", textTransform: "capitalize" }}>
          <Typography level="body3" >
            {formatDate(date)}
          </Typography>
        </Card>
      </TooltipTrigger>
      <TooltipContent>
        <div ref={floatingRef} style={{ width: "fit-content",
                      backgroundColor: "#bebdbc", 
                      borderColor: "rgba(237, 237, 237, 0.7)", 
                      boxShadow: "0px 0.5px 4px #e4e4e4",
                      position: "absolute",
                      zIndex: 2 }}>
          <Typography level="body3" noWrap sx={{ cursor: "default", color: "black" }}>
            {DateTime.fromISO(date).toFormat("d LLLL y")}
          </Typography>
        </div>
      </TooltipContent>
    </Tooltip>)
}

const MessageSubList = function({ date, messages }: { date: string, messages: DisplayMessage[] }) {

  const convertedMessages = labelFirsts(messages);

  return (
    <ListItem nested key={date} sx={{ display: "grid" }}>
      <ListSubheader sticky sx={{ display: "flex", justifyContent: "center", backgroundColor: "transparent", width: "fit-content", justifySelf: "center" }}>
        <DayCard date={date}/>
      </ListSubheader>
      <List component="ol" sx={{ "--List-gap": 5 }}>
        {convertedMessages.map((message) => (
          <ListItem key={message.timestamp} sx={{ display: "flex", flexDirection: "row" }}>
            <MessageCard {...message}/>
          </ListItem>
        ))}
      </List>
    </ListItem>
  )
}

const MessageSubListMemo = memo(MessageSubList, 
  (prev, next) => prev.date === next.date && isEqual(prev.messages, next.messages));

const MessageList = function({ messages }: MessageListProps) {

  const groupedMessages = _.chain(messages)
    .orderBy((m) => m.timestamp, "asc")
    .groupBy((m) => DateTime.fromMillis(m.timestamp).toISODate())
    .map((messages, date) => ({ date, messages }))
    .value();

  return (
    <List>
      {groupedMessages.map(({ date, messages }) => (
        <MessageSubListMemo key={date} date={date} messages={messages}/>
      ))}
    </List>)
}

export const MessageListMemo = memo(MessageList, 
  (prev, next) => isEqual(prev.messages, next.messages));