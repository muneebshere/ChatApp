import _ from "lodash";
import isEqual from "react-fast-compare";
import React, { memo, useRef, useState, useEffect, createContext, useContext, useLayoutEffect } from "react";
import { Card, List, ListItem, ListSubheader } from "@mui/joy";
import { DateTime } from "luxon";
import { Tooltip, TooltipTrigger, TooltipContent } from "./Tooltip";
import MessageCard from "./MessageCard";
import { ElementRects } from "@floating-ui/react";
import { DisableSelectTypography } from "./CommonElementStyles";
import { ChatMessageList } from "../ChatClasses";
import { SxProps } from "@mui/material";
import { Observable } from "rxjs";

export const DayCardContext = createContext<Observable<number>>(null);

function formatDate(date: string): string {
  const dt = DateTime.fromISO(date);
  const diff = -(dt.diffNow("day").as("day"));
  if (diff < 4) return dt.toRelativeCalendar();
  if (diff < 7) return dt.weekdayLong;
  return dt.toFormat("dd/LL/y");
}

const inlineCardSx: SxProps = { 
  padding: 1,
  width: "fit-content",
  textTransform: "capitalize",
  backgroundColor: "rgba(255, 255, 255, 0)",
  boxShadow: "none"
}

const floatingCardSx: SxProps = {
  ...inlineCardSx,
  backgroundColor: "rgba(255, 255, 255, 0.7)", 
  backdropFilter: "blur(30px)",
  boxShadow: undefined
}

export function DayCard({ date }: { date: string }) {
  const observeMaxTop = useContext(DayCardContext);
  const floatingRef = useRef<HTMLDivElement>(null);
  const cardRef = useRef<HTMLDivElement>(null);
  const [inline, setInline] = useState(false);
  const offsetFunc = (rects: ElementRects) => {
    const crossAxis = (-floatingRef.current?.getBoundingClientRect()?.width || 0) - 10;
    const mainAxis = (-rects.reference.height / 2) - ((floatingRef.current?.getBoundingClientRect()?.height || 0) / 2);
    return { crossAxis, mainAxis }
  }

  useLayoutEffect(() => {
    const subscription = observeMaxTop.subscribe((maxTop) => {
      setInline((cardRef.current?.getBoundingClientRect()?.top || 0) > (maxTop + 8));
    });
    return () => subscription.unsubscribe();
  }, [observeMaxTop]);

  return (
    <Tooltip placement="bottom-start" offsetFunc={offsetFunc}>
      <TooltipTrigger>
        <Card
          ref={cardRef}
          variant={inline ? "plain" : "outlined"} 
          sx={ inline ? inlineCardSx : floatingCardSx }>
          <DisableSelectTypography level="body3">
            {formatDate(date)}
          </DisableSelectTypography>
        </Card>
      </TooltipTrigger>
      <TooltipContent>
        <div ref={floatingRef} style={{ width: "fit-content",
                      backgroundColor: "#bebdbc", 
                      borderColor: "rgba(237, 237, 237, 0.7)", 
                      boxShadow: "0px 0.5px 4px #e4e4e4",
                      position: "absolute",
                      zIndex: 2 }}>
          <DisableSelectTypography level="body3" noWrap sx={{ cursor: "default", color: "black" }}>
            {DateTime.fromISO(date).toFormat("d LLLL y")}
          </DisableSelectTypography>
        </div>
      </TooltipContent>
    </Tooltip>)
}

const MessageSubList = function({ chatMessageList }: { chatMessageList: ChatMessageList }) {
  const [chatMessages, setChatMessages] = useState(chatMessageList.messageList);
  
  useEffect(() => {
    chatMessageList.subscribe(() => {
      setChatMessages(chatMessageList.messageList);
    });
    return () => chatMessageList.unsubscribe();
  }, [])

  return (
    <ListItem nested key={chatMessageList.date} sx={{ display: "grid" }}>
      <ListSubheader sticky sx={{ display: "flex", justifyContent: "center", backgroundColor: "transparent", width: "fit-content", justifySelf: "center" }}>
        <DayCard date={chatMessageList.date}/>
      </ListSubheader>
      <List component="ol" sx={{ "--List-gap": 5 }}>
        {chatMessages.map((chatMessage) => (
          <ListItem key={chatMessage.messageId} sx={{ display: "flex", flexDirection: "row" }}>
            <MessageCard chatMessage={chatMessage}/>
          </ListItem>
        ))}
      </List>
    </ListItem>
  )
}

const MessageSubListMemo = memo(MessageSubList, 
  (prev, next) => prev.chatMessageList === next.chatMessageList);

const MessageList = function({ chatMessageLists }: { chatMessageLists: ChatMessageList[] }) {

  return (
    <List>
      {chatMessageLists.map((chatMessageList) => (
        <MessageSubListMemo key={chatMessageList.date} chatMessageList={chatMessageList}/>
      ))}
    </List>)
}

export const MessageListMemo = memo(MessageList, 
  (prev, next) => isEqual(prev.chatMessageLists, next.chatMessageLists));