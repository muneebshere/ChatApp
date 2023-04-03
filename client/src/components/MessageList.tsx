import _ from "lodash";
import React, { useState, useLayoutEffect, useRef, useContext, memo } from "react";
import { Card, CircularProgress, List, ListItem, ListSubheader, Typography } from "@mui/joy";
import { DateTime } from "luxon";
import { Tooltip, TooltipTrigger, TooltipContent } from "./Tooltip";
import { MessageCardMemo, ViewMessage, FocusContext, ChatContext } from "./MessageCard";
import styled from "@emotion/styled";
import { KeyboardDoubleArrowDownOutlined } from "@mui/icons-material";
import { StyledScrollbar } from "./Common";
import { chats } from "./prvChats";
import { DisplayMessage, PlainMessage } from "../../../shared/commonTypes";

const chatMap = new Map(chats.map(({chatWith, messages}) => ([chatWith, messages])));

const ScrollDownButton = styled.div`
  display: grid;
  position: fixed;
  bottom: 150px;
  right: 35px;
  height: 45px;
  width: 45px;
  z-index: 10;
  background-color: rgba(244, 244, 244, 0.8);
  border: 1px solid #d2d2d2;
  border-radius: 10px;
  box-shadow: 0px 0px 4px #dadada;

  :hover {
    filter: brightness(0.9);
  }`;

type MessageListProps = {
  lastScroll: number,
  setLastScroll: (scroll: number) => void
}

function truncateText(text: string) {
  const maxChar = 200;
  if (!text) return null;
  if (text.length <= maxChar) return text;
  const truncate = text.indexOf(" ", maxChar);
  return `${ text.slice(0, truncate) } ...`;
}

function formatDate(date: string): string {
  const dt = DateTime.fromISO(date);
  const diff = -(dt.diffNow("day").as("day"));
  if (diff < 4) return dt.toRelativeCalendar();
  if (diff < 7) return dt.weekdayLong;
  return dt.toFormat("dd/LL/y");
}

function labelFirsts(messages: DisplayMessage[]): ViewMessage[] {
  const result: ViewMessage[] = [];
  let lastByMe : boolean = null;
  for (const { messageId, sentByMe, ...rest } of messages) { 
    const first = lastByMe !== sentByMe;
    lastByMe = sentByMe;
    result.push({ messageId, sentByMe, first, ...rest });
  }
  return result;
}

const MessageList = function({ lastScroll, setLastScroll }: MessageListProps) {
  const { chatWith } = useContext(ChatContext);
  const scrollRef = useRef<HTMLDivElement>(null);
  const [currentFocus, setCurrentFocus] = useState<string>(null);
  const [showScrollDown, setShowScrollDown] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const scrollHandler = (event: Event) => {
    const scrollbar = event.target as HTMLDivElement;
    const scrollFinished = scrollbar.scrollTop >= scrollbar.scrollHeight - scrollbar.clientHeight - 1;
    setShowScrollDown(!scrollFinished);
    if (scrollFinished && !scrolled) {
      setScrolled(true);
    }
  }
  const debouncedScrollHandler = _.debounce(scrollHandler, 50, { trailing: true, maxWait: 50 });

  useLayoutEffect(() => {
    const scroller = scrollRef.current;
    scroller.scrollTop = scroller.scrollHeight - (lastScroll || 0);
    scroller.addEventListener("scroll", debouncedScrollHandler);
    return () => {
      const scroller = scrollRef.current;
      setLastScroll(scroller.scrollHeight - scroller.scrollTop);
      debouncedScrollHandler.cancel();
      scroller.removeEventListener("scroll", debouncedScrollHandler);
    }
  }, []);

  const convertedMessages = _.chain(chatMap.get(chatWith))
    .orderBy((m) => m.timestamp, "asc")
    .groupBy((m) => DateTime.fromMillis(m.timestamp).toISODate())
    .map((messages, date) => ({ date, messages: labelFirsts(messages) }))
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
    <StyledScrollbar ref={scrollRef}>
      <div 
        style={{ display: "flex", 
                justifyContent: "center",
                zIndex: 10, 
                position: "absolute", 
                top: "20px",
                left: "50%",
                visibility: "collapse" }}>
        <CircularProgress size="md" variant="soft" color="success"/>
      </div>
      <FocusContext.Provider value={{ currentFocus, setCurrentFocus }} >
        <List>
          {convertedMessages.map(({ date, messages }) => (
            <ListItem nested key={date} sx={{ display: "grid" }}>
              <ListSubheader sticky sx={{ display: "flex", justifyContent: "center", backgroundColor: "transparent", width: "fit-content", justifySelf: "center" }}>
                { formatDate(date).search(/^\d{1,2}\/\d{1,2}\/\d{4}$/) === -1
                  ?(<Tooltip placement="left" mainAxisOffset={120} crossAxisOffset={-10}>
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
                {messages.map((m) => (
                  <ListItem key={m.timestamp} sx={{ display: "flex", flexDirection: "row" }}>
                    <MessageCardMemo message={m}/>
                  </ListItem>
                ))}
              </List>
            </ListItem>
          ))}
        </List>
      </FocusContext.Provider>
      {showScrollDown &&
        <ScrollDownButton onClick={ () => scrollRef.current.scrollTop = scrollRef.current.scrollHeight }>
          <KeyboardDoubleArrowDownOutlined sx={{ color: "#6e6e6e", fontSize: "2rem", placeSelf: "center" }}/>
        </ScrollDownButton>}
    </StyledScrollbar>
  )
}

export const MessageListMemo = memo(MessageList);