import _ from "lodash";
import react from "react";
import { Card, List, ListItem, ListSubheader, Sheet, Tooltip, Typography } from "@mui/joy";
import { DateTime } from "luxon";
import MessageCard, { ViewMessage } from "./MessageCard";

export type ListMessage = {
  readonly id: string;
  readonly content: string;
  readonly timestamp: number;
  readonly replyingTo?: { id: string, sentByMe: boolean, text: string };
  readonly status: "read" | "delivered" | "sent" | "pending";
}

type MessageListProps = {
  chatWith: string,
  messages: ListMessage[],
  repliedClicked: (id: string) => void
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
  return dt.toFormat("d/L/y");
}

function convertMessages(messages: ListMessage[], chatWith: string, repliedClicked: (id: string) => void): ViewMessage[] {
  const result: ViewMessage[] = [];
  let lastByMe : boolean = null;
  for (const { id, status, replyingTo: replying, ...rest } of messages) { 
    const byMe = status !== null;
    const first = lastByMe !== byMe;
    lastByMe = byMe;
    const replyingTo = !replying
      ? null
      : (() => {
      let { id, sentByMe, text } = replying;
      const click = () => repliedClicked(id);
      const sender = sentByMe ? null : chatWith;
      text = truncateText(text);
      return { text, sender, click }; })();
    result.push({ id, status, replyingTo, first, ...rest });
  }
  return result;
}

export default function MessageList({ chatWith, messages, repliedClicked } : MessageListProps) {
  const convertedMessages = _.chain(messages)
    .orderBy((m) => m.timestamp, "asc")
    .groupBy((m) => DateTime.fromMillis(m.timestamp).toISODate())
    .map((messages, date) => ({ date, messages: convertMessages(messages, chatWith, repliedClicked) }))
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
    <Sheet variant="plain" sx={{ maxHeight: "90vh", overflowX: "clip", overflowY: "auto" }}>
      <List>
        {convertedMessages.map(({ date, messages }) => (
          <ListItem nested key={date}>
            <ListSubheader sticky sx={{ display: "flex", justifyContent: "center", backgroundColor: "transparent" }}>
              { formatDate(date).search(/^\d{1,2}\/\d{1,2}\/\d{4}$/) === -1
                ? 
                <Tooltip 
                  title={DateTime.fromISO(date).toFormat("d LLLL y")} 
                  placement="right" 
                  variant="outlined"
                  size="sm"
                  sx={{ backgroundColor: "#f8f7f5", borderColor: "rgba(237, 237, 237, 0.7)", boxShadow: "0px 0.5px 2px #e4e4e4" }}>
                    { dayCard(date) }
                </Tooltip>
                : dayCard(date) }
            </ListSubheader>
            <List component="ol" sx={{ "--List-gap": 5 }}>
              {messages.map((m) => (
                <ListItem key={m.timestamp} sx={{ display: "flex", flexDirection: "row" }}>
                  <MessageCard message={m}/>
                </ListItem>
              ))}
            </List>
          </ListItem>
        ))}
      </List>
    </Sheet>
  )
}