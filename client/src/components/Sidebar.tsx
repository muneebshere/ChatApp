import _ from "lodash";
import React, { useState, useRef, useMemo, useEffect } from "react";
import { Avatar, Badge, Card, IconButton, Input, List, ListItem, ListItemButton, Stack } from "@mui/joy";
import { PersonAddAltOutlined, Search, ClearSharp, HourglassTop, DoneAllSharp, DoneSharp } from "@mui/icons-material";
import { NewChatPopup, NewMessageDialog } from "./NewChat";
import { DisableSelectTypography, StyledScrollbar } from "./CommonElementStyles";
import { AwaitedRequest, Chat, ChatDetails, ChatRequest, Client, truncateText } from "../client";
import { DisplayMessage } from "../../../shared/commonTypes";
import { DateTime } from "luxon";

type SidebarProps = {
  currentChatWith: string,
  openChat: (chatWith: string) => void,
  client: Client,
  chats: string[],
  belowXL: boolean
}

export default function Sidebar({ currentChatWith, openChat, chats, client, belowXL }: SidebarProps) {
  const [search, setSearch] = useState("");
  const [newChatWith, setNewChatWith] = useState("");
  const [isPopupOpen, setIsPopupOpen] = useState(false);
  const [warn, setWarn] = useState(false);
  const newMessageRef = useRef("");
  
  async function validateNewChat(username: string) {
    if (!username) return "";
    if (client.chatsList.some((chatWith) => chatWith.toLowerCase() === username.toLowerCase())) return "There is already an existing chat with this user.";
    return (await client.checkUsernameExists(username)) ? (username !== client.username ? "" : "Cannot chat with yourself.") : "No such user.";
  }

  function matchesSearch(otherUser: string) {
    const searchLowerCase = search.toLowerCase();
    const { displayName, contactName } = client.getChatDetailsByUser(otherUser);
    return displayName.toLowerCase().includes(searchLowerCase) || (contactName && contactName.toLowerCase().includes(searchLowerCase));
  }

  return (
    <Stack direction="column" style={{ height: "100%" }}>
      <NewMessageDialog
        newChatWith={newChatWith} 
        warn={warn} 
        setWarn={setWarn} 
        belowXL={belowXL} 
        setNewChatWith={(newChatWith) => setNewChatWith(newChatWith)}
        setNewMessage={(message) => { newMessageRef.current = message; }}
        validate={validateNewChat}
        sendRequest={() => {
          client.sendChatRequest(newChatWith, newMessageRef.current, Date.now()).then(({ reason }) => {
            if (!reason) {
              setNewChatWith("");
            }
          });
        }}
        />
      <div style={{ display: "flex" }}>
        <div style={{ display: "flex", flex: 1, flexWrap: "wrap", justifyContent: "flex-start", alignContent: "center", paddingLeft: 20 }}>
          <DisableSelectTypography level="h4" fontWeight="md">
            Chats
          </DisableSelectTypography>
        </div>
        <div style={{ display: "flex", flex: 1, flexWrap: "wrap", justifyContent: "flex-end", alignContent: "center", paddingRight: 40 }}>
        <NewChatPopup
          isPopupOpen={isPopupOpen}
          setIsPopupOpen={setIsPopupOpen}
          belowXL={belowXL} 
          placement={ belowXL ? "bottom-end" : "bottom-start" }
          validate={validateNewChat} 
          returnUser={(chatWith) => {
              setIsPopupOpen(false);
              setNewChatWith(chatWith);
            }}>
            <IconButton variant="plain" color="success" sx={ isPopupOpen ? { backgroundColor: "var(--joy-palette-success-plainHoverBg)" } : {} }>
              <PersonAddAltOutlined color="success" sx={{ fontSize: "1.5rem" }}/>
            </IconButton>
        </NewChatPopup>
        </div>
      </div>
      <div style={{ display: "flex", alignContent: "center", justifyContent: "stretch", paddingBlock: 10, paddingInline: 15 }}>
        <Input 
          placeholder="Search for chat"
          value={search}
          style={{ width: "100%" }}
          onChange={(e: any) => setSearch(e.target.value)}
          endDecorator={
            search 
              ? (<IconButton variant="soft" color="neutral" onClick={() => setSearch("")}>
                  <ClearSharp sx={{ fontSize: "1.2rem" }}/>
                </IconButton>)
              : (<Search sx={{ fontSize: "1.2rem" }}/>) 
          }/>
      </div>
      <StyledScrollbar>
        <List variant="plain" color="neutral">
          {chats
            .filter((otherUser) => !search || matchesSearch(otherUser))
            .map((otherUser) => (<ListItem key={otherUser}>
              <ChatCard otherUser={otherUser} client={client} isCurrent={currentChatWith === otherUser} setCurrent={() => openChat(otherUser) }/>
            </ListItem>))}
        </List>            
      </StyledScrollbar>
    </Stack>)
}

type ChatCardProps = Readonly<{
  otherUser: string,
  client: Client,
  isCurrent: boolean,
  setCurrent: () => void
}>;

function ChatCard({ otherUser, client, isCurrent, setCurrent }: ChatCardProps) {
  const [chatDetails, setChatDetails] = useState(client.getChatDetailsByUser(otherUser));
  const { displayName, contactName, profilePicture, lastActivity, online } = chatDetails;
  const { text, timestamp, sentByMe, delivery } = lastActivity;
  const [isTyping, setIsTyping] = useState(false);
  const status = useMemo(() => {
    if (!sentByMe) return null;
    if (!delivery) return <HourglassTop sx={{ color: "gold", rotate: "-90deg", fontSize: "1rem", marginRight: "4px" }}/>;
    const { delivered, seen } = delivery;
    return delivered 
            ? (<DoneAllSharp sx={{ color: seen ? "blue" : "gray", fontSize: "1rem", marginRight: "4px" }}/>) 
            : <DoneSharp sx={{ color: "gray", fontSize: "1rem", marginRight: "4px" }}/>;
  }, [delivery]);

  function formatTime() {
    const dt = DateTime.fromMillis(timestamp);
    const diff = -(dt.diffNow("day").as("day"));
    if (diff < 4) {
      const relative = dt.toRelativeCalendar();
      return relative === "today" ? dt.toFormat("h:mm a") : relative;
    }
    if (diff < 7) return dt.weekdayLong;
    return dt.toFormat("dd/LL/y");
  }

  useEffect(() => {
    const chat = client.getChatByUser(otherUser);
    if (chat?.type === "Chat") {
      chat.subscribeActivity(() => {
        setChatDetails(client.getChatDetailsByUser(otherUser));
        setIsTyping(chat.isOtherTyping);
      })
    }
  }, []);
  return (<ListItemButton 
    onClick={() => setCurrent()} 
    selected={isCurrent} 
    sx={{ borderRadius: "10px" }}
    variant={isCurrent ? "soft" : "plain"}
    color="success">
    <Stack direction="row" spacing={2} sx={{ flexGrow: 1 }}>
      <Badge variant="solid" color="success" badgeInset="10%" invisible={!online} sx={{ height: "fit-content", margin: "auto" }}>
        <Avatar src={profilePicture} size="lg"/>
      </Badge>
      <Stack direction="column" sx={{ flexGrow: 1 }}>
        <div style={{ display: "flex" }}>
          <DisableSelectTypography level="h6" fontWeight="lg" sx={{ width: "fit-content" }}>
            {contactName || displayName}
          </DisableSelectTypography>
          <div style={{ flexGrow: 1, display: "flex", flexWrap: "wrap", justifyContent: "right", alignContent: "center" }}>
            <DisableSelectTypography level="body3" component="span" sx={{ height: "fit-content" }}>
              {formatTime()}
            </DisableSelectTypography>
          </div>
        </div>
        <DisableSelectTypography sx={{ fontSize: "14px", color: isTyping ? "#1fa855" : "#656565" }}>
          {!isTyping && status}
          {isTyping ? "typing..." : truncateText(text, 50)}
        </DisableSelectTypography>
      </Stack>
    </Stack>
  </ListItemButton>)
}