import _ from "lodash";
import React, { useState, useRef, useMemo, useLayoutEffect } from "react";
import { Avatar, Badge, IconButton, Input, List, ListItem, ListItemButton, Stack } from "@mui/joy";
import { PersonAddAltOutlined, Search, ClearSharp, HourglassTop, DoneAllSharp, DoneSharp } from "@mui/icons-material";
import { NewChatPopup, NewMessageDialog } from "./NewChat";
import { DisableSelectTypography, StyledScrollbar } from "./CommonElementStyles";
import Client from "../client";
import { DateTime } from "luxon";
import { truncateText } from "../../../shared/commonFunctions";
import { AwaitedRequest, Chat, ChatRequest } from "../chatClasses";

type SidebarProps = {
  currentChatWith: string,
  openChat: (chatWith: string) => void,
  client: Client,
  chats: (Chat | ChatRequest | AwaitedRequest)[],
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
    if (client.chatsList.some((chat) => chat.otherUser.toLowerCase() === username.toLowerCase())) return "There is already an existing chat with this user.";
    return (await client.checkUsernameExists(username)) ? (username !== client.username ? "" : "Cannot chat with yourself.") : "No such user.";
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
            .filter((chat) => !search || chat.matchesName(search))
            .map((chat) => (<ListItem key={chat.otherUser}>
              <ChatCard chat={chat} isCurrent={currentChatWith === chat.otherUser} setCurrent={() => openChat(chat.otherUser) }/>
            </ListItem>))}
        </List>            
      </StyledScrollbar>
    </Stack>)
}

type ChatCardProps = Readonly<{
  chat: Chat | ChatRequest | AwaitedRequest
  isCurrent: boolean,
  setCurrent: () => void
}>;

function ChatCard({ chat, isCurrent, setCurrent }: ChatCardProps) {
  const [refresh, setRefresh] = useState({});
  const { displayName, contactName, profilePicture, lastActivity, isOnline, isOtherTyping, unreadMessages, draft } = refresh && chat.details; 
  const { text, timestamp, sentByMe, delivery } = lastActivity;
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

  useLayoutEffect(() => {
    chat.subscribeActivity(() => setRefresh({}));

    return () => chat.unsubscribeActivity();
  }, []);

  return (<ListItemButton 
    onClick={() => setCurrent()} 
    selected={isCurrent} 
    sx={{ borderRadius: "10px" }}
    variant={isCurrent ? "soft" : "plain"}
    color="success">
    <Stack direction="row" spacing={2} sx={{ flexGrow: 1 }}>
      <Badge variant="solid" color="success" badgeInset="10%" invisible={!isOnline} sx={{ height: "fit-content", margin: "auto" }}>
        <Avatar src={profilePicture} size="lg"/>
      </Badge>
      <Stack direction="column" sx={{ flexGrow: 1 }}>
        <div style={{ display: "flex" }}>
          <DisableSelectTypography level="h6" fontWeight="lg" sx={{ width: "fit-content" }}>
            {contactName || displayName}
          </DisableSelectTypography>
          <div style={{ flexGrow: 1, display: "flex", flexWrap: "wrap", justifyContent: "right", alignContent: "center" }}>
            <DisableSelectTypography level="body3" component="span" sx={{ height: "fit-content", color: unreadMessages ? "#1fa855" : "#656565" }}>
              {formatTime()}
            </DisableSelectTypography>
          </div>
        </div>
        <div style={{ display: "flex", flexDirection: "row" }}>
          <DisableSelectTypography sx={{ flexGrow: 1, fontSize: "15px", color: isOtherTyping ? "#1fa855" : "#656565" }}>
            {!isOtherTyping && status}
            {isOtherTyping 
              ? "typing..." 
              : (draft 
                  ? (<>
                      <DisableSelectTypography fontWeight="lg" sx={{ color: "#1fa855" }}>Draft: </DisableSelectTypography>
                      <DisableSelectTypography sx={{ fontStyle: "italic" }}>{draft}</DisableSelectTypography>
                    </>)
                  : truncateText(text, 50))}
          </DisableSelectTypography>
          {!!unreadMessages &&
            <div style={{ marginBlock: "auto", 
                          marginInline: "5px",
                          display: "flex",
                          flexWrap: "wrap",
                          justifyContent: "center",
                          alignContent: "center",
                          textAlign: "center",
                          paddingBlock: "1px",
                          paddingInline: "2px",
                          height: "20px",
                          width: "20px",
                          fontSize: "12px",
                          fontWeight: "800",
                          borderRadius: "100%", 
                          backgroundColor: "#1fa855", 
                          color: "white" }}>
              {unreadMessages < 10 ? unreadMessages : "9+"}
            </div>}
        </div>
      </Stack>
    </Stack>
  </ListItemButton>)
}