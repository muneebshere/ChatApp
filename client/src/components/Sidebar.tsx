import React, { useState, useRef } from "react";
import { IconButton, Input, List, ListItem, ListItemButton, Stack } from "@mui/joy";
import { PersonAddAltOutlined, Search, ClearSharp } from "@mui/icons-material";
import { NewChatPopup, NewMessageDialog } from "./NewChat";
import { DisableSelectTypography, StyledScrollbar } from "./CommonElementStyles";
import { Client } from "../client";

type SidebarProps = {
  currentChatWith: string,
  openChat: (chatWith: string) => void,
  client: Client,
  belowXL: boolean
}

export default function Sidebar({ currentChatWith, openChat, client, belowXL }: SidebarProps) {
  const [search, setSearch] = useState("");
  const [newChatWith, setNewChatWith] = useState("");
  const [isPopupOpen, setIsPopupOpen] = useState(false);
  const [warn, setWarn] = useState(false);
  const newMessageRef = useRef("");
  const currentDetails = "";
  
  async function validateNewChat(username: string) {
    if (!username) return "";
    if (client.chatsList.some((chatWith) => chatWith.toLowerCase() === username.toLowerCase())) return "There is already an existing chat with this user.";
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
          {client.chatsList.filter((chatWith) => !search || chatWith.toLowerCase().includes(search.toLowerCase())).map((chatWith) =>
          <ListItem key={chatWith}>
            <ChatCard {...client.getChatDetailsByUser(chatWith)} isCurrent={currentChatWith === chatWith} setCurrent={() => openChat(chatWith) }/>
          </ListItem>)}
        </List>            
      </StyledScrollbar>
    </Stack>)
}

type ChatCardProps = Readonly<{
  displayName?: string, 
  contactName?: string, 
  profilePicture?: string, 
  lastActivity: number,
  isCurrent: boolean,
  setCurrent: () => void
}>;

function ChatCard({ displayName, contactName, profilePicture, lastActivity, isCurrent, setCurrent }: ChatCardProps) {
  return (<ListItemButton 
    onClick={() => setCurrent()} 
    selected={isCurrent} 
    sx={{ borderRadius: "10px", userSelect: "none" }}
    variant={isCurrent ? "soft" : "plain"}
    color="success">
    {contactName || displayName}
  </ListItemButton>)
}