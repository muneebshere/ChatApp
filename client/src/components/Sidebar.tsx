import React, { useState, useRef } from "react";
import { IconButton, Input, List, ListItem, ListItemButton, Stack, Typography } from "@mui/joy";
import { PersonAddAltOutlined, Search, ClearSharp } from "@mui/icons-material";
import { NewChatPopup, NewMessageDialog } from "./NewChat";
import { StyledScrollbar } from "./CommonElementStyles";
import { Client } from "../client";

type SidebarProps = {
  chatsList: string[],
  currentChatWith: string,
  openChat: (chatWith: string) => void,
  client: Client,
  belowXL: boolean
}

export default function Sidebar({ currentChatWith, chatsList, openChat, client, belowXL }: SidebarProps) {
  const [search, setSearch] = useState("");
  const [newChat, setNewChat] = useState("");
  const [isPopupOpen, setIsPopupOpen] = useState(false);
  const [warn, setWarn] = useState(false);
  const newMessageRef = useRef("");

  async function validateNewChat(username: string) {
    if (!username) return "";
    if (chatsList.some((chatWith) => chatWith.toLowerCase() === username.toLowerCase())) return "There is already an existing chat with this user.";
    return (await client.checkUsernameExists(username)) ? (username !== client.username ? "" : "Cannot chat with yourself.") : "No such user.";
  }

  return (
    <Stack direction="column" style={{ height: "100%" }}>
      <NewMessageDialog
        chatWith={newChat} 
        warn={warn} 
        setWarn={setWarn} 
        belowXL={belowXL} 
        setChatWith={(chatWith) => setNewChat(chatWith)}
        setNewMessage={(message) => { newMessageRef.current = message; }}
        validate={validateNewChat}
        />
      <div style={{ display: "flex" }}>
        <div style={{ display: "flex", flex: 1, flexWrap: "wrap", justifyContent: "flex-start", alignContent: "center", paddingLeft: 20 }}>
          <Typography level="h4" fontWeight="md">
            Chats
          </Typography>
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
              setNewChat(chatWith);
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
          {chatsList.filter((chatWith) => !search || chatWith.toLowerCase().includes(search.toLowerCase())).map((chatWith) =>
          <ListItem key={chatWith}>
            <ListItemButton 
              onClick={() => openChat(chatWith)} 
              selected={currentChatWith === chatWith} 
              sx={{ borderRadius: "10px" }}
              variant={currentChatWith === chatWith ? "soft" : "plain"}
              color="success">
              {chatWith}
            </ListItemButton>
          </ListItem>)}
        </List>            
      </StyledScrollbar>
    </Stack>)
}