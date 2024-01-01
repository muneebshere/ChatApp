import _ from "lodash";
import React, { useState, useRef, useMemo, useLayoutEffect, useEffect } from "react";
import { Avatar, Badge, Button, Grid, IconButton, Input, List, ListItem, ListItemButton, Sheet, Stack } from "@mui/joy";
import { PersonAddAltOutlined, Search, ClearSharp, HourglassTop, DoneAllSharp, DoneSharp, LogoutOutlined } from "@mui/icons-material";
import { NewChatPopup, NewMessageDialog } from "./NewChat";
import { DisableSelectTypography, ReactMarkdownVariableEmoji, StyledScrollbar } from "./CommonElementStyles";
import Client from "../Client";
import { DateTime } from "luxon";
import { truncateMarkdown } from "../../../shared/commonFunctions";
import { SentChatRequest, Chat, ReceivedChatRequest } from "../ChatClasses";
import { flushSync } from "react-dom";
import { useUpdateEffect } from "usehooks-ts";
import remarkGfm from "remark-gfm";
import remarkMath from "remark-math";
import twemoji from "../custom_modules/remark-twemoji";
import rehypeKatex from "rehype-katex";
import rehypeRaw from "rehype-raw";
import { SxProps } from "@mui/material";
import { Profile } from "../../../shared/commonTypes";
import Dialog from "./Dialog";

type SidebarProps = {
  currentChatWith: string,
  openChat: (chatWith: string) => void,
  client: Client,
  chats: (Chat | ReceivedChatRequest | SentChatRequest)[],
  belowXL: boolean,
  allowLeaveFocus: React.MutableRefObject<boolean>,
  giveBackFocus: React.MutableRefObject<() => void>,
  profile: Profile,
  changeProfile: (profile: Omit<Profile, "username">) => Promise<void>,
}

export default function Sidebar({ profile, currentChatWith, openChat, chats, client, belowXL, allowLeaveFocus, giveBackFocus }: SidebarProps) {
  const [search, setSearch] = useState("");
  const [newChatWith, setNewChatWith] = useState("");
  const [isPopupOpen, setIsPopupOpen] = useState(false);
  const [isLogoutDialogOpen, setIsLogoutDialogOpen] = useState(false);
  const [warn, setWarn] = useState(false);
  const newMessageRef = useRef("");

  const mouseDown = () => allowLeaveFocus.current = true;
  const mouseUp = () => allowLeaveFocus.current = false;

  useUpdateEffect(() => {
    if (!newChatWith && !isPopupOpen && !allowLeaveFocus.current) giveBackFocus.current?.();
  }, [newChatWith, isPopupOpen]);
  
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
      isMessageEmpty={() => !newMessageRef.current?.trim()} 
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
    <Dialog
      outsidePress={false}
      open={isLogoutDialogOpen}
      overlayBackdrop="opacity(100%) blur(6px)">
      <Sheet
        variant="outlined"
        sx={{
          width: belowXL ? "75vw" : "30vw",
          borderRadius: "md",
          p: 3,
          boxShadow: "lg"}}>
        <DisableSelectTypography
          textAlign="center"
          component="h2"
          id="modal-title"
          level="h4"
          textColor="inherit"
          fontWeight="lg"
          mb={1}>
          Are you sure you want to log out?
        </DisableSelectTypography>
        <DisableSelectTypography id="modal-desc" textColor="text.tertiary" textAlign="center">
          You will have to re-enter the password to log in again.
        </DisableSelectTypography>
        <Grid container direction="row" sx={{ paddingTop: "15px" }}>
          <Grid xs={6} sx={{ display: "flex", justifyContent: "center", paddingInline: "20px" }}>
            <Button 
              variant="solid" 
              color="primary" 
              sx={{ flexGrow: 1 }} 
              onClick={ () => setIsLogoutDialogOpen(false) }>
              Cancel
            </Button>
          </Grid>
          <Grid xs={6} sx={{ display: "flex", justifyContent: "center", paddingInline: "20px" }}>
            <Button 
              variant="solid" 
              color="danger" 
              sx={{ flexGrow: 1 }} 
              onClick={ () => {
                setIsLogoutDialogOpen(false);
                client.userLogOut();
              }}>
              Logout
            </Button>
          </Grid>
        </Grid>
      </Sheet>      
    </Dialog>
    <div style={{ display: "flex", marginBottom: 10 }}>
      <div style={{ display: "flex", flex: 1, flexWrap: "wrap", justifyContent: "flex-start", alignContent: "center", paddingLeft: 20 }}>
        <Avatar src={profile?.profilePicture} size="md"/>
      </div>
      <div style={{ display: "flex", flex: 1, flexWrap: "wrap", justifyContent: "flex-end", alignContent: "center", paddingRight: 15 }}>
        <IconButton 
          variant="solid" 
          color="danger"
          size="sm"
          style={{ height: "32px", width: "32px", padding: 0, margin: "8px" }}
          sx={ isLogoutDialogOpen ? { backgroundColor: "var(--joy-palette-danger-solidHoverBg)" } : {} }
          onClick={() => setIsLogoutDialogOpen(true)}>
          <LogoutOutlined color="inherit" sx={{ fontSize: "1.5rem" }}/>
        </IconButton>
      </div>
    </div>
    <div style={{ display: "flex", alignContent: "center", justifyContent: "stretch", paddingBlock: 0, paddingInline: 15 }}>
      <Input 
        placeholder="Search for chat"
        value={search}
        style={{ width: "100%" }}
        onChange={(e: any) => setSearch(e?.target?.value || "")}
        onMouseDown={mouseDown}
        onMouseUp={mouseUp}
        onBlur={() => giveBackFocus.current?.()}
        endDecorator={
          search 
            ? (<IconButton variant="soft" color="neutral" onClick={() => setSearch("")}>
                <ClearSharp sx={{ fontSize: "1.2rem" }}/>
              </IconButton>)
            : (<Search sx={{ fontSize: "1.2rem" }}/>) 
        }/>
      <NewChatPopup
        isPopupOpen={isPopupOpen}
        setIsPopupOpen={setIsPopupOpen}
        belowXL={belowXL} 
        placement={ belowXL ? "bottom-end" : "bottom-start" }
        validate={validateNewChat} 
        returnUser={(chatWith) => {
          if (chatWith) allowLeaveFocus.current = true;
          flushSync(() => setIsPopupOpen(false));
          allowLeaveFocus.current = false;
          setNewChatWith(chatWith);
        }}>
          <IconButton
            variant="plain" 
            color="success"
            style={{ marginInline: "5px" }}
            sx={ isPopupOpen ? { backgroundColor: "var(--joy-palette-success-plainHoverBg)" } : {} }
            onMouseDown={mouseDown}
            onMouseUp={mouseUp}>
            <PersonAddAltOutlined color="success" sx={{ fontSize: "1.5rem" }}/>
          </IconButton>
      </NewChatPopup>
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
  chat: Chat | ReceivedChatRequest | SentChatRequest
  isCurrent: boolean,
  setCurrent: () => void
}>;

function ChatCard({ chat, isCurrent, setCurrent }: ChatCardProps) {
  const [refresh, setRefresh] = useState({});
  const { displayName, contactName, profilePicture, lastActivity, isOnline, isOtherTyping, unreadMessages, draft } = refresh && chat.details; 
  const { text, timestamp, sentByMe, delivery } = lastActivity;
  const [displayText, setDisplayText] = useState(""); 
  const status = useMemo(() => {
    const commonProps: SxProps = { fontSize: "1rem", marginRight: "6px", marginBlock: "auto" };
    if (!sentByMe) return null;
    if (!delivery) return <HourglassTop sx={{ color: "gold", rotate: "-90deg", ...commonProps }}/>;
    const { delivered, seen } = delivery;
    return delivered 
            ? (<DoneAllSharp sx={{ color: seen ? "blue" : "gray", ...commonProps }}/>) 
            : <DoneSharp sx={{ color: "gray", ...commonProps }}/>;
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
    truncateMarkdown(draft ? draft : text, 50).then((truncated) => setDisplayText(truncated));
  }, [draft, text]);

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
        <div style={{ display: "flex", flexDirection: "row", fontSize: "15px" }}>
            {!isOtherTyping && !draft && status}
            {isOtherTyping
              ? (<DisableSelectTypography sx={{ flexGrow: 1, color: isOtherTyping ? "#1fa855" : "#656565" }}>
                  typing...
                </DisableSelectTypography>)
              : (<div style={{ flexGrow: 1, display: "flex", flexDirection: "row" }}>
                  {draft && 
                    <DisableSelectTypography fontWeight="lg" sx={{ color: "#1fa855" }}>
                      Draft:&nbsp;
                    </DisableSelectTypography>}
                  <DisableSelectTypography component="span" sx={{ fontStyle: draft ? "italic" : undefined, color: "#656565", "--markdown-emoji-size": "18px" }}>
                    <ReactMarkdownVariableEmoji 
                    className="react-markdown" 
                    components={{ p: "span", div: "span" }}
                    children={displayText}
                    remarkPlugins={[remarkGfm, remarkMath, twemoji]}
                    rehypePlugins={[rehypeKatex, rehypeRaw]}/>
                  </DisableSelectTypography>
                </div>)}
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