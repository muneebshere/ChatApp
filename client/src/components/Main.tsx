import React, { useState, useRef, useEffect, useCallback } from "react";
import { Alert, Grid, IconButton, Input, LinearProgress, List, ListItem, ListItemButton, Modal, ModalClose, Sheet, Stack, Typography } from "@mui/joy";
import { useMediaQuery, Theme } from "@mui/material";
import { ReportProblem, PersonAddAltOutlined, Search, ClearSharp } from "@mui/icons-material";
import { Popover, PopoverTrigger, PopoverContent } from "./Popover";
import { Item, StyledScrollbar, ControlledTextField } from "./Common";
import { ChatViewMemo } from "./ChatView";
import { useEffectOnce } from "usehooks-ts";
import { Client } from "../client";
import { chats } from "./prvChats";
import styled from "@emotion/styled";

const ToggledIconButton = styled(IconButton)`
`

const chatWithList = chats.map((c) => c.chatWith);

export default function Main({ connected, displayName, client }: { connected: boolean, displayName: string, client: Client }) {
  const [currentChatWith, setCurrentChatWith] = useState("");
  const belowXL = useMediaQuery((theme: Theme) => theme.breakpoints.down("xl"));
  const typedMessages = useRef(new Map<string, string>());
  const lastScrollPositions = useRef(new Map<string, number>());
  
  useEffectOnce(() => {
    const currentChatWith = window.history.state?.currentChatWith || "";
    window.history.replaceState({ currentChatWith }, "", `#${currentChatWith}`);
    setCurrentChatWith(currentChatWith);
    const popStateListener = (event: PopStateEvent) => setCurrentChatWith(event.state?.currentChatWith || "");
    window.addEventListener("popstate", popStateListener);
    return () => window.removeEventListener("popstate", popStateListener);
  });

  function openChat(chat: string) {
    window.history.pushState({ currentChatWith: chat }, "", `#${chat}`);
    setCurrentChatWith(chat);
  }

  return (
  <Grid container direction="column" sx={{ flex: 1, flexBasis: "content", display: "flex", flexDirection: "column" }}>
    <DisconnectedAlert connected={connected}/>
    <Grid xs={12} sx={{ flex: 0, flexBasis: "content" }}>
      <Item>
        <Typography level="h4" sx={{ textAlign: "center" }}>
          {displayName}
        </Typography>
      </Item>
    </Grid>
    <Grid 
      container 
      xs={12} 
      sx={{ flex: 1, flexBasis: 0, minHeight: 0 }}>
      {(!belowXL || !currentChatWith) &&
      <Grid xs={12} xl={3} sx={{ minHeight: 0, maxHeight: "100%", display: "flex", flexDirection: "column" }}>
        <Sidebar currentChatWith={currentChatWith} openChat={openChat} client={client} belowXL={belowXL}/>
      </Grid>}
      {(!belowXL || currentChatWith) &&
      <Grid xs={12} xl={9} sx={{ minHeight: 0, maxHeight: "100%" }}>
        <ChatViewMemo 
          key={currentChatWith ?? ""}
          chatWith={currentChatWith ?? ""}
          message={typedMessages.current.get(currentChatWith) || ""}
          setMessage={(message: string) => {
            if (currentChatWith) {
              typedMessages.current.set(currentChatWith, message)
            }}}
          lastScroll={ lastScrollPositions.current.get(currentChatWith) || 0 }
          setLastScroll={(scroll) => {
            if (currentChatWith) {
              lastScrollPositions.current.set(currentChatWith, scroll);
            }
          }}/>
      </Grid>}
    </Grid>
  </Grid>)
}

type SidebarProps = {
  currentChatWith: string,
  openChat: (chatWith: string) => void,
  client: Client,
  belowXL: boolean
}

function Sidebar({ currentChatWith, openChat, client, belowXL }: SidebarProps) {
  const [search, setSearch] = useState("");
  const [newChat, setNewChat] = useState("");
  const [isPopupOpen, setIsPopupOpen] = useState(false);
  const [warn, setWarn] = useState(false);
  const newMessageRef = useRef("");

  async function validateNewChat(username: string) {
    if (!username) return "";
    if (chatWithList.some((chatWith) => chatWith.toLowerCase() === username.toLowerCase())) return "There is already an existing chat with this user.";
    return (await client.checkUsernameExists(username)) ? (username !== client.username ? "" : "Cannot chat with yourself.") : "No such user.";
  }

  return (
    <Stack direction="column" style={{ height: "100%" }}>
      <NewMessageModal open={!!newChat} 
        warn={warn} 
        setWarn={setWarn} 
        belowXL={belowXL} 
        eraseNewChat={() => setNewChat("")}
        setNewMessage={(message) => { newMessageRef.current = message; }}
        />
      <div style={{ display: "flex" }}>
        <div style={{ display: "flex", flex: 1, flexWrap: "wrap", justifyContent: "flex-start", alignContent: "center", paddingLeft: 20 }}>
          <Typography level="h4" fontWeight="md">
            Chats
          </Typography>
        </div>
        <div style={{ display: "flex", flex: 1, flexWrap: "wrap", justifyContent: "flex-end", alignContent: "center", paddingRight: 40 }}>
        <Popover modal={true}
          placement={ belowXL ? "bottom-end" : "bottom-start" }
          changeOpenTo={isPopupOpen}
          notifyChange={(open) => setIsPopupOpen(open)}>
          <PopoverTrigger>
            <IconButton variant="plain" color="success" sx={ isPopupOpen ? { backgroundColor: "var(--joy-palette-success-plainHoverBg)" } : {} }>
              <PersonAddAltOutlined color="success" sx={{ fontSize: "1.5rem" }}/>
            </IconButton>
          </PopoverTrigger>
          <PopoverContent>
            <NewChatPopup belowXL={belowXL} validate={validateNewChat} returnUser={(chatWith) => {
              setIsPopupOpen(false);
              setNewChat(chatWith);
            }}/>
          </PopoverContent>
        </Popover>
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
          {chatWithList.filter((chatWith) => !search || chatWith.toLowerCase().includes(search.toLowerCase())).map((chatWith) =>
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

function DisconnectedAlert({ connected }: { connected: boolean }) {
  return !connected
    ? (<Grid xs={12} sx={{ flex: 0, flexBasis: "content" }}>
        <Item>
          <Stack direction="column" sx={{ justifyContent: "stretch", justifySelf: "center" }}>
            <Alert 
              variant="soft" 
              size="lg"
              sx={{ justifyContent: "center", borderBottomRightRadius: 0, borderBottomLeftRadius: 0 }} 
              color="danger" 
              startDecorator={<ReportProblem/>}>
              <Typography sx={{ textAlign: "center" }}>
                Disconnected. Reconnecting...
              </Typography>
            </Alert>
            <LinearProgress variant="soft" color="danger" 
              sx={{ borderTopRightRadius: 0, borderTopLeftRadius: 0 }} />
         </Stack>
        </Item>
      </Grid>)
    : null;
}

type NewChatPopupProps = { 
  validate: (username: string) => Promise<string>, 
  returnUser: (username: string) => void,
  belowXL: boolean
};

function NewChatPopup({ validate, returnUser, belowXL }: NewChatPopupProps) {
  const [chatWithUser, setChatWithUser] = useState("");
  const [usernameInvalid, setUsernameInvalid] = useState("");
  
  useEffect(() => {
    let ignore = false;
    const setUserValid = async () => {
      const message = await validate(chatWithUser);
      if (!ignore) {
        setUsernameInvalid(message);
      }
    };
    setUserValid();
    return () => {
      ignore = true;
    }
  }, [chatWithUser]);

  return (
    <div style={{ borderRadius: 8, padding: 10, border: "1.5px solid #d8d8df", backgroundColor: "rgba(244, 246, 244, 0.8)", boxShadow: "0px 1px 3px 1.5px #eeeeee", backdropFilter: "blur(4px)", width: belowXL ? "80vw" : "20vw" }}>
      <Stack direction="column" spacing={1}>
        <Typography level="h5" fontWeight="md">
          New chat
        </Typography>
        <div style={{ display: "flex", alignContent: "center", justifyContent: "stretch" }}>
        <ControlledTextField
          autoComplete="new-random"
          role="presentation"
          variant="outlined"
          placeholder="Begin chat with" 
          type="text"
          value={chatWithUser}
          setValue={setChatWithUser}
          forceInvalid
          preventSpaces
          valid={!usernameInvalid}
          errorMessage={usernameInvalid}
          onEnter={ () => {
            if (!usernameInvalid && chatWithUser) {
              returnUser(chatWithUser);
            }
          }}/>
        </div>
      </Stack>
    </div>)
}

type NewMessageModalProps = {
  open: boolean,
  warn: boolean,
  belowXL: boolean,
  setWarn: (warn: boolean) => void,
  eraseNewChat: () => void,
  setNewMessage: (newMessage: string) => void
};

function NewMessageModal({ open, warn, belowXL, setWarn, eraseNewChat, setNewMessage }: NewMessageModalProps) {
  return (
    <Modal
      disableEnforceFocus
      open={open}
      onClose={ (_, reason) => {
        if (reason === "closeClick" || reason === "escapeKeyDown") {
          setWarn(true);
        }
      } }
      sx={{ display: "flex", justifyContent: "center", alignItems: "center" }}>
      <Sheet
        variant="outlined"
        sx={{
          width: belowXL ? "90vw" : "60vw",
          borderRadius: "md",
          p: 3,
          boxShadow: "lg"}}>
        <Modal
          disableEnforceFocus
          open={warn}
          onClose={ () => {
            setWarn(false);
            eraseNewChat();
            setNewMessage("");
          } }
          sx={{ display: "flex", justifyContent: "center", alignItems: "center" }}>
          <Sheet
            variant="outlined"
            sx={{
              maxWidth: 500,
              borderRadius: "md",
              p: 3,
              boxShadow: "lg"}}>
            <ModalClose
              variant="outlined"
              sx={{
                top: "calc(-1/4 * var(--IconButton-size))",
                right: "calc(-1/4 * var(--IconButton-size))",
                boxShadow: "0 2px 12px 0 rgba(0 0 0 / 0.2)",
                borderRadius: "50%",
                bgcolor: "background.body"}}/>
            <Typography
              component="h2"
              id="modal-title"
              level="h4"
              textColor="inherit"
              fontWeight="lg"
              mb={1}>
              Cancel message request?
            </Typography>
            <Typography id="modal-desc" textColor="text.tertiary">
              You will lose the message you're typing.
            </Typography>
          </Sheet>
        </Modal>
        <ModalClose
          variant="outlined"
          sx={{
            top: "calc(-1/4 * var(--IconButton-size))",
            right: "calc(-1/4 * var(--IconButton-size))",
            boxShadow: "0 2px 12px 0 rgba(0 0 0 / 0.2)",
            borderRadius: "50%",
            bgcolor: "background.body"}}/>
        <Typography
          component="h2"
          id="modal-title"
          level="h4"
          textColor="inherit"
          fontWeight="lg"
          mb={1}>
            Type Message
        </Typography>
        <Typography id="modal-desc" textColor="text.tertiary">
        </Typography>
      </Sheet>
    </Modal>)
}