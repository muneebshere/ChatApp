import React, { useState, useRef, useEffect } from "react";
import { useEffectOnce } from "usehooks-ts";
import { Alert, Grid, IconButton, Input, LinearProgress, List, ListItem, ListItemButton, Button, Sheet, Stack, Typography } from "@mui/joy";
import { useMediaQuery, Theme } from "@mui/material";
import { ReportProblem, PersonAddAltOutlined, Search, ClearSharp, CloseSharp, SendRounded } from "@mui/icons-material";
import { Popover, PopoverTrigger, PopoverContent } from "./Popover";
import { Dialog, DialogContent } from "./Dialog";
import { StyledSheet, StyledScrollbar, CloseButton } from "./CommonElementStyles";
import ControlledTextField from "./ControlledTextField";
import { ChatViewMemo, ScrollState } from "./ChatView";
import { Client } from "../client";
import { chats } from "../prvChats";
import { StyledScrollingTextarea } from "./TextareaAutosize";
import { Placement } from "@floating-ui/react";

const chatWithList = chats.map((c) => c.chatWith);

export default function Main({ connected, displayName, client }: { connected: boolean, displayName: string, client: Client }) {
  const [currentChatWith, setCurrentChatWith] = useState("");
  const belowXL = useMediaQuery((theme: Theme) => theme.breakpoints.down("xl"));
  const typedMessages = useRef(new Map<string, string>());
  const lastScrollPositions = useRef(new Map<string, ScrollState>());
  
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
      <StyledSheet id="titleBar">
        <Typography level="h4" sx={{ textAlign: "center" }}>
          {displayName}
        </Typography>
      </StyledSheet>
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
          lastScrolledTo={ lastScrollPositions.current.get(currentChatWith) }
          setLastScrolledTo={(lastScrolledTo) => {
            if (currentChatWith) {
              lastScrollPositions.current.set(currentChatWith, lastScrolledTo);
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
        <StyledSheet>
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
        </StyledSheet>
      </Grid>)
    : null;
}

type NewChatPopupProps = {
  initialChatWith?: string,
  validate: (username: string) => Promise<string>, 
  returnUser: (username: string) => void,
  isPopupOpen: boolean,
  setIsPopupOpen: (open: boolean) => void,
  placement: Placement,
  belowXL: boolean,
  children: JSX.Element
};

function NewChatPopup({ validate, initialChatWith, returnUser, placement, belowXL, isPopupOpen, setIsPopupOpen, children }: NewChatPopupProps) {
  const [chatWithUser, setChatWithUser] = useState(initialChatWith || "");
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
    <Popover modal={true}
      placement={placement}
      changeOpenTo={isPopupOpen}
      notifyChange={(open) => {
        setChatWithUser("");
        setIsPopupOpen(open);
      }}>
      <PopoverTrigger>
        {children}
      </PopoverTrigger>
      <PopoverContent>
        <div style={{ borderRadius: 8, padding: 10, border: "1.5px solid #d8d8df", backgroundColor: "rgba(246, 246, 246, 0.8)", boxShadow: "0px 1px 3px 1.5px #eeeeee", backdropFilter: "blur(4px)", width: belowXL ? "80vw" : "20vw" }}>
          <Stack direction="column" spacing={1}>
            <Typography level="h6" fontWeight="lg">
              New chat
            </Typography>
            <div style={{ display: "flex", alignContent: "center", justifyContent: "stretch" }}>
              <ControlledTextField
                autoFocus
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
                  }}}/>
              </div>
          </Stack>
        </div>
      </PopoverContent>
    </Popover>)
}

type NewMessageDialogProps = {
  warn: boolean,
  belowXL: boolean,
  chatWith: string,
  setWarn: (warn: boolean) => void,
  setChatWith: (newChat: string) => void,
  setNewMessage: (newMessage: string) => void,
  validate: (username: string) => Promise<string>
};

function NewMessageDialog({ warn, chatWith, belowXL, setWarn, setChatWith, setNewMessage, validate }: NewMessageDialogProps) {
  const [isPopupOpen, setIsPopupOpen] = useState(false);
  return (
    <>
      <Dialog 
        outsidePress
        overlayBackdrop="opacity(100%) blur(4px)"
        controlledOpen={!!chatWith} 
        setControlledOpen={(open) => { 
          if (!open) {
            if (isPopupOpen) {
              setIsPopupOpen(false);
            }
            else {
              setWarn(true);
            }
          }
        }}>
        <DialogContent>
          <Sheet
            variant="outlined"
            sx={{
              width: belowXL ? "90vw" : "40vw",
              borderRadius: "md",
              p: 3,
              backgroundColor: "rgba(246, 246, 246, 0.8)",
              boxShadow: "lg", 
              backdropFilter: "blur(4px)"}}>
            <CloseButton onClick={ () => setWarn(true) }>
              <CloseSharp sx={{ fontSize: "1.5rem" }}/>
            </CloseButton>
            <Stack direction="row" spacing={0.7} sx={{ flexWrap: "wrap", alignContent: "center" }}>
              <Typography
                component="h2"
                level="h6"
                textColor="inherit"
                fontWeight="lg"
                mb={1} 
                sx={{ display: "flex", textAlign: "center", flexWrap: "wrap", alignContent: "center", marginBottom: 0 }}>
                  Send message request to
              </Typography>
              <NewChatPopup
                initialChatWith={chatWith}
                isPopupOpen={isPopupOpen}
                setIsPopupOpen={setIsPopupOpen}
                belowXL={belowXL} 
                placement="bottom"
                validate={validate} 
                returnUser={(chatWith) => {
                  setIsPopupOpen(false);
                  setChatWith(chatWith);
                }}>
                <Sheet sx={{ marginBlock: "8px", paddingBlock: "2px", paddingInline: "6px", border: "solid 0.8px black", backgroundColor: "#d8d8df", borderRadius: "12px", textAlign: "center", ":hover" : {
                  filter: "brightness(0.9)"
                } }}>
                  <Typography
                    component="h2"
                    level="h6"
                    textColor="inherit"
                    fontWeight="md"
                    sx={{ display: "flex", textAlign: "center", flexWrap: "wrap", alignContent: "center", marginBottom: 0, cursor: "default" }}
                    mb={1}>
                      {chatWith}
                  </Typography>
                </Sheet>
              </NewChatPopup>
            </Stack>
            <Stack
              direction="row" 
              spacing={1} 
              sx={{
                flex: 0, 
                flexBasis: "content", 
                display: "flex", 
                flexDirection: "row", 
                flexWrap: "nowrap",
                borderTopRightRadius: 20,
                borderBottomRightRadius: 20,
                paddingBottom: "8px",
                zIndex: 20 }}>
              <StyledScrollingTextarea
                placeholder="Type a message"
                outerProps={{ style: { marginTop: "12px" } }}
                onChange={ (e) => setNewMessage(e.target.value) }
                onSubmit={(value) => alert(`Sending message request: ${value}`)}
                minRows={3}
                maxRows={5} 
                style={{ flex: 1 }}/>
                <IconButton 
                  variant="outlined"
                  color="success" 
                  sx={{ flexGrow: 0, flexBasis: "content", height: "fit-content", alignSelf: "center", borderRadius: 20, backgroundColor: "var(--joy-palette-success-plainHoverBg)" }}>
                  <SendRounded sx={{ fontSize: "2rem"}}/>
                </IconButton>
            </Stack>
          </Sheet>      
        </DialogContent>
      </Dialog>
      <Dialog 
        outsidePress={false}
        controlledOpen={warn}
        setControlledOpen={() => {}}>
        <DialogContent>
          <Sheet
            variant="outlined"
            sx={{
              width: belowXL ? "70vw" : "25vw",
              borderRadius: "md",
              p: 3,
              boxShadow: "lg"}}>
            <Typography
              textAlign="center"
              component="h2"
              id="modal-title"
              level="h4"
              textColor="inherit"
              fontWeight="lg"
              mb={1}>
              Cancel message request?
            </Typography>
            <Typography id="modal-desc" textColor="text.tertiary" textAlign="center">
              You'll lose the message you're typing.
            </Typography>
            <Grid container direction="row" sx={{ paddingTop: "15px" }}>
              <Grid xs={6} sx={{ display: "flex", justifyContent: "center", paddingInline: "20px" }}>
                <Button variant="solid" color="success" sx={{ flexGrow: 1 }} onClick={ () => setWarn(false) }>
                  Go back
                </Button>
              </Grid>
              <Grid xs={6} sx={{ display: "flex", justifyContent: "center", paddingInline: "20px" }}>
                <Button variant="solid" color="danger" sx={{ flexGrow: 1 }} onClick={ () => {
                  setWarn(false);
                  setChatWith("");
                  setNewMessage("");
                } }>
                  Cancel
                </Button>
              </Grid>
            </Grid>
          </Sheet>      
        </DialogContent>
      </Dialog>
    </>);
}