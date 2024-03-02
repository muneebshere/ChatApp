import React, { useState, useEffect, useRef, useMemo } from "react";
import { Grid, IconButton, Button, Sheet, Stack, ButtonProps } from "@mui/joy";
import { CloseSharp, SendRounded } from "@mui/icons-material";
import Popover, { PopoverTrigger, PopoverContent } from "./Popover";
import Dialog from "./Dialog";
import { CloseButton, DisableSelectTypography } from "./CommonElementStyles";
import ControlledTextField from "./ControlledTextField";
import { StyledScrollingTextarea } from "./TextareaAutosize";
import { Placement } from "@floating-ui/react";
import { flushSync } from "react-dom";
import { match } from "ts-pattern";

type NewChatPopupProps = {
  initialChatWith?: string,
  escOnEnter?: boolean,
  validate: (username: string) => Promise<string>, 
  returnUser: (username: string) => void,
  isPopupOpen: boolean,
  setIsPopupOpen: (open: boolean) => void,
  placement: Placement,
  belowXL: boolean,
  children: JSX.Element
};

export function NewChatPopup({ validate, escOnEnter, initialChatWith, returnUser, placement, belowXL, isPopupOpen, setIsPopupOpen, children }: NewChatPopupProps) {
  const [newChatWith, setNewChatWith] = useState("");
  const [usernameInvalid, setUsernameInvalid] = useState("");
  
  useEffect(() => {
    let ignore = false;
    const setUserValid = async () => {
      const message = await validate(newChatWith);
      if (!ignore) {
        setUsernameInvalid(message);
      }
    };
    setUserValid();
    return () => {
      ignore = true;
    }
  }, [newChatWith]);

  useEffect(() => {
    if (isPopupOpen && initialChatWith) {
      setNewChatWith(initialChatWith);
    }
  }, [isPopupOpen])

  return (
    <Popover modal={true}
      placement={placement}
      controlledOpen={isPopupOpen}
      setControlledOpen={(open) => {
        setNewChatWith("");
        setIsPopupOpen(open);
      }}>
      <PopoverTrigger>
        {children}
      </PopoverTrigger>
      <PopoverContent>
        <div style={{ borderRadius: 8, padding: 10, border: "1.5px solid #d8d8df", backgroundColor: "rgba(246, 246, 246, 0.8)", boxShadow: "0px 1px 3px 1.5px #eeeeee", backdropFilter: "blur(4px)", width: belowXL ? "80vw" : "20vw" }}>
          <Stack direction="column" spacing={1}>
            <DisableSelectTypography level="h4" fontWeight="lg">
              New chat
            </DisableSelectTypography>
            <div style={{ display: "flex", alignContent: "center", justifyContent: "stretch" }}>
              <ControlledTextField
                autoFocus
                autoComplete="username"
                role="presentation"
                variant="outlined"
                highlightColor="#1f7a1f"
                placeholder="Begin chat with" 
                type="text"
                defaultValue={newChatWith || undefined}
                value={newChatWith}
                setValue={setNewChatWith}
                forceInvalid
                preventSpaces
                valid={!usernameInvalid}
                errorMessage={usernameInvalid}
                onEnter={ () => {
                    if (newChatWith) {
                      if (!usernameInvalid) {
                        returnUser(newChatWith);
                        setNewChatWith("");
                      }
                    }
                    else if (escOnEnter) {
                      returnUser("");
                    }
                  }}/>
              </div>
          </Stack>
        </div>
      </PopoverContent>
    </Popover>)
}

type NewMessageDialogProps = {
  warn: boolean,
  belowXL: boolean,
  newChatWith: string,
  isMessageEmpty: () => boolean,
  setWarn: (warn: boolean) => void,
  setNewChatWith: (newChat: string) => void,
  setNewMessage: (newMessage: string) => void,
  validate: (username: string) => Promise<string>,
  sendRequest: () => void
};

export function NewMessageDialog({ warn, newChatWith, belowXL, isMessageEmpty, setWarn, setNewChatWith, setNewMessage, validate, sendRequest }: NewMessageDialogProps) {
  const [isPopupOpen, setIsPopupOpen] = useState(false);
  const [keyboardHeight, setKeyboardHeight] = useState((navigator as any).virtualKeyboard.boundingRect.height);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const clickedInside = useRef(false);
  const keepFocusIn = useMemo(() => [textareaRef, clickedInside] as const, []);

  useEffect(() => {
    const updateHeight = () => setKeyboardHeight((navigator as any).virtualKeyboard.boundingRect.height);
    window.visualViewport.addEventListener("resize", updateHeight);
    return () => {
      window.visualViewport.removeEventListener("resize", updateHeight);
    }
  }, []);

  return (
    <>
      <Dialog 
        outsidePress
        overlayBackdrop="opacity(100%) blur(4px)"
        open={!!newChatWith}
        keepFocusIn={keepFocusIn}
        onDismiss={() => { 
          if (isPopupOpen) {
            setIsPopupOpen(false);
          }
          else if (isMessageEmpty()) {
            setNewChatWith("");
          }
          else {
            setWarn(true);
          }
        }}>
        <Sheet
          variant="outlined"
          sx={{
            width: belowXL ? "90vw" : "40vw",
            borderRadius: "md",
            position: "relative",
            bottom: keyboardHeight ? "100px" : 0,
            p: 3,
            backgroundColor: "rgba(246, 246, 246, 0.8)",
            boxShadow: "lg", 
            backdropFilter: "blur(4px)"}}>
          <CloseButton onClick={ () => {   
              if (isPopupOpen) {
                setIsPopupOpen(false);
              }
              else if (isMessageEmpty()) {
                setNewChatWith("");
              }
              else {
                setWarn(true);
              }              
            } }>
            <CloseSharp sx={{ fontSize: "1.5rem" }}/>
          </CloseButton>
          <Stack direction="row" spacing={0.7} sx={{ flexWrap: "wrap", alignContent: "center" }}>
            <DisableSelectTypography
              component="h2"
              level="h4"
              textColor="inherit"
              fontWeight="lg"
              mb={1} 
              sx={{ display: "flex", textAlign: "center", flexWrap: "wrap", alignContent: "center", marginBottom: 0 }}>
                Send chat request to
            </DisableSelectTypography>
            <NewChatPopup
              key="0"
              escOnEnter
              initialChatWith={newChatWith}
              isPopupOpen={isPopupOpen}
              setIsPopupOpen={setIsPopupOpen}
              belowXL={belowXL} 
              placement="bottom"
              validate={validate} 
              returnUser={(chatWith) => {
                flushSync(() => setIsPopupOpen(false));
                textareaRef.current?.focus();
                if (chatWith) setNewChatWith(chatWith);
              }}>
              <Sheet sx={{ 
                marginBlock: "8px", 
                paddingBlock: "2px", 
                paddingInline: "6px", 
                border: "solid 0.8px black", 
                backgroundColor: "#d8d8df", 
                borderRadius: "12px", 
                textAlign: "center",
                ":hover" : {
                  filter: "brightness(0.9)" 
                },
                ...(isPopupOpen ? { filter: "brightness(0.9)" } : {}) }}>
                <DisableSelectTypography
                  component="h2"
                  level="h4"
                  textColor="inherit"
                  fontWeight="md"
                  sx={{ display: "flex", textAlign: "center", flexWrap: "wrap", alignContent: "center", marginBottom: 0, cursor: "default" }}
                  mb={1}>
                    {newChatWith}
                </DisableSelectTypography>
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
              ref={textareaRef}
              openKeyboardManual={false}
              autoFocus={true}
              tabbedOutside={clickedInside}
              placeholder="Type a message"
              outerProps={{ style: { marginTop: "12px" } }}
              onChange={ (e) => setNewMessage(e?.target?.value || "") }
              onSubmit={() => isMessageEmpty() || sendRequest()}
              onBlur={(e) => clickedInside.current && e.target.focus()}
              minRows={3}
              maxRows={5} 
              style={{ flex: 1 }}/>
              <IconButton 
                variant="outlined"
                color="success" 
                onClick={() => isMessageEmpty() || sendRequest()}
                sx={{ flexGrow: 0, flexBasis: "content", height: "fit-content", alignSelf: "center", borderRadius: 20, backgroundColor: "var(--joy-palette-success-plainHoverBg)" }}>
                <SendRounded sx={{ fontSize: "2rem"}}/>
              </IconButton>
          </Stack>
        </Sheet>      
      </Dialog>
      <Dialog 
        outsidePress={false}
        open={warn}>
        <Sheet
          variant="outlined"
          sx={{
            width: belowXL ? "70vw" : "25vw",
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
            Cancel message request?
          </DisableSelectTypography>
          <DisableSelectTypography id="modal-desc" textColor="text.tertiary" textAlign="center">
            You'll lose the message you're typing.
          </DisableSelectTypography>
          <Grid container direction="row" sx={{ paddingTop: "15px" }}>
            <DialogButton action="Go back" onClick={ () => setWarn(false) }/>
            <DialogButton action="Close" onClick={ () => {
              setWarn(false);
              setNewChatWith("");
              setNewMessage("");
            }}/>
          </Grid>
        </Sheet>      
      </Dialog>
    </>);
  }
  
  type QuitAction = "Go back" | "Close";
  
  function DialogButton({ action, onClick }: Pick<ButtonProps, "onClick"> & { action: QuitAction }) {
    const color = 
      match(action)
        .with("Go back", () => "success")
        .with("Close", () => "danger")
        .exhaustive() as any;
  
    return (
      <Grid xs={6} sx={{ display: "flex", justifyContent: "center", paddingInline: "20px" }}>
        <Button
          variant="solid"
          color={color}
          onClick={onClick}
          sx={{ flexGrow: 1 }}>
          {action}
        </Button>
      </Grid>)
    }