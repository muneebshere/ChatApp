import React, { useState, useEffect } from "react";
import { Grid, IconButton, Button, Sheet, Stack } from "@mui/joy";
import { CloseSharp, SendRounded } from "@mui/icons-material";
import { Popover, PopoverTrigger, PopoverContent } from "./Popover";
import { Dialog, DialogContent } from "./Dialog";
import { CloseButton, DisableSelectTypography } from "./CommonElementStyles";
import ControlledTextField from "./ControlledTextField";
import { StyledScrollingTextarea } from "./TextareaAutosize";
import { Placement } from "@floating-ui/react";

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
      changeOpenTo={isPopupOpen}
      notifyChange={(open) => {
        setNewChatWith("");
        setIsPopupOpen(open);
      }}>
      <PopoverTrigger>
        {children}
      </PopoverTrigger>
      <PopoverContent>
        <div style={{ borderRadius: 8, padding: 10, border: "1.5px solid #d8d8df", backgroundColor: "rgba(246, 246, 246, 0.8)", boxShadow: "0px 1px 3px 1.5px #eeeeee", backdropFilter: "blur(4px)", width: belowXL ? "80vw" : "20vw" }}>
          <Stack direction="column" spacing={1}>
            <DisableSelectTypography level="h6" fontWeight="lg">
              New chat
            </DisableSelectTypography>
            <div style={{ display: "flex", alignContent: "center", justifyContent: "stretch" }}>
              <ControlledTextField
                autoFocus
                autoComplete="new-random"
                role="presentation"
                variant="outlined"
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
                      setNewChatWith("");
                      setIsPopupOpen(false);
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
        controlledOpen={!!newChatWith} 
        setControlledOpen={(open) => { 
          if (!open) {
            if (isPopupOpen) {
              setIsPopupOpen(false);
            }
            else if (isMessageEmpty()) {
              setNewChatWith("");
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
              position: "relative",
              bottom: keyboardHeight ? "100px" : 0,
              p: 3,
              backgroundColor: "rgba(246, 246, 246, 0.8)",
              boxShadow: "lg", 
              backdropFilter: "blur(4px)"}}>
            <CloseButton onClick={ () => setWarn(true) }>
              <CloseSharp sx={{ fontSize: "1.5rem" }}/>
            </CloseButton>
            <Stack direction="row" spacing={0.7} sx={{ flexWrap: "wrap", alignContent: "center" }}>
              <DisableSelectTypography
                component="h2"
                level="h6"
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
                  setIsPopupOpen(false);
                  setNewChatWith(chatWith);
                }}>
                <Sheet sx={{ marginBlock: "8px", paddingBlock: "2px", paddingInline: "6px", border: "solid 0.8px black", backgroundColor: "#d8d8df", borderRadius: "12px", textAlign: "center", ":hover" : {
                  filter: "brightness(0.9)"
                } }}>
                  <DisableSelectTypography
                    component="h2"
                    level="h6"
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
                placeholder="Type a message"
                outerProps={{ style: { marginTop: "12px" } }}
                onChange={ (e) => setNewMessage(e.target.value) }
                onSubmit={() => sendRequest()}
                minRows={3}
                maxRows={5} 
                style={{ flex: 1 }}/>
                <IconButton 
                  variant="outlined"
                  color="success" 
                  onClick={() => sendRequest()}
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
              <Grid xs={6} sx={{ display: "flex", justifyContent: "center", paddingInline: "20px" }}>
                <Button variant="solid" color="success" sx={{ flexGrow: 1 }} onClick={ () => setWarn(false) }>
                  Go back
                </Button>
              </Grid>
              <Grid xs={6} sx={{ display: "flex", justifyContent: "center", paddingInline: "20px" }}>
                <Button variant="solid" color="danger" sx={{ flexGrow: 1 }} onClick={ () => {
                  setWarn(false);
                  setNewChatWith("");
                  setNewMessage("");
                } }>
                  Close
                </Button>
              </Grid>
            </Grid>
          </Sheet>      
        </DialogContent>
      </Dialog>
    </>);
}