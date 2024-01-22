import React, { useState, useEffect, useRef, createContext, useContext } from "react";
import { Grid, IconButton, Button, Sheet, Stack, Avatar, Input, CircularProgress, Box, Theme, ButtonProps, Tabs, TabList, Tab, TabPanel } from "@mui/joy";
import { ArrowBackSharp, Cached, ClearOutlined, CloseSharp, DoneOutlined, EditOutlined } from "@mui/icons-material";
import Popover, { PopoverTrigger, PopoverContent } from "./Popover";
import Dialog from "./Dialog";
import { CloseButton, DisableSelectTypography } from "./CommonElementStyles";
import { Profile } from "../../../shared/commonTypes";
import { match } from "ts-pattern";
import { ButtonBaseProps, useMediaQuery } from "@mui/material";
import { FlexBox } from "./FlexBox";
import { noProfilePictureImage, generateAvatar, extractInitials, randomAvatarParams } from "../imageUtilities";

type CurrentPictureContextType = Readonly<{
  currentInitials: string;
  currentPicture: string;
}>;

const CurrentPictureContext = createContext<CurrentPictureContextType>(null);

type ChangePictureContextType = Readonly<{
  picture: string;
  setPicture: (picture: string) => void;
  submit: () => void;
}>;

const ChangePictureContext = createContext<ChangePictureContextType>(null);

type ProfilePopupProps = Readonly<{
  profile: Profile;
  changeProfile: (profile: Partial<Omit<Profile, "username">>) => Promise<boolean>;
  isPopupOpen: boolean;
  setIsPopupOpen: (open: boolean) => void;
  children: JSX.Element;
  width: number;
}>;


export function ProfilePopup({ profile, changeProfile, width, isPopupOpen, setIsPopupOpen, children }: ProfilePopupProps) {
  const { username, displayName, description, profilePicture } = profile || {};
  const [isMenuVisible, setIsMenuVisible] = useState(false);
  
  return (
    <Popover modal={true}
      placement="top-start"
      ancestorScrollDismiss={false}
      dismissBubbles={{ outsidePress: false, escapeKey: false }}
      customOffset={{ mainAxis: -50, crossAxis: -25 }}
      controlledOpen={isPopupOpen}
      setControlledOpen={(open) => {
        if (!open && isMenuVisible) {
          setIsMenuVisible(false);
        }
        else setIsPopupOpen(open);
      }}>
      <PopoverTrigger>
        {children}
      </PopoverTrigger>
      <PopoverContent>
        <div style={{ padding: 10, borderRadius: "3px", border: "1.5px solid #d8d8df", backgroundColor: "#f0f2f5", boxShadow: "-1px 1px 4px 1px #eeeeee", width: width - 5 }}>
          <Stack direction="column" spacing={2} sx={{}}>
            <Stack direction="row" spacing={2}>
              <IconButton variant="outlined" color="neutral" onClick={() => setIsPopupOpen(false)}>
                <ArrowBackSharp sx={{ fontSize: "1.5rem" }}/>
              </IconButton>
              <DisableSelectTypography level="h4" fontWeight="lg" fontSize="1.5rem">
                Profile
              </DisableSelectTypography>
            </Stack>
            <div style={{ display: "flex", flexDirection: "column", flexWrap: "wrap", alignContent: "center" }}>
              <CurrentPictureContext.Provider 
                value={{
                  currentInitials: extractInitials(displayName, username),
                  currentPicture: profilePicture
                }}>
                <ProfilePicture 
                  isMenuVisible={isMenuVisible} 
                  setIsMenuVisible={setIsMenuVisible}
                  changePicture ={async (value) => await changeProfile({ profilePicture: value })}/>
                <DisableSelectTypography textColor="text.tertiary" textAlign="center" fontSize="1rem" fontStyle="italic">
                  @{username}
                </DisableSelectTypography>
              </CurrentPictureContext.Provider>
            </div>
            <EditDetail 
              title="Display Name" 
              currentValue={displayName} 
              changeValue={async (value) => await changeProfile({ displayName: value })}/>
            <EditDetail 
              title="Description" 
              currentValue={description} 
              changeValue={async (value) => await changeProfile({ description: value })}/>
          </Stack>
        </div>
      </PopoverContent>
    </Popover>)
}
type EditState = "Editing" | "Saving" | "Display";

type EditDetailProps = Readonly<{
  title: "Display Name" | "Description";
  currentValue: string;
  changeValue: (value: string) => Promise<boolean>;
}>;

function EditDetail({ title, currentValue, changeValue }: EditDetailProps) {
  const [editState, setEditState] = useState<EditState>("Display");
  const [value, setValue] = useState(currentValue);

  async function submit() {
    setEditState("Saving");
    await changeValue(value);
    setEditState("Display");
  }

  function cancel() {
    setEditState("Display");
    setValue(currentValue);
  }

  return (
    <Stack direction="column" spacing={0.2} style={{ backgroundColor: "white", padding: "4px", borderRadius: "1px" }}>
      <DisableSelectTypography level="h4" fontWeight="lg" fontSize="0.8rem">
        {title}
      </DisableSelectTypography>
      <div style={{ display: "flex", flexWrap: "wrap", flexDirection: "row", justifyContent: "space-between", alignContent: "center", marginLeft: "5px" }}>
        {editState === "Display"
          ? (<>
              <DisableSelectTypography textColor="text.tertiary" fontSize="0.9rem" style={{ marginBlock: "auto", marginLeft: "8px" }}>
                {currentValue}
              </DisableSelectTypography>
              <IconButton variant="plain" color="neutral" size="sm" onClick={() => setEditState("Editing")}>
                <EditOutlined color="disabled" sx={{ fontSize: "1.1rem", marginRight: "3px" }}/>
              </IconButton>
            </>)
          : (<Input 
              size="sm"
              variant="plain" 
              color="neutral"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              onKeyDown={(e) => { 
                const keyState = 
                  match(e.key)
                    .with("Enter", () => 1)
                    .with("Escape", () => -1)
                    .otherwise(() => 0);
                  if (keyState) {
                    e.stopPropagation();
                    keyState === 1 ? submit() : cancel();
                  }
              }}
              autoFocus={true}
              sx={{ width: "100%",
                    color: "text.tertiary",
                    borderRadius: 0,
                    fontSize: "0.9rem",
                    paddingRight: "0px",
                    "&:hover": { 
                      color: "text.tertiary"
                    },
                    "&:focus-within::before": { 
                      boxShadow: "none",
                      borderBottom: "2px solid #667781" } }}
              endDecorator={
                editState === "Editing"
                ? (<Stack direction="row" spacing={1}>
                    <IconButton 
                      variant="plain" 
                      color="neutral" 
                      size="sm" 
                      onClick={cancel}>
                      <ClearOutlined color="disabled" sx={{ fontSize: "1.1rem" }}/>
                    </IconButton>
                    <IconButton 
                      variant="plain" 
                      color="neutral" 
                      size="sm" 
                      onClick={submit}>
                      <DoneOutlined color="disabled" sx={{ fontSize: "1.1rem" }}/>
                    </IconButton>
                  </Stack>)
                : (<CircularProgress size="sm" variant="plain" color="neutral"/>)}/>)
        }
      </div>
    </Stack>);
}

type ProfilePictureProps = Readonly<{
  isMenuVisible: boolean;
  setIsMenuVisible: (value: boolean) => void;
  changePicture: (value: string) => Promise<boolean>;
}>;

function ProfilePicture({ isMenuVisible, setIsMenuVisible, changePicture }: ProfilePictureProps) {
  const { currentPicture } = useContext(CurrentPictureContext);
  const [editState, setEditState] = useState<EditState>("Display");
  const [picture, setPicture] = useState(currentPicture);
  const [generatingType, setGeneratingType] = useState<ChangePictureType>("None");
  const menuPosition = useRef({ x: 0, y: 0 });
  const darkenFilter = "saturate(0.9) brightness(0.5) contrast(0.8)";

  async function submit() {
    setEditState("Saving");
    await changePicture(picture);
    setEditState("Display");
  }

  function cancel() {
    setEditState("Display");
    setPicture(currentPicture);
  }

  function openGeneratingType(type: ChangePictureType) {
    setIsMenuVisible(false);
    setGeneratingType(type);
  }

  const highlightOff = {
        "--highlight-display": "none",
        "--highlight-image-filter": "none"
      };

  const highlightOn = {
        "--highlight-display": "block",
        "--highlight-image-filter": darkenFilter
      };

  const highlightIf = (cond: boolean) => cond ? highlightOn : highlightOff;

  const buttonSx = { 
    color: "white", 
    marginBlock: "auto", 
    fontSize: "1.8rem"
  };

  const buttonBoxSx = { 
    position: "relative",
    zIndex: 2,
    display: "flex",
    justifyContent: "center",
    flex: 1, 
    paddingBottom: "10px",
    "&:hover": {
      filter: "brightness(0.6)"
    }
  }

  const centerOverlaySx = { 
    color: "white",
    display: "var(--highlight-display)",
    fontSize: "1rem",
    position: "absolute", 
    top: "50px",
    left: "50px",
    height: "50px",
    width: "50px",
    zIndex: 1};

  const circularSx = {
    "--CircularProgress-size": "50px",
    "--CircularProgress-trackThickness": "5px",
    "--CircularProgress-progressThickness": "4px",
    "--CircularProgress-progressColor": "white"
  };

  const editingOverlay = (
    <Box
      sx={{ 
        display: "flex",
        flexDirection: "row",
        justifyContent: "center",
        fontSize: "1rem",
        position: "absolute",
        bottom: "0px",
        left: "0px",
        height: "50px",
        width: "100%",
        clipPath: "circle(75px at 50% -25px)",
        backdropFilter: darkenFilter,
        zIndex: 1
      }}>
      <Box
        sx={{ ...buttonBoxSx, paddingLeft: "35px" }}
        onClickCapture={(e) => {
          e.stopPropagation();
          cancel();
          }}>
        <ClearOutlined sx={buttonSx}/>
      </Box>
      <Box
        sx={{ ...buttonBoxSx, paddingRight: "35px" }}
        onClickCapture={(e) => {
          e.stopPropagation();
          submit();
          }}>
        <DoneOutlined sx={buttonSx}/>
      </Box>
    </Box>);

  const pictureOverlay = (
    editState === "Editing"
        ? (editingOverlay)
        : (editState === "Display" 
            ? (<EditOutlined sx={centerOverlaySx}/>)
            : (<CircularProgress 
                size="md" 
                variant="plain" 
                color="neutral" 
                sx={{ 
                  ...centerOverlaySx,
                  ...circularSx,
                  display: "block" }}/>)))

  const mainDisplay = (
    <Box
      sx={{
        isolation: "isolate",
        position: "relative",
        width: "fit-content",
        height: "fit-content", 
        marginBottom: "8px",
        padding: 0,
        borderRadius: "100%",
        ...highlightIf(isMenuVisible || editState === "Saving" || generatingType !== "None"),
        "&:hover": 
          highlightIf(editState !== "Editing")
        }}
      onClickCapture={(e) => {
        if (editState !== "Display") return;
        const { top, left } = e.currentTarget.getBoundingClientRect();
        menuPosition.current = { x: e.clientX - left, y: e.clientY - top };
      }}>
      <Avatar 
        src={picture} 
        size="lg" 
        sx={{ 
          width: "150px", 
          height: "150px", 
          zIndex: -1,
          filter: "var(--highlight-image-filter)" }}/>
      {pictureOverlay}
    </Box>);

  const menu = (
    <Stack
      direction="column" 
      spacing={0}
      style={{ 
        width: "fit-content", 
        height: "fit-content", 
        paddingBlock: "10px",
        paddingInline: "0px",
        backgroundColor: "white", 
        borderRadius: "4px",
        boxShadow: "0px 0px 5px 2px #babdbe" }}>
      <OptionButton onClick={() => openGeneratingType("TakingPhoto")}>
        Take photo
      </OptionButton>
      <OptionButton onClick={() => openGeneratingType("UploadingPicture")}>
        Upload photo
      </OptionButton>
      <OptionButton onClick={() => openGeneratingType("GeneratingAvatar")}>
        Generate avatar
      </OptionButton>
      <OptionButton onClick={() => {
        setIsMenuVisible(false);
        setPicture(noProfilePictureImage);
        setEditState("Editing");
      }}>
        Remove picture
      </OptionButton>
    </Stack>);

  return (
    <>
      <Popover
        modal={true}
        allowFlip={false}
        ancestorScrollDismiss={false}
        dismissBubbles={{ outsidePress: false, escapeKey: false }}
        placement="bottom-start"
        customOffset={({ rects: { reference } }) => ({
            mainAxis: (menuPosition.current.y || 0) - reference.height + 10,
            crossAxis: (menuPosition.current.x || 0) + 10
          })}
        controlledOpen={isMenuVisible}
        setControlledOpen={(open) => setIsMenuVisible(open)}>
        <PopoverTrigger>
          {mainDisplay}
        </PopoverTrigger>
        <PopoverContent>
          {menu}
        </PopoverContent>
      </Popover>
      <ChangePictureDialog
        type={generatingType} 
        setType={setGeneratingType} 
        returnPicture={(picture) => {
          if (picture && picture !== currentPicture) {
            setPicture(picture);
            setEditState("Editing");
          }
          setGeneratingType("None");
        }}/>
      </>);
}

type ChangePictureType = "GeneratingAvatar" | "TakingPhoto" | "UploadingPicture" | "None";

type ChangePictureDialogProps = Readonly<{
  type: ChangePictureType;
  setType: (type: ChangePictureType) => void;
  returnPicture: (picture: string) => void;
}>;

function ChangePictureDialog({ type, setType, returnPicture }: ChangePictureDialogProps) {
  const { currentPicture } = useContext(CurrentPictureContext);
  const [keyboardHeight, setKeyboardHeight] = useState((navigator as any).virtualKeyboard.boundingRect.height);
  const [warn, setWarn] = useState(false);
  const [picture, setPicture] = useState(currentPicture);
  const belowXL = useMediaQuery((theme: Theme) => theme.breakpoints.down("xl"));

  useEffect(() => {
    const updateHeight = () => setKeyboardHeight((navigator as any).virtualKeyboard.boundingRect.height);
    window.visualViewport.addEventListener("resize", updateHeight);
    return () => {
      window.visualViewport.removeEventListener("resize", updateHeight);
    }
  }, []);

  const dismiss = () => { 
    if (type !== "None") {
      if (picture) setWarn(true);
      else setType("None");
    }
  };

  const dismissWarn = (picture: string = null) => {
    setWarn(false);
    if (picture !== null) returnPicture(picture);
  } 

  return (
    <>
      <Dialog 
        outsidePress
        overlayBackdrop="opacity(100%) blur(4px)"
        open={type !== "None"}
        onDismiss={dismiss}>
        <Sheet
          variant="outlined"
          sx={{
            maxWidth: belowXL ? "90vw" : "50vw",
            width: "fit-content",
            borderRadius: "md",
            position: "relative",
            zIndex: 10,
            bottom: keyboardHeight ? "100px" : 0,
            p: 3,
            backgroundColor: "rgba(246, 246, 246, 0.8)",
            boxShadow: "lg", 
            backdropFilter: "blur(4px)"}}>
          <FlexBox 
            direction="row" 
            sx={{ 
              justifyContent: "space-between", 
              alignItems: "center",
              paddingInline: "8px",
              marginBottom: "8px" }}>
            <DisableSelectTypography
              component="h2"
              level="h4"
              textColor="inherit"
              fontWeight="lg"
              mb={1} 
              sx={{ display: "flex", textAlign: "center", flexWrap: "wrap", alignContent: "center", marginBottom: 0 }}>
                Generate profile picture
            </DisableSelectTypography>
            <IconButton variant="outlined" color="neutral" onClick={dismiss}>
                <CloseSharp sx={{ fontSize: "1.5rem" }}/>
              </IconButton>
          </FlexBox>
          <Tabs
            orientation="horizontal"
            value={type}
            onChange={(_, value: Exclude<ChangePictureType, "None">) => setType(value)}>
            <TabList
              color="success"
              disableUnderline 
              variant="soft" 
              tabFlex={0.5} 
              sx={{ borderRadius: "sm", padding: "3px", gap: 0.5 }}>
              <ChangePictureTab
                type={"TakingPhoto"}
                currentType={type}/>
              <ChangePictureTab
                type={"UploadingPicture"}
                currentType={type}/>
              <ChangePictureTab
                type={"GeneratingAvatar"}
                currentType={type}/>
            </TabList>
            <ChangePictureContext.Provider 
              value={{ 
                picture, 
                setPicture, 
                submit: () => returnPicture(picture) 
              }}>
              <ChangePicturePanel type="TakingPhoto"/>
              <ChangePicturePanel type="UploadingPicture"/>
              <ChangePicturePanel type="GeneratingAvatar"/>
            </ChangePictureContext.Provider>
          </Tabs>
        </Sheet>      
      </Dialog>
      <Dialog 
        outsidePress={false}
        open={warn}>
        <Sheet
          variant="outlined"
          sx={{
            width: belowXL ? "90vw" : "25vw",
            zIndex: 12,
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
            Cancel generating profile picture?
          </DisableSelectTypography>
          <Grid container direction="row" sx={{ paddingTop: "15px" }}>
            <DialogButton action="Keep changes" onClick={() => dismissWarn(picture)}/>
            <DialogButton action="Discard changes" onClick={() => dismissWarn("")}/>
            <DialogButton action="Stay" onClick={ () => dismissWarn() }/>
          </Grid>
        </Sheet>      
      </Dialog>
    </>);
}

type ChangePictureTabProps = Readonly<{
  currentType: ChangePictureType;
  type: ChangePictureType;
}>;

function ChangePictureTab({ currentType, type }: ChangePictureTabProps) {
  const belowXL = useMediaQuery((theme: Theme) => theme.breakpoints.down("xl"));
  const title = 
    match(type)
      .with("GeneratingAvatar", () => "Generating Avatar")
      .with("UploadingPicture", () => "Uploading Picture")
      .with("TakingPhoto", () => "Taking Photo")
      .otherwise(() => null);
  
  const isCurrent = type === currentType;

  return (
    <Tab
      value={type}
      disableIndicator
      variant={isCurrent ? "solid" : "plain"}
      sx={{ 
        borderRadius: "sm",
        whiteSpace: belowXL ? "normal" : "nowrap",
        paddingInline: belowXL ? "10px" : "25px",
        textAlign: "center",
        textJustify: "center",
        ...(isCurrent
              ? { backgroundColor: "#1f7a1f !important" } 
              : { "&:hover": { backgroundColor: "#f1fdf1 !important" } })
      }}>
        {title}
    </Tab>);
}

function ChangePicturePanel({ type }: Pick<ChangePictureTabProps, "type">) {
  const belowXL = useMediaQuery((theme: Theme) => theme.breakpoints.down("xl"));
  const { submit } = useContext(ChangePictureContext);

  const panel = 
    match(type)
      .with("GeneratingAvatar", () => <GenerateAvatar/>)
      .with("UploadingPicture", () => <div style={{ height: "200px" }}/>)
      .with("TakingPhoto", () => <div style={{ height: "200px" }}/>)
      .otherwise(() => null)
  return ( 
    <TabPanel value={type} sx={{ backgroundColor: "var(--Sheet-background)" }}>
      <FlexBox 
        direction={belowXL ? "column" : "row" } 
        sx={{ 
          justifyContent: "space-between", 
          alignItems: "center",
          paddingInline: "25px",
          gap: "25px" }}>
        {panel}
        <Button
          variant="solid"
          color="success"
          onClick={submit}>
          Done
        </Button>
      </FlexBox>
    </TabPanel>  
  );
}

function GenerateAvatar() {
  const belowXL = useMediaQuery((theme: Theme) => theme.breakpoints.down("xl"));
  const { picture, setPicture } = useContext(ChangePictureContext);
  const { currentInitials } = useContext(CurrentPictureContext);
  const [initials, setInitials] = useState(currentInitials);
  const [params, setParams] = useState(randomAvatarParams());

  useEffect(() => setPicture(generateAvatar({ initials, ...params })), [initials, params]);

  return (
    <FlexBox 
      direction={belowXL? "column" : "row"} 
      sx={{ justifyContent: "center", alignItems: "center", gap: "25px" }}>
      <Avatar 
        src={picture} 
        size="lg" 
        sx={{ 
          width: "200px", 
          height: "200px" }}/>
      <IconButton 
        variant="solid"
        color="success"
        onClick={() => setParams(randomAvatarParams())}>
          <Cached sx={{ fontSize: "3rem" }}/>
      </IconButton>
    </FlexBox>
  )
}

function OptionButton({ children, onClick }: ButtonBaseProps) {
  return (
    <Button
      variant="plain"
      color="neutral"
      onClick={onClick}
      style={{ paddingInline: "15px", paddingBlock: "2px", justifyContent: "flex-start" }}>
      <DisableSelectTypography level="body-sm" fontWeight="400" fontSize="1rem" textAlign="start">
        {children}
      </DisableSelectTypography>
    </Button>
  );
}

type QuitAction = "Keep changes" | "Discard changes" | "Stay";

function DialogButton({ action, onClick }: Pick<ButtonProps, "onClick"> & { action: QuitAction }) {
  const color = 
    match(action)
      .with("Discard changes", () => "danger")
      .with("Keep changes", () => "success")
      .with("Stay", () => "primary")
      .exhaustive() as any;

  return (
    <Grid xs={4} sx={{ display: "flex", justifyContent: "center", paddingInline: "20px" }}>
      <Button
        variant="solid"
        color={color}
        onClick={onClick}
        sx={{ flexGrow: 1 }}>
        {action}
      </Button>
    </Grid>)
  }