import _ from "lodash";
import React from "react";
import { Sheet, Typography } from "@mui/joy";
import styled from "@emotion/styled";
import { Theme, useMediaQuery } from "@mui/material";
import { Dialog, DialogContent } from "./Dialog";
import { CloseSharp } from "@mui/icons-material";

export const CloseButton = styled.button`
  all: unset;
  position: absolute;
  top: -12px;
  right: -12px;
  width: 26px;
  height: 34px;
  padding-inline: 4px;
  padding-block: 0px;
  box-shadow: 0px 2px 12px 0px rgba(0, 0, 0, 0.2);
  border: 0.8px solid rgb(185, 185, 198);
  border-radius: 50%;
  background-color: #ebebef;

  &:hover {
    color: #131318;
    background-color: rgb(216, 216, 223);#ebebef;
    border-color: #b9b9c6;
  }`;

export default function WarnSavePassword({ open, setWarned }: WarnSavePasswordProps) {  
  const belowXL = useMediaQuery((theme: Theme) => theme.breakpoints.down("xl"));

  return (
    <Dialog 
      outsidePress
      overlayBackdrop="opacity(100%) blur(4px)"
      controlledOpen={open} 
      setControlledOpen={(open) => { 
        if (!open) {
          setWarned(true);
        }
      }}>
      <DialogContent>
        <Sheet
          variant="outlined"
          sx={{
            width: belowXL ? "90vw" : "40vw",
            borderRadius: "md",
            p: 3,
            boxShadow: "lg"}}>
          <CloseButton style={{ display: "grid", placeItems: "center" }} 
            onClick={ () => setWarned(true) }>
            <CloseSharp sx={{ fontSize: "1.5rem" }}/>
          </CloseButton>
          <Typography
            component="h2"
            id="modal-title"
            level="h4"
            textColor="inherit"
            fontWeight="lg"
            mb={1}>
              Save password?
          </Typography>
          <Typography id="modal-desc" textColor="text.tertiary">
            The browser will save your password so you won't have to re-enter it on future visits. However, this compromises the security of your account. Anyone with access to your browser may be able to extract the password from its cookies. You may disable password saving later from your settings.
          </Typography>
        </Sheet>      
      </DialogContent>
    </Dialog>);
}

export type WarnSavePasswordProps = {
  open: boolean,
  setWarned: (warned: boolean) => void
}