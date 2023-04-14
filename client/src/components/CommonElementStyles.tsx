import _ from "lodash";
import React from "react";
import { Sheet, Switch } from "@mui/joy";
import { styled as joyStyled } from "@mui/joy/styles";
import styled from "@emotion/styled";

export const StyledSheet = joyStyled(Sheet)(({ theme }) => ({
  ...theme.typography.body2,
  padding: theme.spacing(1),
  textAlign: 'center',
  color: theme.vars.palette.text.tertiary,
}));

export const StyledJoySwitch = styled(Switch)`
  input {
    top: 0px;
    left: 0px;
  }`;

export const StyledScrollbar = styled(StyledSheet)`
  flex: 1; 
  flex-basis: 0;
  max-height: 100%; 
  overflow-x: clip;
  overflow-y: scroll;
  scroll-behavior: smooth;
  overscroll-behavior: contain;
  scrollbar-width: thin;
  scrollbar-color: #afafaf #d1d1d1;

  ::-webkit-scrollbar {
    width: 6px;
  }

  ::-webkit-scrollbar-track {
    background-color: #d1d1d1;
    border-radius: 5px;
    border: 2px solid transparent;
    background-clip: padding-box;
    &:hover {
      border: none 0px;
    }
  }

  ::-webkit-scrollbar-thumb {
    background-color: #afafaf;
    border-radius: 5px;
    box-shadow: inset 0px 0px 5px rgba(0,0,0,0.7);
}`;

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
  display: grid;
  place-items: center;

  &:hover {
    color: #131318;
    background-color: rgb(216, 216, 223);#ebebef;
    border-color: #b9b9c6;
  }`;

export function Spacer({ units }: { units: number }) {
  return (
    <React.Fragment>
      { (new Array(units)).fill(null).map((v, i) => <div key={i}><span>&nbsp;</span></div>) }
    </React.Fragment>
  );
}