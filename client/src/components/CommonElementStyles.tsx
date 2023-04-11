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
  scroll-behavior: auto !important;
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

export function Spacer({ units }: { units: number }) {
  return (
    <React.Fragment>
      { (new Array(units)).fill(null).map((v, i) => <div key={i}><span>&nbsp;</span></div>) }
    </React.Fragment>
  );
}