import React from "react";
import { Box } from "@mui/joy";
import { SxProps } from "@mui/material";

type FlexBoxProps = Readonly<{
  direction?: "row" | "column";
  sx?: SxProps;
  children?: React.ReactNode; 
}>;

export function FlexBox({ direction: flexDirection = "row", sx, children }: FlexBoxProps) {
  return (
    <Box sx={{ display: "flex", flexDirection, flexWrap: "wrap", ...sx }}>
      {children}
    </Box>
  );
}