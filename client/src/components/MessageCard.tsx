import _ from "lodash";
import  { match } from "ts-pattern";
import React, { createContext, useContext, useLayoutEffect, useRef, useState } from "react";
import { useUpdateEffect } from "usehooks-ts";
import { Grid, Link, Sheet, Stack, Tooltip, Typography } from "@mui/joy";
import { DoneSharp, DoneAllSharp, HourglassTop } from "@mui/icons-material";
import { Item } from "./Common";
import ReactMarkdown from "../node_modules/react-markdown";
import remarkGfm from "../node_modules/remark-gfm";
import { DateTime } from "../node_modules/luxon";
import styled from "@emotion/styled";
import { ReactMarkdownOptions } from "react-markdown/lib/react-markdown";
import SvgMessageCard from "./SvgMessageCard";

interface HTMLDivElementScroll extends HTMLDivElement {
  scrollIntoViewIfNeeded(centerIfNeeded?: boolean): void;
}

const StyledReactMarkdown = styled(ReactMarkdown as unknown as React.ComponentClass<ReactMarkdownOptions, {}>)`
  & > p:last-child {
    padding-bottom: 0px;
    margin-bottom: 0px;
  }
`
export type FocusData = {
  readonly currentFocus: string;
  readonly clearFocus: () => void;
}

export const FocusContext = createContext<FocusData>(null);

export type ViewMessage = {
  readonly id: string;
  readonly content: string;
  readonly timestamp: number;
  readonly replyingTo?: { click: () => void, sender: string, text: string };
  readonly status: "read" | "delivered" | "sent" | "pending";
  readonly first: boolean;
}

export default function MessageCard({ message }: { message: ViewMessage}) {
  const { currentFocus, clearFocus } = useContext(FocusContext);
  const { id, content, timestamp, replyingTo, status, first } = message;
  const [hasMeasured, setHasMeasured] = useState(false);
  const [darken, setDarken] = useState(false);
  const sheetRef = useRef<HTMLDivElementScroll>(null);
  useLayoutEffect(() => setHasMeasured(true), []);
  useUpdateEffect(() => {
    if (currentFocus === id) { 
      sheetRef.current.scrollIntoViewIfNeeded();
      setDarken(true);
      clearFocus();
    } 
  }, [currentFocus]);
  const sentByMe = status !== null;
  const statusIcon = 
    status !== null ? match(status)
                        .with("pending", () => <HourglassTop sx={{ color: "gold", rotate: "-90deg", fontSize: "1rem" }}/>)
                        .with("sent", () => <DoneSharp sx={{ color: "gray", fontSize: "1rem" }}/>)
                        .with("delivered", () => <DoneAllSharp sx={{ color: "gray", fontSize: "1rem" }}/>)
                        .with("read", () => <DoneAllSharp sx={{ color: "blue", fontSize: "1rem" }}/>)
                        .exhaustive() : null;
  const repliedMessage = 
    replyingTo !== null ? (() => {
      const { click, sender, text } = replyingTo
      const repliedColor = sentByMe ? "#e8fae5" : "#f2f2f2";
      const repliedOutlineColor = sender === null ? "#53bdeb" : "#06cf9c";
      const repliedBorderColor = sentByMe ? "#bddcb8" : "#c7c7c7";
      const repliedBorder = `thin solid ${repliedBorderColor}`;
      return (
          <Link component="button" underline="none" onClick={click}>
            <Stack direction="row" sx={{ width: "100%", paddingBottom: 0.5 }}>
              <Sheet sx={{ width: "7px", backgroundColor: repliedOutlineColor, borderLeftColor: repliedOutlineColor, borderTopLeftRadius: "10px", borderBottomLeftRadius: "10px" }}/>
              <Sheet variant="soft" sx={{ flexGrow: 1, backgroundColor: repliedColor, padding: 1, borderTopRightRadius: "10px", borderBottomRightRadius: "10px", borderTop: "thin solid transparent", borderBottom: repliedBorder, borderRight: repliedBorder, boxShadow: `1px 0px 2px ${repliedBorderColor}`, "&:hover": { boxShadow: `1px 0px 7px ${repliedBorderColor}` } }}>
                <Stack direction="column" justifyContent="flex-start" sx={{ display: "flex", textAlign: "left" }}>
                  <Typography component="span" level="body3" fontWeight="bold" textColor={repliedOutlineColor} sx={{ filter: "blur(4px)" }}>
                    {sender ?? "You"}
                  </Typography>
                  <Typography component="span" level="body3" sx={{ filter: "blur(4px)" }}>
                    <ReactMarkdown components={{ p: "span" }}  children={text} remarkPlugins={[remarkGfm]}/>
                  </Typography>
                </Stack>
              </Sheet>
            </Stack>
          </Link>)
    })() : null;
  const side = sentByMe ? "flex-end" : "flex-start";
  const direction = sentByMe ? "right" : "left";
  const messageColor = sentByMe ? "#d7fad1" : "white";
  return (
    <Grid container sx={{ display: "flex", flexGrow: 1, justifyContent: side, height: "fit-content", maxWidth: "100%" }}>
      <Grid xs={10} sm={8} lg={7} sx={{ display: "flex", flexGrow: 0, justifyContent: side, height: "fit-content" }}>
        <Item sx={{ width: "100%", display: "flex", flexGrow: 1, justifyContent: side, alignContent: "flex-start", padding: 0, margin: 0 }} ref={sheetRef} style={{ }}>
          {hasMeasured
            ? (
              <SvgMessageCard background={messageColor} first={first} direction={direction} shadowColor="#adb5bd" darken={darken} darkenFinished={() => setDarken(false) }>
                <Stack direction="column"
                sx={{ maxWidth: "max-content", width: "fit-content", padding: 1.5, paddingBottom: 0.5, alignContent: "flex-start", textAlign: "start" }}>
                  {repliedMessage && repliedMessage}
                  <Typography component="span" sx={{ width: "fit-content", maxWidth: "max-content", filter: "blur(4px)" }}>
                    <StyledReactMarkdown className="react-markdown" children={content} remarkPlugins={[remarkGfm]}/>
                  </Typography>
                  <Tooltip 
                    title={DateTime.fromMillis(timestamp).toFormat("d LLLL, h:mm a")} 
                    placement="right-start" 
                    size="sm"
                    variant="outlined"
                    sx={{ backgroundColor: "#f8f7f5", borderColor: "rgba(237, 237, 237, 0.7)", boxShadow: "0px 0.5px 2px #e4e4e4" }}>
                    <Stack direction="row" spacing={1} sx={{ justifyContent: "end" }}>
                      <Typography level="body3">
                        {DateTime.fromMillis(timestamp).toLocaleString(DateTime.TIME_SIMPLE)}
                      </Typography>
                      {statusIcon}
                    </Stack>
                  </Tooltip>
                </Stack>
              </SvgMessageCard>)
            : <div/> }
        </Item>        
      </Grid>
    </Grid>
  )
}