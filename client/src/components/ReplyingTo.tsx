import _ from "lodash";
import isEqual from "react-fast-compare";
import React, { ForwardedRef, forwardRef, memo, useMemo } from "react";
import { IconButton, Link, Sheet, Stack } from "@mui/joy";
import { ClearSharp } from "@mui/icons-material";
import remarkGfm from "remark-gfm";
import remarkMath from "remark-math";
import twemoji from "../custom_modules/remark-twemoji";
import rehypeRaw from "rehype-raw";
import rehypeKatex from "rehype-katex";
import "katex/dist/katex.min.css"
import { MessageCardContextData } from "./MessageCard";
import { DisableSelectTypography, StyledReactMarkdownVariable } from "./CommonElementStyles";
import { ReplyingToInfo } from "../../../shared/commonTypes";

const StyledReactMarkdownReply = StyledReactMarkdownVariable(18);

export type ReplyingToProps = ReplyingToInfo & Pick<MessageCardContextData, "chatWith" | "setHighlight"> & Readonly<{
  sentByMe: boolean;
  renderClose?: () => void;
}>

const ReplyingTo = forwardRef(function(replyingTo: ReplyingToProps, ref: ForwardedRef<HTMLDivElement>) {
  const { chatWith, id: replyId, sentByMe, displayText, replyToOwn, setHighlight, renderClose } = replyingTo;
  const repliedColor = sentByMe ? "#e8fae5" : "#f2f2f2";
  const repliedOutlineColor = replyToOwn ? "#53bdeb" : "#06cf9c";
  const repliedBorderColor = sentByMe ? "#bddcb8" : "#c7c7c7";
  const repliedBorder = `thin solid ${repliedBorderColor}`;
  const main = useMemo(() => (
    <Stack direction="column" justifyContent="flex-start" sx={{ display: "flex", textAlign: "left", padding: 1 }}>
      <DisableSelectTypography component="span" level="body3" fontWeight="bold" textColor={repliedOutlineColor}>
        {replyToOwn ? "You" : chatWith }
      </DisableSelectTypography>
      <DisableSelectTypography component="span" level="body3">
        <StyledReactMarkdownReply 
          className="react-markdown" 
          components={{ p: "span" }}
          children={displayText}
          remarkPlugins={[remarkGfm, remarkMath, twemoji]}
          rehypePlugins={[rehypeKatex, rehypeRaw]}/>
      </DisableSelectTypography>
    </Stack>), [repliedOutlineColor, replyToOwn, chatWith, displayText]);

  const stack = useMemo(() => (
    renderClose
      ? <Stack direction="row" sx={{ display: "flex", justifyContent: "space-between" }}>
          {main}
          <IconButton variant="plain" color="neutral" sx={{ minWidth: "52px",":hover": { backgroundColor: repliedColor, filter: "brightness(90%)" } }} onClick={(event) => {
            renderClose();
            event.stopPropagation();
            return false;
          }}>
            <ClearSharp sx={{ color: "#6e6e6e" }}/>
          </IconButton>
        </Stack>
      : main
    ), [main, renderClose])

  return (
      <Link component="div" underline="none" sx={{ width: "100%" }} onClick={(event) => {
          setHighlight(replyId);
          event.stopPropagation();
          return false;
        } }>
        <Stack ref={ref} direction="row" sx={{ width: "100%", paddingBottom: 0.5 }}>
          <Sheet sx={{ width: "4px", minWidth: "4px", backgroundColor: repliedOutlineColor, borderLeftColor: repliedOutlineColor, borderTopLeftRadius: "10px", borderBottomLeftRadius: "10px" }}/>
          <Sheet variant="soft" sx={{ flexGrow: 1, backgroundColor: repliedColor, padding: 0, borderTopRightRadius: "10px", borderBottomRightRadius: "10px", borderTop: "thin solid transparent", borderBottom: repliedBorder, borderRight: repliedBorder, boxShadow: `1px 0px 2px ${repliedBorderColor}`, "&:hover": { boxShadow: `1px 0px 7px ${repliedBorderColor}` } }}>
            {stack}
          </Sheet>
        </Stack>
      </Link>)
})

export const ReplyingToMemo = memo(ReplyingTo, (prev, next) => isEqual(prev, next));