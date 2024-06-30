import _ from "lodash";
import React, { useRef } from "react";
import { useUpdateEffect } from "usehooks-ts";
import styled from "@emotion/styled";

export type SvgMessageProps = {
  darken: boolean,
  darkenFinished: () => void,
  first: boolean,
  sentByMe: boolean,
  children: JSX.Element,
  background: string,
  shadowColor: string
}

export default function SvgMessageCard(props: SvgMessageProps) {
  const { children, sentByMe, background, shadowColor, first, darken, darkenFinished } = props;
  const darkenNode = useRef<HTMLDivElement>(null);
  const shadowString = `drop-shadow(0px 0px 3px ${shadowColor})`;

  const direction = sentByMe ? "right" : "left";

  useUpdateEffect(() => {
    if (darken) {
      const element = darkenNode.current;
      if (element) {
        const animation = element.getAnimations().find((a) => a.id === "darkenAnimation");
        if (animation) {
          animation.onfinish = () => darkenFinished();
          animation.play();
        }
        else {
          element.animate([
              { filter: `${shadowString} brightness(100%)`, offset: 0 },
              { filter: `${shadowString} brightness(50%)`, offset: 0.5 },
              { filter: `${shadowString} brightness(100%)`, offset: 1 }
            ], { duration: 1000, easing: "ease-out", id: "darkenAnimation" }).onfinish = () => darkenFinished();
        }
      };
    }
  }, [darken]);

  const pointWidth = 15;
  const pointHeight = 10;
  const polygon = sentByMe ? "polygon(100% 0%, 0% 100%, 0% 0%)" : "polygon(0 0, 100% 0%, 100% 100%)";

  const PointBefore =
    first
      ? styled.div`
      :before {
        content: "";
        display: block;
        position: absolute;
        top: 0px;
        ${direction}: 0px;
        width: ${pointWidth + 1}px;
        height: ${pointHeight}px;
        background: ${background};
        clip-path: ${polygon};
      }`
      : styled.div``;

  const outerStyle: React.CSSProperties = {
    display: "flex",
    justifyContent: sentByMe ? "flex-end" : "flex-start",
    filter: shadowString
  }

  const radiusPosition: React.CSSProperties =
    first
      ? (sentByMe
        ? { borderTopRightRadius: 0 }
        : { borderTopLeftRadius: 0 })
      : {};

  const innerStyle: React.CSSProperties = {
    position: "relative",
    top: 0,
    [direction]: pointWidth,
    background,
    borderRadius: 10,
    ...radiusPosition
  }

  return (
    <PointBefore style={outerStyle} ref={darkenNode}>
      <div style={innerStyle} onClick={(event) => {
          event.stopPropagation();
          return false;
         }}>
        {children}
      </div>
    </PointBefore>
  )
}