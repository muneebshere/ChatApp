import _ from "lodash";
import React, { useState, RefObject, useLayoutEffect } from "react";
import useResizeObserver from "@react-hook/resize-observer";

function sizeFromRect(rect: DOMRect): [number, number] {
  return rect ? [rect?.width || 0, rect?.height || 0] : [0, 0];
}

export function useSize<T extends HTMLElement>(target: RefObject<T>, rect: "content" | "client", initialValue?: [number, number]) {
  const [size, setSize] = useState<[number, number]>(initialValue || [0, 0]);

  useLayoutEffect(() => {
    const element = target.current;
    if (element && !initialValue) {
      const { clientWidth, clientHeight } = element;
      setSize([clientWidth, clientHeight]);
    }
  }, [target]);
  
  useResizeObserver(target, (entry) => setSize(sizeFromRect(rect === "content" ? entry.contentRect : target.current.getBoundingClientRect())));
  return size;
}