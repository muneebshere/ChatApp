import _ from "lodash";
import React, { useState, MutableRefObject, useLayoutEffect } from "react";
import useResizeObserver from "@react-hook/resize-observer";

function sizeFromRect(rect: DOMRect): [number, number] {
  return rect ? [rect?.width || 0, rect?.height || 0] : [0, 0];
}

export function useSize<T extends HTMLElement>(target: MutableRefObject<T>, initialValue?: [number, number]) {
  const [size, setSize] = useState<[number, number]>(initialValue || [0, 0]);

  useLayoutEffect(() => {
    const element = target.current;
    if (element && !initialValue) {
      const computedStyle = getComputedStyle(element);
      let elementHeight = element.clientHeight;
      let elementWidth = element.clientWidth;
      elementHeight -= parseFloat(computedStyle.paddingTop) + parseFloat(computedStyle.paddingBottom);
      elementWidth -= parseFloat(computedStyle.paddingLeft) + parseFloat(computedStyle.paddingRight);
      elementHeight = Math.max(elementHeight, 0);
      elementWidth = Math.max(elementWidth, 0);
      setSize([elementWidth, elementHeight]);
    }
  }, [target]);
  
  useResizeObserver(target, (entry) => setSize(sizeFromRect(entry.contentRect)));
  return size;
}