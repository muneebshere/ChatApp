import React, { MutableRefObject, useCallback, useLayoutEffect, useMemo, useRef } from "react";
import { useSwipeable } from "react-swipeable";
import { SwipeCallback } from "react-swipeable/es/types";

export default function useSwipeDrag(ref: MutableRefObject<HTMLDivElement>, maxDrag: number, actionThreshold: number, action: () => void, toggleScroll?: (scrollOn: boolean) => void) {
  const dragXRef= useRef<number>(null);
  const setDragX = (dragX: number) => {
    if (ref.current) {
      ref.current.style.transform = `translateX(${dragX || 0}px)`;
      dragXRef.current = dragX;
      toggleScroll?.(dragX === null ? true : false);
    }
  }
  const dragSelectedRef = useRef(false);

  const onSwipeStart: SwipeCallback = useCallback(({ dir, deltaX }) => {
    if (dir === "Right") {
      setDragX(deltaX);
    }
  }, []);

  const onSwiping: SwipeCallback = useCallback(({ deltaX }) => {
    if (dragXRef.current !== null && (dragXRef.current <= maxDrag || deltaX <= maxDrag)) {
      setDragX(Math.max(deltaX, 0));
      if (deltaX >= actionThreshold && !dragSelectedRef.current) {
        action();
        dragSelectedRef.current = true;
        if (window.navigator.userActivation.isActive) {
          window.navigator.vibrate(20);
        }
      }
    }
  }, []);

  const onSwiped: SwipeCallback = useCallback(() => {
    if (dragXRef.current !== null) {
      setDragX(null);
      dragSelectedRef.current = false;
    }
  }, []);

  const swipeConfig: Parameters<typeof useSwipeable>[0] = useMemo(() => ({ onSwipeStart, onSwiped, onSwiping, delta: { up: Infinity, down: Infinity, left: Infinity, right: 10 }, trackTouch: true, trackMouse: false, touchEventOptions: { passive: true } }), []);
  
  const { ref: swipeRef, ...handlers } = useSwipeable(swipeConfig);

  useLayoutEffect(()=> {
    swipeRef(ref.current);
    return () => swipeRef(null);
  }, []);

  return handlers;
}