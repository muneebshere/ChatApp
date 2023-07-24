import React, { RefObject, useCallback, useLayoutEffect, useMemo, useRef } from "react";
import { useSwipeable } from "react-swipeable";
import { SwipeCallback } from "react-swipeable/es/types";

export default function useSwipeDrag(ref: RefObject<HTMLDivElement>, maxDrag: number, actionThreshold: number, action: () => void, toggleScroll: (scrollOn: boolean) => void, allowToScroll?: RefObject<HTMLElement>) {
  const dragXRef= useRef<number>(null);
  const setDragX = (dragX: number) => {
    if (ref.current) {
      ref.current.style.transform = `translateX(${dragX || 0}px)`;
      dragXRef.current = dragX;
      toggleScroll?.(dragX === null);
    }
  }
  const dragSelectedRef = useRef(false);

  const onSwipeStart: SwipeCallback = useCallback(({ event, dir, deltaX }) => {
    const target = event.target as any;
    if (allowToScroll 
      && (target.id === allowToScroll.current.id || allowToScroll.current.contains(target)) 
      && allowToScroll.current.scrollLeft > 0) {
      return;
    }
    if (dir === "Right") {
      setDragX(deltaX);
    }
  }, [allowToScroll]);

  const onSwiping: SwipeCallback = useCallback(({ deltaX }) => {
    if (dragXRef.current !== null && (dragXRef.current <= maxDrag || deltaX <= maxDrag)) {
      setDragX(Math.max(deltaX, 0));
      if (deltaX >= actionThreshold && !dragSelectedRef.current) {
        dragSelectedRef.current = true;
        if (window.navigator.userActivation.isActive) {
          window.navigator.vibrate(20);
        }
      }
    }
  }, []);

  const onSwiped: SwipeCallback = useCallback(({ deltaX }) => {
    if (dragXRef.current !== null) {
      setDragX(null);
      dragSelectedRef.current = false;
      if (deltaX >= actionThreshold) action();
    }
  }, []);

  const swipeConfig: Parameters<typeof useSwipeable>[0] = useMemo(() => ({ onSwipeStart, onSwiped, onSwiping, delta: { up: Infinity, down: Infinity, left: Infinity, right: 0 }, trackTouch: true, trackMouse: false, touchEventOptions: { passive: true } }), [allowToScroll]);
  
  const { ref: swipeRef, ...handlers } = useSwipeable(swipeConfig);

  useLayoutEffect(()=> {
    swipeRef(ref.current);
    return () => swipeRef(null);
  }, []);

  return handlers;
}