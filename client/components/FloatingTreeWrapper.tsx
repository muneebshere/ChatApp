import React from "react";
import {
  useFloatingNodeId,
  useFloatingParentNodeId,
  FloatingNode,
  FloatingTree
} from "@floating-ui/react";

type FloatingTreeProps = Readonly<{ 
  open: boolean, 
  children: (zIndex: number | string) => JSX.Element
}>;

export default function FloatingTreeWrapper({ open, children }: FloatingTreeProps) {

  const nodeId = useFloatingNodeId();
  const parentId = useFloatingParentNodeId();

  const calculateChildZ = (parentId: string) => {
    const element = document.querySelector(`#${CSS.escape(parentId)}`);
    if (!element) return undefined;
    const zIndex = getComputedStyle(element).zIndex;
    const zIndexN = parseInt(zIndex);
    return isNaN(zIndexN) ? zIndex : zIndexN + 1;
  }

  const zIndex = 
    !parentId
      ? undefined
      : calculateChildZ(parentId);

  const render = (
  <FloatingNode id={nodeId}>
    {open && children(zIndex)}
  </FloatingNode>);

  return (
    !parentId
      ? (<FloatingTree>
          {render}
        </FloatingTree>)
      : render);
}