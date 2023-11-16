import { stringify } from "safe-stable-stringify";
import { isBrowser, isNode, isWebWorker } from "./node_modules/browser-or-node";
import { ErrorStrings, Failure } from "./commonTypes";
import { Node, Parent, Literal } from "unist";

const logOff = false;

export function failure(reason: ErrorStrings, details: any = null): Failure {
    return details ? { reason, details } : { reason };
}

export function randomFunctions() {
    let crypto: any = null;
    if (isNode) { 
        crypto = eval(`require("node:crypto").webcrypto`);
    }
    else if (isBrowser) {
        crypto = window.crypto;
    }
    else if (isWebWorker) {
        crypto = self.crypto;
    }
    if (crypto === null) {
        throw "No crypto in this environment";
    }
    function getRandomVector(bytes: number): Buffer {
        let rv = new Uint8Array(bytes);
        crypto.getRandomValues(rv);
        return Buffer.from(rv);
      }
    function getRandomString(chars: number, base: "base64" | "hex") {
        const bitsPerChar = base === "hex" ? 4 : 6;
        const bytes = Math.ceil((chars * bitsPerChar) / 8);
        return getRandomVector(bytes).toString(base).slice(0, chars);
    }
    return { getRandomVector, getRandomString };
}

export function logError(err: any): void {
    if (logOff) return;
    const message = err.message;
    if (message) {
        console.log(`${message}`);
    }
    else {
        console.log(`${stringify(err)}`);
    }
    console.trace();
}

export function fromBase64(data: string) {
    return Buffer.from(data, "base64");
}

export async function allSettledResults<T>(promises: Promise<T>[]): Promise<T[]> {
    return (await Promise.allSettled(promises)).filter((result) => result.status === "fulfilled").map((result) => (result as PromiseFulfilledResult<T>).value);
}

export function awaitCallback<T>(callback: (resolve: (result: T) => void) => Promise<void>, timeout = 0, timeoutResponse: T = null) {
    return new Promise<T>(async (resolve) => {
        await callback(resolve);
        if (timeout) {
            window.setTimeout(() => resolve(timeoutResponse), timeout);
        }
    });
}

export type Entry<T> = { 
    [K in keyof T]: [K, T[K]] 
}[keyof T]

export function typedEntries<T extends {}>(object: T): ReadonlyArray<Entry<T>> {
  return Object.entries(object) as unknown as ReadonlyArray<Entry<T>>; 
}

export async function truncateMarkdown(markdown: string, maxChars: number) {
    const { unified } = await import("unified");
    const { default: remarkParse } = await import("remark-parse");
    const { default: remarkGfm } = await import("remark-gfm");
    const { default: remarkMath } = await import("remark-math");
    const { default: remarkStringify } = await import("remark-stringify");
    const { removePosition } = await import("unist-util-remove-position");
    const { visit, SKIP, CONTINUE } = await import("unist-util-visit");

    function replaceHeadings(node: any, index: number | null, parent: any) {
        const { children } = node;
        parent.children.splice(index, 1, { type: "paragraph", children });
        return CONTINUE;
    }

    function replaceAsPara(parent: any, index: number, newNode: any) {
        const insertNode = (parent.type !== "paragraph") ? { type: "paragraph", children: [newNode] }: newNode;
        parent.children.splice(index, 1, insertNode);
    }

    function replaceImages(node: any, index: number | null, parent: any) {
        replaceAsPara(parent, index, { type: "text", value: "[Image]" });
        return CONTINUE;
    }

    function replaceCodeBlocks(node: any, index: number | null, parent: any) {
        const lang = node.lang.trim();
        const label = 
            lang === "mermaid"
                ? "[Diagram]"
                : (lang
                    ? `[${lang.charAt(0).toUpperCase()}${lang.slice(1)} Code]`
                    : ["Codeblock"]);
        replaceAsPara(parent, index, { type: "text", value: label });
        return CONTINUE;
    }

    function replaceMathBlocks(node: any, index: number | null, parent: any) {
        replaceAsPara(parent, index, { type: "text", value: "[Math]" });
        return CONTINUE;
    }

    function replaceTables(node: any, index: number | null, parent: any) {
        replaceAsPara(parent, index, { type: "text", value: "[Table]" });
        return CONTINUE;
    }

    function expandList(listNode: any, listLevel = 0) {
        const children = listNode.children.flatMap((listItem: any) =>
            listItem.children.map((child: any) => {
                if (child.type === "paragraph") {
                    child.children.splice(0, 0, { type: "text", value: `${"    ".repeat(listLevel)}*   ` });
                }
                return child;
            }));
        let listAt = NaN;
        while (Number.isNaN(listAt) || listAt > -1) {
            if (!Number.isNaN(listAt)) children.splice(listAt, 1, ...expandList(children[listAt], listLevel + 1));
            listAt = children.findIndex((c: any) => c.type === "list");
        }
        return children;
    }

    function replaceLists(node: any, index: number | null, parent: any) {
        parent.children.splice(index, 1, ...expandList(node, 0));
        return SKIP;
    }

    function truncateTree(node: Node | Parent | Literal, maxChars: number): { reachedEnd: boolean, isLeaf: boolean, usedChars: number, truncated: Node | Parent | Literal} {
        if ("value" in node) {
            const { value } = node;
            let [reachedEnd, usedChars, truncated] = truncateText(value as string, maxChars);
            usedChars = truncated.trim() ? usedChars : 0;
            return { reachedEnd, isLeaf: true, usedChars, truncated: usedChars ? { ...node, value: truncated } : null };
        }
        else if ("children" in node) {
            const { children } = node;
            let usedCharsYet = 0;
            let append = false;
            const newChildren: (Node | Parent | Literal)[] = [];
            for (const child of children) {
                if (usedCharsYet < maxChars) {
                    const { reachedEnd, isLeaf, usedChars, truncated } = truncateTree(child, maxChars - usedCharsYet);
                    if (truncated) newChildren.push(truncated);
                    if (reachedEnd) usedCharsYet = maxChars;
                    else usedCharsYet += usedChars;
                    if (usedCharsYet >= maxChars) {
                        append = isLeaf;
                        break;
                    }
                }
                else break;
            }
            if (append) newChildren.push({ type: "text", value: " ..." });
            const truncated = newChildren.length > 0 ? { ...node, children: newChildren } : null;
            const usedChars = truncated ? usedCharsYet : 0;
            return { reachedEnd: usedCharsYet >= maxChars, isLeaf: false, usedChars, truncated }
        }
        else return { reachedEnd: false, isLeaf: true, usedChars: 0, truncated: node };
    }

    function truncateText(text: string, maxChars: number): [boolean, number, string] {
        if (!text) return [false, 0, ""];
        const chars = [...text];
        const textLength = chars.length;
        if (textLength <= maxChars) return [false, textLength, text];
        const indexedChars = chars.map((c, i) => ([c, i] as const));
        let trimLength = 0;
        for (const [c, i] of indexedChars.reverse()) {
            if (!c.trim() && i < maxChars) {
                trimLength = i + 1;
                break;
            }
        }
        return [true, trimLength, text.slice(0, trimLength)];
    }

    const processor = unified()
                        .use(remarkParse)
                        .use(remarkGfm)
                        .use(remarkMath)
                        .freeze();
    const reverseProcessor = unified()
                        .use(remarkGfm)
                        .use(remarkMath)
                        .use(remarkStringify)
                        .freeze();
    const tree = processor.parse(markdown);
    removePosition(tree, { force: true });
    visit(tree, "heading", replaceHeadings);
    visit(tree, "image", replaceImages);
    visit(tree, "code", replaceCodeBlocks);
    visit(tree, "math", replaceMathBlocks);
    visit(tree, "table", replaceTables);
    visit(tree, "list", replaceLists);
    const { truncated } = truncateTree(tree, maxChars);
    return reverseProcessor.stringify(truncated as any);
}

export async function escapeHtml(markdown: string) {
    const { unified } = await import("unified");
    const { default: remarkParse } = await import("remark-parse");
    const { default: remarkGfm } = await import("remark-gfm");
    const { default: remarkStringify } = await import("remark-stringify");
    const { removePosition } = await import("unist-util-remove-position");
    const { visit, CONTINUE } = await import("unist-util-visit");

    function replaceAsPara(parent: any, index: number, newNode: any) {
        const insertNode = (parent.type !== "paragraph") ? { type: "paragraph", children: [newNode] }: newNode;
        parent.children.splice(index, 1, insertNode);
    }

    function htmlToText(node: any, index: number | null, parent: any) {
        const { value } = node;
        replaceAsPara(parent, index, { type: "text", value });
        return CONTINUE;
    }

    const processor = unified()
                        .use(remarkParse)
                        .use(remarkGfm)
                        .freeze();
    const reverseProcessor = unified()
                        .use(remarkGfm)
                        .use(remarkStringify)
                        .freeze();
    const tree = processor.parse(markdown);
    removePosition(tree, { force: true });
    visit(tree, "html", htmlToText);
    return reverseProcessor.stringify(tree);
}