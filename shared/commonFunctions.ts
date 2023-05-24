import { stringify } from "safe-stable-stringify";
import { Buffer } from "./node_modules/buffer";
import { isBrowser, isNode, isWebWorker } from "./node_modules/browser-or-node";
import { Failure } from "./commonTypes";

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
    const message = err.message;
    if (message) {
        console.log(`${message}`);
    }
    else {
        console.log(`${stringify(err)}`);
    }
    console.trace();
}

export function truncateText(text: string, maxChar = 200) {
    if (!text) return null;
    if (text.length <= maxChar) return text;
    const truncate = text.indexOf(" ", maxChar);
    return `${text.slice(0, truncate)} ...`;
}

export function fromBase64(data: string) {
    return Buffer.from(data, "base64");
}

export async function allSettledResults<T>(promises: Promise<T>[]): Promise<T[]> {
    return (await Promise.allSettled(promises)).filter((result) => result.status === "fulfilled").map((result) => (result as PromiseFulfilledResult<T>).value);
}

export type Entry<T> = { 
    [K in keyof T]: [K, T[K]] 
}[keyof T]

export function typedEntries<T extends {}>(object: T): ReadonlyArray<Entry<T>> {
  return Object.entries(object) as unknown as ReadonlyArray<Entry<T>>; 
}