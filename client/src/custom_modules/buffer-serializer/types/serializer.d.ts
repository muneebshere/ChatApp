import BufferReader from "./buffer-reader";
import BufferWriter from "./buffer-writer";
import { Buffer } from "../../../node_modules/buffer";

export default BufferSerializer;
declare class BufferSerializer {
    helpers: any[];
    /**
     * Deserialize a buffer.  Double checks the version before calling
     * the fromBufferInternal* methods.
     *
     * @param {Buffer} buff
     * @param {number} [offset=0]
     * @return {*}
     * @throws {Error} invalid version stored in the buffer
     */
    fromBuffer(buff: Buffer, offset?: number): any;
    /**
     * Deserialize a buffer after the version checks were performed.
     * Reads the stored type code (single byte).  From there it either
     * decodes the information directly or else it passes control to
     * another function.
     *
     * @param {BufferReader} buffReader
     * @return {*}
     * @throws {Error} invalid type code
     */
    fromBufferInternal(buffReader: BufferReader): any;
    /**
     * Register a custom object type for serialization.
     *
     * @param {string} name Shorter names mean smaller serialized buffers.
     * @param {Function(obj)} checkFn Returns true if obj is the one you want.
     * @param {Function(obj,BufferWriter)} toBufferFn Write to the BufferWriter
     * @param {Function(BufferReader)} fromBufferFn Change buffer back to object
     */
    register(name: string, checkFn: any, toBufferFn: any, fromBufferFn: any): void;
    /**
     * Convert something to a buffer.  Creates the new BufferWriter and
     * kicks off the internal functions.
     *
     * @param {*} thing
     * @return {Buffer}
     */
    toBuffer(thing: any): Buffer;
    /**
     * Convert something to a buffer, writing it using the passed
     * BufferWriter instance.
     *
     * @param {*} thing
     * @param {BufferWriter} buffWriter
     * @throws {Error} when encountering an invalid type
     */
    toBufferInternal(thing: any, buffWriter: BufferWriter): any;
}