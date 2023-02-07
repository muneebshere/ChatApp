import { Buffer } from "../../buffer";

export default BufferWriter;
declare class BufferWriter {
    bufferList: any[];
    /**
     * Adds a buffer to the list.  This does not encode the length.
     * You will typically want to write code like this:
     *
     *   bufferWriter.size(buff.length);
     *   bufferWriter.buffer(buff);
     *
     * @param {Buffer} buff
     */
    buffer(buff: Buffer): void;
    /**
     * Adds an 8-byte big-endian double.
     *
     * @param {number} val
     */
    double(val: number): void;
    /**
     * Encodes a size using a mechanism like LZ77 distances.  This uses
     * a method to consume fewer bytes than just storing doubles or
     * uint32.  It's limited to a range of 0 to 0x1FFFFFFF.
     *
     * @param {number} s
     * @throws {Error} when negative
     * @throws {Error} when excessively large
     */
    size(s: number): void;
    /**
     * Adds a string to the buffer.  Does not add the length of the
     * string, which is necessary for decoding.  Normally you would use
     * the method like this example:
     *
     *   bufferWriter.size(str.length);
     *   bufferWriter.string(str);
     *
     * @param {string} str
     */
    string(str: string): void;
    /**
     * Converts the internal array of buffers into a single Buffer.
     *
     * @return {Buffer}
     */
    toBuffer(): Buffer;
    /**
     * Writes an unsigned 8-bit integer.
     *
     * @param {number} val
     */
    uint8(val: number): void;
    /**
     * Writes an unsigned big-endian 16-bit integer.
     *
     * @param {number} val
     */
    uint16(val: number): void;
    /**
     * Writes an unsigned big-endian 32-bit integer.
     *
     * @param {number} val
     */
    uint32(val: number): void;
}
