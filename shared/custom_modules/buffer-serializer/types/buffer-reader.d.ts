import { Buffer } from "../../buffer";

export default BufferReader;
declare class BufferReader {
    /**
     * Loads an existing buffer into the BufferReader.  Optionally, you
     * may specify the byte that indicates the starting point of the
     * buffer.
     *
     * @param {Buffer} buff
     * @param {number} [offset=0]
     */
    constructor(buff: Buffer, offset?: number);
    readBuffer: Buffer;
    offset: number;
    /**
     * Reads a buffer of a given length.
     *
     * Typically the length is stored before the buffer, so one can
     * use code similar to this:
     *
     *   buff = bufferReader.buffer(bufferReader.size());
     *
     * @param {number} length
     * @return {Buffer}
     */
    buffer(length: number): Buffer;
    /**
     * Reads an 8-byte big-endian double.
     *
     * @return {number}
     */
    double(): number;
    /**
     * Look at the current byte but do not increment the offset.  This
     * lets us investigate what we should do in order to decode the
     * next chunk that's in the buffer.
     *
     * @return {number}
     * @throws {Error} when reading beyond the end of the buffer
     */
    peek(): number;
    /**
     * Read an encoded size.  This can only read sizes up to
     * 0x1FFFFFFF.  The size is encoded using something akin to
     * how lengths are stored in LZ77.
     *
     * Peeks at the first byte.  It's high bits determine the
     * length of the integer to read.
     *
     *   0xxx xxxx = 8 bits
     *   10xx xxxx = 16 bits
     *   110x xxxx = 32 bits
     *
     * This can be extended when necessary.
     *
     * @return {number}
     * @throws {Error} when initial byte doesn't match an expected pattern
     */
    size(): number;
    /**
     * Moves the offset forward without having to read any bytes.
     * Used primarily when one has used peek to scan ahead or when the
     * next byte is already known in advance.
     */
    skip(): void;
    /**
     * Reads a string of a given length.  Normally this is written to
     * the buffer with the size preceeding it, and the following code
     * would be seen for decoding the string.
     *
     *   str = bufferReader.string(bufferReader.size());
     *
     * @param {number} length
     * @return {string}
     */
    string(length: number): string;
    /**
     * Reads an 8-bit unsigned integer.
     *
     * @return {number}
     */
    uint8(): number;
    /**
     * Reads a 16-bit big-endian unsigned integer.
     *
     * @return {number}
     */
    uint16(): number;
    /**
     * Reads a 32-bit big-endian unsigned integer.
     *
     * @return {number}
     */
    uint32(): number;
}
