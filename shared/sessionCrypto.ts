import { SignedEncryptedData, randomFunctions } from "./commonTypes";
import * as crypto from "./cryptoOperator";
import { Buffer } from "./node_modules/buffer";
import BufferSerializer from "./custom_modules/buffer-serializer";
const serializer = new BufferSerializer();
const serialize: (data: any) => Buffer = serializer.toBuffer.bind(serializer);
function deserialize(buff: Buffer, offset = 0): any {
  let result;
  if (!buff) {
    throw "Nothing to deserialize.";
  }
  try {
    result = serializer.fromBuffer(buff, offset);
    if (result && result instanceof Uint8Array) {
      result = null;
    }
  }
  catch(err) {
    console.log(`${err.message}${err.stack}`);
    result = null;
  }
  if (result) {
    return result;
  }
  if (offset < 50) {
    return deserialize(buff, offset + 1);
  }
  return {};
}

const { getRandomVector } = randomFunctions();

type SignedEncryptedMessage = SignedEncryptedData & {
  readonly sessionReference: string;
  readonly salt: Buffer;
}

export class SessionCrypto {
  readonly #sessionKeyBits: Buffer;
  readonly #sessionReference: string;
  readonly #sessionSigningKey: CryptoKey;
  readonly #sessionVerifyingKey: CryptoKey;
  
  constructor(sessionReference: string, sessionKeyBits: Buffer, sessionSigningKey: CryptoKey, sessionVerifyingKey: CryptoKey) {
    this.#sessionReference = sessionReference;
    this.#sessionKeyBits = sessionKeyBits;
    this.#sessionSigningKey = sessionSigningKey;
    this.#sessionVerifyingKey = sessionVerifyingKey;
  }

  async signEncrypt(data: any, purpose: string): Promise<Buffer> {
    const salt = getRandomVector(48);
    const plaintext = serialize(data);
    const sessionReference = this.#sessionReference;
    const sessionSigningKey = this.#sessionSigningKey;
    const { ciphertext, signature } = await crypto.deriveSignEncrypt(this.#sessionKeyBits, plaintext, salt, purpose, sessionSigningKey);
    const message: SignedEncryptedMessage = { sessionReference, salt, ciphertext, signature };
    return serialize(message);
  }

  async decryptVerify(serializedData: Buffer, purpose: string): Promise<any> {
    try {
      const data: SignedEncryptedMessage | SignedEncryptedMessage = deserialize(serializedData);
      const { sessionReference, salt, ciphertext, signature } = data;
      if (sessionReference !== this.#sessionReference)
        return null;
      return deserialize(await crypto.deriveDecryptVerify(this.#sessionKeyBits, ciphertext, salt, purpose, signature, this.#sessionVerifyingKey));
    }
    catch(err) {
        console.log(`${err}`);
        return null;
    }

  }
}