import { SignedEncryptedData } from "./commonTypes";
import * as crypto from "./cryptoOperator";
import { serialize, deserialize } from "./cryptoOperator";
import { fromBase64, randomFunctions } from "./commonFunctions";

const { getRandomVector } = randomFunctions();

type SignedEncryptedMessage = SignedEncryptedData & {
    readonly sessionReference: string;
    readonly salt: Buffer;
}

export class SessionCrypto {
    readonly #sessionKeyBits: CryptoKey;
    readonly #sessionReference: string;
    readonly #sessionSigningKey: CryptoKey;
    readonly #sessionVerifyingKey: CryptoKey;

    constructor(sessionReference: string, sessionKeyBits: CryptoKey, sessionSigningKey: CryptoKey, sessionVerifyingKey: CryptoKey) {
        this.#sessionReference = sessionReference;
        this.#sessionKeyBits = sessionKeyBits;
        this.#sessionSigningKey = sessionSigningKey;
        this.#sessionVerifyingKey = sessionVerifyingKey;
    }

    async signEncryptToBase64(data: any, purpose: string): Promise<string> {
        const salt = getRandomVector(48);
        const sessionReference = this.#sessionReference;
        const sessionSigningKey = this.#sessionSigningKey;
        const { ciphertext, signature } = await crypto.deriveSignEncrypt(this.#sessionKeyBits, data, salt, purpose, sessionSigningKey);
        const message: SignedEncryptedMessage = { sessionReference, salt, ciphertext, signature };
        return serialize(message).toString("base64");
    }

    async decryptVerifyFromBase64(serializedData: string, purpose: string): Promise<any> {
        try {
            const data: SignedEncryptedMessage | SignedEncryptedMessage = deserialize(fromBase64(serializedData));
            const { sessionReference, salt } = data;
            if (sessionReference !== this.#sessionReference)
                return null;
            return await crypto.deriveDecryptVerify(this.#sessionKeyBits, data, salt, purpose, this.#sessionVerifyingKey);
        }
        catch (err) {
            console.log(`${err}`);
            return null;
        }
    }
}