import { SignedEncryptedData } from "./commonTypes";
import * as crypto from "./cryptoOperator";
import { serialize, deserialize } from "./cryptoOperator";
import { fromBase64, randomFunctions } from "./commonFunctions";

const { getRandomVector } = randomFunctions();

type SignedEncryptedMessage = SignedEncryptedData & {
    readonly reference: string;
    readonly hSalt: Buffer;
}

export class SessionCrypto {
    readonly #sessionKeyBits: CryptoKey;
    readonly #reference: string;
    readonly #sessionSigningKey: CryptoKey;
    readonly #sessionVerifyingKey: CryptoKey;

    constructor(reference: string, sessionKeyBits: CryptoKey, sessionSigningKey: CryptoKey, sessionVerifyingKey: CryptoKey) {
        this.#reference = reference;
        this.#sessionKeyBits = sessionKeyBits;
        this.#sessionSigningKey = sessionSigningKey;
        this.#sessionVerifyingKey = sessionVerifyingKey;
    }

    async signEncryptToBase64(data: any, purpose: string): Promise<string> {
        const hSalt = getRandomVector(48);
        const sessionSigningKey = this.#sessionSigningKey;
        const { ciphertext, signature } = await crypto.deriveSignEncrypt(this.#sessionKeyBits, data, hSalt, `${purpose}-${this.#reference}`, sessionSigningKey);
        const message: SignedEncryptedMessage = { reference: this.#reference, hSalt, ciphertext, signature };
        return serialize(message).toString("base64");
    }

    async decryptVerifyFromBase64(serializedData: string, purpose: string): Promise<any> {
        try {
            const data: SignedEncryptedMessage = deserialize(fromBase64(serializedData)) || {};
            const { reference, hSalt } = data;
            if (reference !== this.#reference)
                return null;
            return await crypto.deriveDecryptVerify(this.#sessionKeyBits, data, hSalt, `${purpose}-${this.#reference}`, this.#sessionVerifyingKey);
        }
        catch (err) {
            console.log(`${err}`);
            return null;
        }
    }
}