import { encode as base64Encode } from "base64-arraybuffer";
import type { KeyIdStorage, MethodDigest } from "~identity_wasm";

export class KeyIdMemStore implements KeyIdStorage {
    private _keyIds: Map<string, string>;

    constructor() {
        this._keyIds = new Map<string, string>();
    }

    public async insertKeyId(
        methodDigest: MethodDigest,
        keyId: string,
    ): Promise<void> {
        let methodDigestAsString: string = methodDigestToString(methodDigest);
        let value = this._keyIds.get(methodDigestAsString);
        if (value !== undefined) {
            throw new Error("KeyId already exists");
        }
        this._keyIds.set(methodDigestAsString, keyId);
    }

    public async getKeyId(methodDigest: MethodDigest): Promise<string> {
        let methodDigestAsString: string = methodDigestToString(methodDigest);
        let value = this._keyIds.get(methodDigestAsString);
        if (value == undefined) {
            throw new Error("KeyId not found");
        }
        return value;
    }

    public async deleteKeyId(methodDigest: MethodDigest): Promise<void> {
        let methodDigestAsString: string = methodDigestToString(methodDigest);
        let success = this._keyIds.delete(methodDigestAsString);
        if (success) {
            return;
        } else {
            throw new Error("KeyId not found!");
        }
    }

    public count(): number {
        return this._keyIds.size;
    }
}

/**
 * Converts a `MethodDigest` to a base64 encoded string.
 */
function methodDigestToString(methodDigest: MethodDigest): string {
    let arrayBuffer = methodDigest.pack().buffer;
    return base64Encode(arrayBuffer);
}
