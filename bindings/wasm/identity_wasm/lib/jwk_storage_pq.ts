// Copyright 2024 Fondazione Links
// SPDX-License-Identifier: Apache-2.0
import * as ed from "@noble/ed25519";
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa';
import { decodeB64, encodeB64, Jwk, JwkGenOutput, JwkStoragePQ, JwkStorage  } from "~identity_wasm";
import { EdCurve, JwkType, JwsAlgorithm} from "./jose";

type Ed25519PrivateKey = Uint8Array;
type Ed25519PublicKey = Uint8Array;


//JkwStorage for PQ and PQ/T examples
export class JwkPqMemStore implements  JwkStorage, JwkStoragePQ{
    /** The map from key identifiers to Jwks. */
    private _keys: Map<string, Jwk>;

    /** Creates a new, empty `MemStore` instance. */
    constructor() {
        this._keys = new Map();
    }

    public static mldsaKeyType(): string {
        return "AKP";
    }

    public static ed25519KeyType(): string {
        return "Ed25519";
    }


    private _get_key(keyId: string): Jwk | undefined {
        return this._keys.get(keyId);
    }

    public async generate(keyType: string, algorithm: JwsAlgorithm): Promise<JwkGenOutput> {
        if (keyType !== JwkPqMemStore.ed25519KeyType()) {
            throw new Error(`unsupported key type ${keyType}`);
        }

        if (algorithm !== JwsAlgorithm.EdDSA) {
            throw new Error(`unsupported algorithm`);
        }

        const keyId = randomKeyId();
        const privKey: Ed25519PrivateKey = ed.utils.randomPrivateKey();

        const publicKey: Ed25519PublicKey = await ed.getPublicKey(privKey);
        const jwk = await encodeJwk(privKey, publicKey, algorithm);

        this._keys.set(keyId, jwk);

        const publicJWK = jwk?.toPublic();
        if (!publicJWK) {
            throw new Error(`JWK is not a public key`);
        }

        return new JwkGenOutput(keyId, publicJWK);
    }

    public async generatePQKey(keyType: String, algorithm: JwsAlgorithm):  Promise<JwkGenOutput> {

        if (keyType !== JwkPqMemStore.mldsaKeyType()) {
            throw new Error(`unsupported key type ${keyType}`);
        }
        
        const seed = new TextEncoder().encode(randomKeyId())
        let keys;
        if (algorithm === JwsAlgorithm.MLDSA44) {
            keys = ml_dsa44.keygen(seed);
        } else if(algorithm === JwsAlgorithm.MLDSA65) {
            keys = ml_dsa65.keygen(seed);
        } else if(algorithm === JwsAlgorithm.MLDSA87) {
            keys = ml_dsa87.keygen(seed);
        } else {
            throw new Error(`unsupported algorithm`);
        }

        const keyId = randomKeyId();
        
        const jwk = await encodeJwk(keys.secretKey, keys.publicKey, algorithm);

        if(jwk == undefined)
            throw new Error("Unexpected error: await encodeJwk(privKey, publicKey, algorithm)");

        this._keys.set(keyId, jwk);

        const publicJWK = jwk?.toPublic();
        if (!publicJWK) {
            throw new Error(`JWK is not a public key`);
        }
        
        return new JwkGenOutput(keyId, publicJWK);

    }

    public async sign(keyId: string, data: Uint8Array, publicKey: Jwk): Promise<Uint8Array> {
        let alg = publicKey.alg();
        let signature = null;
        
        if(alg === undefined) {
            throw new Error("expected a Jwk with an `alg` parameter");
        }

        if (alg !== JwsAlgorithm.EdDSA ) {
            throw new Error("unsupported JWS algorithm");
        } else {
            if (publicKey.paramsOkp()?.crv !== (EdCurve.Ed25519 as string))
            {
                throw new Error("unsupported Okp parameter");
            }
        }

        const jwk = this._keys.get(keyId);

        if (jwk) {
            const [privateKey, _] = decodeJwk(jwk);
            signature = await ed.sign(data, privateKey);

        } else {
            throw new Error(`key with id ${keyId} not found`);
        }
        return signature; 
    }

    public async signPQ(keyId: string, data: Uint8Array, publicKey: Jwk, ctx: Uint8Array|undefined ): Promise<Uint8Array> {
        let alg = publicKey.alg();
        let signature = null;
        
        if(alg === undefined) {
            throw new Error("expected a Jwk with an `alg` parameter");
        }

        if (alg !== JwsAlgorithm.MLDSA44 && alg !== JwsAlgorithm.MLDSA65 && alg !== JwsAlgorithm.MLDSA87) {
            throw new Error("unsupported JWS algorithm");
        }

        const jwk = this._keys.get(keyId);

        if (jwk) {
            
            const [privateKey, _] = decodeJwk(jwk);
            
            if(alg == JwsAlgorithm.MLDSA44)
                signature = ml_dsa44.sign(privateKey, data, ctx);
            else if(alg == JwsAlgorithm.MLDSA65)
                signature = ml_dsa65.sign(privateKey, data, ctx);
            else if(alg == JwsAlgorithm.MLDSA87)
                signature = ml_dsa87.sign(privateKey, data, ctx);
            else
                throw new Error("unsupported algorithm");

        } else {
            throw new Error(`key with id ${keyId} not found`);
        }
        return signature; 
    }

    public async insert(jwk: Jwk): Promise<string> {
        const keyId = randomKeyId();

        if (!jwk.isPrivate) {
            throw new Error("expected a JWK with all private key components set");
        }

        if (!jwk.alg()) {
            throw new Error("expected a Jwk with an `alg` parameter");
        }

        this._keys.set(keyId, jwk);

        return keyId;
    }

    public async delete(keyId: string): Promise<void> {
        this._keys.delete(keyId);
    }

    public async exists(keyId: string): Promise<boolean> {
        return this._keys.has(keyId);
    }

    public count(): number {
        return this._keys.size;
    }
}

// Encodes a Ed25519 keypair into a Jwk.
async function encodeJwk(privateKey: Uint8Array, publicKey: Uint8Array, alg: JwsAlgorithm): Promise<Jwk> {
    let pub = encodeB64(publicKey);
    let priv = encodeB64(privateKey);

    if (alg === JwsAlgorithm.EdDSA) {
        return new Jwk({
            "kty": JwkType.Okp,
            crv: "Ed25519",
            d: priv,
            x: pub,
            alg,
        });
    } else {
        return new Jwk({
            "kty": JwkType.Akp,
            pub: pub,
            priv: priv,
            alg,
        });
    } 

}

function decodeJwk(jwk: Jwk): [Uint8Array, Uint8Array] {
    if (jwk.alg()! !== JwsAlgorithm.MLDSA44 &&
        jwk.alg()! !== JwsAlgorithm.MLDSA65 &&
        jwk.alg()! !== JwsAlgorithm.MLDSA87 &&
        jwk.alg()! !== JwsAlgorithm.EdDSA) {
        throw new Error("unsupported `alg`");
    }
    if (jwk.alg()! === JwsAlgorithm.EdDSA) {
        const paramsOkp = jwk.paramsOkp();
        if (paramsOkp) {
            const d = paramsOkp.d;

            if (d) {
                const textEncoder = new TextEncoder();
                const privateKey = decodeB64(textEncoder.encode(d));
                const publicKey = decodeB64(textEncoder.encode(paramsOkp.x));
                return [privateKey, publicKey];
            } else {
                throw new Error("missing private key component");
            }
        } else {
            throw new Error("expected Okp params");
        }
    } else {
        const paramsPQ = jwk.paramsAkp();

        if (paramsPQ) {
            const priv = paramsPQ.priv;

            if (priv) {
                let textEncoder = new TextEncoder();
                const privateKey = decodeB64(textEncoder.encode(priv));
                const publicKey = decodeB64(textEncoder.encode(paramsPQ.pub));
                return [privateKey, publicKey];
            } else {
                throw new Error("missing private key component");
            }
        } else {
            throw new Error("expected Okp params");
        }

    }

}

// Returns a random number between `min` and `max` (inclusive).
// SAFETY NOTE: This is not cryptographically secure randomness and thus not suitable for production use.
// It suffices for our testing implementation however and avoids an external dependency.
function getRandomNumber(min: number, max: number): number {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

// Returns a random key id.
function randomKeyId(): string {
    const randomness = new Uint8Array(20);
    for (let index = 0; index < randomness.length; index++) {
        randomness[index] = getRandomNumber(0, 255);
    }

    return encodeB64(randomness);
}
