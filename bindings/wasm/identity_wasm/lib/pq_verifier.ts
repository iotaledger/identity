// Copyright 2024 Fondazione Links
// SPDX-License-Identifier: Apache-2.0

import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa';
import { decodeB64, Jwk, IJwsVerifier} from "~identity_wasm";
import { JwsAlgorithm, CompositeAlgIdDomain } from "./jose";

export class PQJwsVerifier implements  IJwsVerifier{

    public verify (alg: JwsAlgorithm, signingInput: Uint8Array, decodedSignature: Uint8Array, publicKey: Jwk): void{
        let res = false;
        let ctx = undefined;
        
        if (alg !== JwsAlgorithm.MLDSA44 &&
            alg !== JwsAlgorithm.MLDSA65 &&
            alg !== JwsAlgorithm.MLDSA87 &&
            alg !== JwsAlgorithm.IdMldsa44Ed25519 &&
            alg !== JwsAlgorithm.IdMldsa65Ed25519) {
            throw new Error("unsupported JWS algorithm");
        }

        const pubKey = decodeJwk(publicKey);

        //Domain separator for hybrid signatures
        if (alg === JwsAlgorithm.IdMldsa44Ed25519) {
            ctx = Uint8Array.from(Buffer.from(CompositeAlgIdDomain.IdMldsa44Ed25519, 'hex'));
        } else if (alg === JwsAlgorithm.IdMldsa65Ed25519) { 
            ctx = Uint8Array.from(Buffer.from(CompositeAlgIdDomain.IdMldsa65Ed25519, 'hex'));
        }

        if (alg === JwsAlgorithm.MLDSA44 || alg === JwsAlgorithm.IdMldsa44Ed25519) {
            res = ml_dsa44.verify(pubKey, signingInput, decodedSignature, ctx);
        } else if (alg === JwsAlgorithm.MLDSA65 || alg === JwsAlgorithm.IdMldsa65Ed25519) {
            res = ml_dsa65.verify(pubKey, signingInput, decodedSignature, ctx);
        } else if (alg === JwsAlgorithm.MLDSA87) {
            res = ml_dsa87.verify(pubKey, signingInput, decodedSignature);
        }
        if (!res) {
            throw new Error("signature verification failed");
        }       
    }

}

function decodeJwk(jwk: Jwk): Uint8Array {
    if (jwk.alg()! !== JwsAlgorithm.MLDSA44 && jwk.alg()! !== JwsAlgorithm.MLDSA65 && jwk.alg()! !== JwsAlgorithm.MLDSA87) {
        throw new Error("unsupported `alg`");
    }

    const paramsPQ = jwk.paramsAkp();

    if (paramsPQ) {
        let textEncoder = new TextEncoder();
        return decodeB64(textEncoder.encode(paramsPQ.pub));
    } else {
        throw new Error("expected Okp params");
    }
}



