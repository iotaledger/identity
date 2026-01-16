// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
    IJwk,
    IJwkParams,
    IResolver,
    IssuerMetadata,
    Jwk,
    JwkType,
    KeyBindingJwtBuilder,
    KeyBindingJwtValidationOptions,
    SdJwtVcBuilder,
    Sha256Hasher,
    Timestamp,
    TypeMetadataHelper,
} from "@iota/identity-wasm/node";
import { exportJWK, generateKeyPair, JWK, JWTHeaderParameters, JWTPayload, SignJWT } from "jose";

const vc_metadata: TypeMetadataHelper = JSON.parse(`{
  "vct": "https://example.com/education_credential",
  "name": "Betelgeuse Education Credential - Preliminary Version",
  "description": "This is our development version of the education credential. Don't panic.",
  "claims": [
    {
      "path": ["name"],
      "display": [
        {
          "lang": "de-DE",
          "label": "Vor- und Nachname",
          "description": "Der Name des Studenten"
        },
        {
          "lang": "en-US",
          "label": "Name",
          "description": "The name of the student"
        }
      ],
      "sd": "allowed"
    },
    {
      "path": ["address"],
      "display": [
        {
          "lang": "de-DE",
          "label": "Adresse",
          "description": "Adresse zum Zeitpunkt des Abschlusses"
        },
        {
          "lang": "en-US",
          "label": "Address",
          "description": "Address at the time of graduation"
        }
      ],
      "sd": "always"
    },
    {
      "path": ["address", "street_address"],
      "display": [
        {
          "lang": "de-DE",
          "label": "Straße"
        },
        {
          "lang": "en-US",
          "label": "Street Address"
        }
      ],
      "sd": "always",
      "svg_id": "address_street_address"
    },
    {
      "path": ["degrees", null],
      "display": [
        {
          "lang": "de-DE",
          "label": "Abschluss",
          "description": "Der Abschluss des Studenten"
        },
        {
          "lang": "en-US",
          "label": "Degree",
          "description": "Degree earned by the student"
        }
      ],
      "sd": "allowed"
    }
  ]
}`);

const keypair_jwk = async (): Promise<[JWK, JWK]> => {
    const [sk, pk] = await generateKeyPair("ES256", { extractable: true }).then(res => [res.privateKey, res.publicKey]);
    const sk_jwk = await exportJWK(sk);
    const pk_jwk = await exportJWK(pk);

    return [sk_jwk, pk_jwk];
};

const signer = async (header: object, payload: object, sk_jwk: JWK) => {
    return new SignJWT(payload as JWTPayload)
        .setProtectedHeader(header as JWTHeaderParameters)
        .sign(sk_jwk)
        .then(jws => new TextEncoder().encode(jws));
};

export async function sdJwtVc() {
    const hasher = new Sha256Hasher();
    const issuer = "https://example.com/";
    const [sk_jwk, pk_jwk] = await keypair_jwk();
    const issuer_public_jwk = { ...pk_jwk, kty: JwkType.Ec, kid: "key1" } as IJwk;
    const issuer_signer = (header: object, payload: object) => signer(header, payload, sk_jwk);
    const issuer_metadata = new IssuerMetadata(issuer, { jwks: { keys: [issuer_public_jwk] } });
    const dummy_resolver = {
        resolve: async (input: string) => {
            if (input == "https://example.com/.well-known/jwt-vc-issuer/") {
                return new TextEncoder().encode(JSON.stringify(issuer_metadata.toJSON()));
            }
            if (input == "https://example.com/education_credential") {
                return new TextEncoder().encode(JSON.stringify(vc_metadata));
            }
        },
    } as IResolver<string, Uint8Array>;
    const [holder_sk, holder_pk] = await keypair_jwk();
    const holder_public_jwk = { ...holder_pk, kty: JwkType.Ec, kid: "key2" } as IJwk;
    const holder_signer = (header: object, payload: object) => signer(header, payload, holder_sk);

    /// Issuer creates an SD-JWT VC.
    let sd_jwt_vc = await new SdJwtVcBuilder({
        name: "John Doe",
        address: {
            street_address: "A random street",
            number: "3a",
        },
        degree: [],
    }, hasher)
        .vct("https://example.com/education_credential")
        .iat(Timestamp.nowUTC())
        .iss(issuer)
        .header("kid", issuer_public_jwk.kid)
        .requireKeyBinding({ kid: holder_public_jwk.kid })
        .makeConcealable("/address/street_address")
        .makeConcealable("/address")
        .finish({ sign: issuer_signer }, "ES256");

    console.log(`issued SD-JWT VC: ${sd_jwt_vc.toString()}`);

    // Holder receives its SD-JWT VC and attaches its keybinding JWT.
    const kb_jwt = await new KeyBindingJwtBuilder()
        .iat(Timestamp.nowUTC())
        .header("kid", holder_public_jwk.kid)
        .nonce("abcdefghi")
        .aud("https://example.com/verify")
        .finish(sd_jwt_vc.asSdJwt(), "ES256", { sign: holder_signer });
    sd_jwt_vc.attachKeyBindingJwt(kb_jwt);
    console.log(`presented SD-JWT VC: ${sd_jwt_vc}`);

    // Verifier checks the presented sdJwtVc.
    await sd_jwt_vc.validate(dummy_resolver, hasher);
    sd_jwt_vc.validateKeyBinding(
        new Jwk(holder_public_jwk as IJwkParams),
        hasher,
        new KeyBindingJwtValidationOptions({ nonce: "abcdefghi" }),
    );

    console.log("The presented SdJwtVc is valid!");
}
