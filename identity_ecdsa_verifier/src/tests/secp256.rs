// Copyright 2020-2024 IOTA Stiftung, Filancore GmbH
// SPDX-License-Identifier: Apache-2.0

mod es256 {
  use identity_verification::jwk::EcCurve;
  use identity_verification::jwk::Jwk;
  use identity_verification::jwk::JwkParamsEc;
  use identity_verification::jwu;
  use p256::ecdsa::Signature;
  use p256::ecdsa::SigningKey;
  use p256::SecretKey;

  pub(crate) fn expand_p256_jwk(jwk: &Jwk) -> SecretKey {
    let params: &JwkParamsEc = jwk.try_ec_params().unwrap();

    if params.try_ec_curve().unwrap() != EcCurve::P256 {
      panic!("expected a P256 curve");
    }

    let sk_bytes = params.d.as_ref().map(jwu::decode_b64).unwrap().unwrap();
    SecretKey::from_slice(&sk_bytes).unwrap()
  }

  pub(crate) fn sign(message: &[u8], private_key: &Jwk) -> impl AsRef<[u8]> {
    let sk: SecretKey = expand_p256_jwk(private_key);
    let signing_key: SigningKey = SigningKey::from(sk);
    let signature: Signature = signature::Signer::sign(&signing_key, message);
    signature.to_bytes()
  }
}

use identity_verification::jwk::Jwk;
use identity_verification::jws;
use identity_verification::jws::JwsHeader;

use crate::EcDSAJwsVerifier;

#[test]
fn test_es256_rfc7515() {
  // Test Vector taken from https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.3.
  let tv_header: &str = r#"{"alg":"ES256"}"#;
  let tv_claims: &[u8] = &[
    123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120, 112, 34, 58, 49, 51, 48, 48,
    56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58, 47, 47, 101, 120, 97, 109, 112, 108, 101, 46,
    99, 111, 109, 47, 105, 115, 95, 114, 111, 111, 116, 34, 58, 116, 114, 117, 101, 125,
  ];
  let tv_encoded: &[u8] = b"eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.e4ZrhZdbFQ7630Tq51E6RQiJaae9bFNGJszIhtusEwzvO21rzH76Wer6yRn2Zb34VjIm3cVRl0iQctbf4uBY3w";
  let tv_private_key: &str = r#"
        {
          "kty": "EC",
          "crv": "P-256",
          "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
          "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
          "d": "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
        }
      "#;

  let header: JwsHeader = serde_json::from_str(tv_header).unwrap();
  let jwk: Jwk = serde_json::from_str(tv_private_key).unwrap();
  let encoder: jws::CompactJwsEncoder<'_> = jws::CompactJwsEncoder::new(tv_claims, &header).unwrap();
  let signing_input: &[u8] = encoder.signing_input();
  let encoded: String = {
    let signature = es256::sign(signing_input, &jwk);
    encoder.into_jws(signature.as_ref())
  };
  assert_eq!(encoded.as_bytes(), tv_encoded);

  let jws_verifier = EcDSAJwsVerifier::default();
  let decoder = jws::Decoder::new();
  let token = decoder
    .decode_compact_serialization(tv_encoded, None)
    .and_then(|decoded| decoded.verify(&jws_verifier, &jwk))
    .unwrap();

  assert_eq!(token.protected, header);
  assert_eq!(token.claims, tv_claims);
}
