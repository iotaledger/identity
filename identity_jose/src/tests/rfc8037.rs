// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::jwk::Jwk;
use crate::jws::CompactJwsEncoder;
use crate::jws::Decoder;
use crate::jws::JwsAlgorithm;
use crate::jws::JwsHeader;
use crate::jws::JwsVerifierFn;
use crate::jws::VerificationInput;
use crate::tests::ed25519;

#[test]
fn test_rfc8037_ed25519() {
  struct TestVector {
    private_jwk: &'static str,
    public_jwk: &'static str,
    thumbprint_b64: &'static str,
    header: &'static str,
    payload: &'static str,
    encoded: &'static str,
  }

  static TVS: &[TestVector] = &include!("fixtures/rfc8037_ed25519.rs");

  for tv in TVS {
    let secret: Jwk = serde_json::from_str(tv.private_jwk).unwrap();
    let public: Jwk = serde_json::from_str(tv.public_jwk).unwrap();

    assert_eq!(secret.thumbprint_sha256_b64(), tv.thumbprint_b64);
    assert_eq!(public.thumbprint_sha256_b64(), tv.thumbprint_b64);

    let header: JwsHeader = serde_json::from_str(tv.header).unwrap();
    let encoder: CompactJwsEncoder<'_> = CompactJwsEncoder::new(tv.payload.as_bytes(), &header).unwrap();
    let signing_input: &[u8] = encoder.signing_input();
    let signature = ed25519::sign(signing_input, &secret);
    let jws: String = encoder.into_jws(signature.as_ref());

    assert_eq!(jws, tv.encoded);

    let jws_verifier = JwsVerifierFn::from(|input: VerificationInput, key: &Jwk| {
      if input.alg != JwsAlgorithm::EdDSA {
        panic!("invalid algorithm");
      }
      ed25519::verify(input, key)
    });
    let decoder = Decoder::new();
    let token = decoder
      .decode_compact_serialization(jws.as_bytes(), None)
      .and_then(|decoded| decoded.verify(&jws_verifier, &public))
      .unwrap();

    assert_eq!(token.protected, header);
    assert_eq!(token.claims, tv.payload.as_bytes());

    let jws_signature_verifier = JwsVerifierFn::from(|input: VerificationInput, key: &Jwk| match input.alg {
      JwsAlgorithm::EdDSA => ed25519::verify(input, key),
      other => unimplemented!("{other}"),
    });

    let decoder = Decoder::new();
    let token_with_default = decoder
      .decode_compact_serialization(jws.as_bytes(), None)
      .and_then(|decoded| decoded.verify(&jws_signature_verifier, &public))
      .unwrap();

    assert_eq!(token, token_with_default);
  }
}
