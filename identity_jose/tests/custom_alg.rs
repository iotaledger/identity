// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::ops::Deref;
use std::time::SystemTime;

use crypto::signatures::ed25519::PublicKey;
use crypto::signatures::ed25519::SecretKey;
use crypto::signatures::ed25519::Signature;
use identity_jose::jwk::EdCurve;
use identity_jose::jwk::Jwk;
use identity_jose::jwk::JwkParamsOkp;
use identity_jose::jwk::JwkType;
use identity_jose::jws::CompactJwsEncoder;
use identity_jose::jws::Decoder;
use identity_jose::jws::JwsAlgorithm;
use identity_jose::jws::JwsHeader;
use identity_jose::jws::JwsVerifierFn;
use identity_jose::jws::SignatureVerificationError;
use identity_jose::jws::SignatureVerificationErrorKind;
use identity_jose::jws::VerificationInput;
use identity_jose::jwt::JwtClaims;
use identity_jose::jwu;
use jsonprooftoken::encoding::base64url_decode;

#[test]
fn custom_alg_roundtrip() {
  let secret_key = SecretKey::generate().unwrap();
  let public_key = secret_key.public_key();

  let mut header: JwsHeader = JwsHeader::new();
  header.set_alg(JwsAlgorithm::Custom("test".to_string()));
  let kid = "did:iota:0x123#signing-key";
  header.set_kid(kid);

  let mut claims: JwtClaims<serde_json::Value> = JwtClaims::new();
  claims.set_iss("issuer");
  claims.set_iat(
    SystemTime::now()
      .duration_since(SystemTime::UNIX_EPOCH)
      .unwrap()
      .as_secs() as i64,
  );
  claims.set_custom(serde_json::json!({"num": 42u64}));

  let claims_bytes: Vec<u8> = serde_json::to_vec(&claims).unwrap();

  let encoder: CompactJwsEncoder<'_> = CompactJwsEncoder::new(&claims_bytes, &header).unwrap();
  let signing_input: &[u8] = encoder.signing_input();
  let signature = secret_key.sign(signing_input).to_bytes();
  let jws = encoder.into_jws(&signature);

  let header = jws.split(".").next().unwrap();
  let header_json = String::from_utf8(base64url_decode(header.as_bytes())).expect("failed to decode header");
  assert_eq!(header_json, r#"{"kid":"did:iota:0x123#signing-key","alg":"test"}"#);

  let verifier = JwsVerifierFn::from(|input: VerificationInput, key: &Jwk| {
    if input.alg != JwsAlgorithm::Custom("test".to_string()) {
      panic!("invalid algorithm");
    }
    verify(input, key)
  });
  let decoder = Decoder::new();
  let mut public_key_jwk = Jwk::new(JwkType::Okp);
  public_key_jwk.set_kid(kid);
  public_key_jwk
    .set_params(JwkParamsOkp {
      crv: "Ed25519".into(),
      x: jwu::encode_b64(public_key.as_slice()),
      d: None,
    })
    .unwrap();

  let token = decoder
    .decode_compact_serialization(jws.as_bytes(), None)
    .and_then(|decoded| decoded.verify(&verifier, &public_key_jwk))
    .unwrap();

  let recovered_claims: JwtClaims<serde_json::Value> = serde_json::from_slice(&token.claims).unwrap();

  assert_eq!(token.protected.alg(), Some(JwsAlgorithm::Custom("test".to_string())));
  assert_eq!(claims, recovered_claims);
}

fn verify(verification_input: VerificationInput, jwk: &Jwk) -> Result<(), SignatureVerificationError> {
  let public_key = expand_public_jwk(jwk);

  let signature_arr = <[u8; Signature::LENGTH]>::try_from(verification_input.decoded_signature.deref())
    .map_err(|err| err.to_string())
    .unwrap();

  let signature = Signature::from_bytes(signature_arr);
  if public_key.verify(&signature, &verification_input.signing_input) {
    Ok(())
  } else {
    Err(SignatureVerificationErrorKind::InvalidSignature.into())
  }
}

fn expand_public_jwk(jwk: &Jwk) -> PublicKey {
  let params: &JwkParamsOkp = jwk.try_okp_params().unwrap();

  if params.try_ed_curve().unwrap() != EdCurve::Ed25519 {
    panic!("expected an ed25519 jwk");
  }

  let pk: [u8; PublicKey::LENGTH] = jwu::decode_b64(params.x.as_str()).unwrap().try_into().unwrap();

  PublicKey::try_from(pk).unwrap()
}
