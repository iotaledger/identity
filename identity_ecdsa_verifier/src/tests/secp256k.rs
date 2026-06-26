// Copyright 2020-2024 IOTA Stiftung, Filancore GmbH
// SPDX-License-Identifier: Apache-2.0

mod es256k1 {
  use identity_verification::jwk::EcCurve;
  use identity_verification::jwk::Jwk;
  use identity_verification::jwk::JwkParamsEc;
  use identity_verification::jwu;
  use k256::ecdsa::Signature;
  use k256::ecdsa::SigningKey;
  use k256::SecretKey;

  pub(crate) fn expand_k256_jwk(jwk: &Jwk) -> SecretKey {
    let params: &JwkParamsEc = jwk.try_ec_params().unwrap();

    if params.try_ec_curve().unwrap() != EcCurve::Secp256K1 {
      panic!("expected a Secp256K1 curve");
    }

    let sk_bytes = params.d.as_ref().map(jwu::decode_b64).unwrap().unwrap();
    SecretKey::from_slice(&sk_bytes).unwrap()
  }

  pub(crate) fn sign(message: &[u8], private_key: &Jwk) -> impl AsRef<[u8]> {
    let sk: SecretKey = expand_k256_jwk(private_key);
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
fn test_es256k_verifier() {
  let tv_header: &str = r#"{
    "typ": "JWT",
    "alg":"ES256K"
  }"#;
  let tv_private_key: &str = r#"
  {
    "kty":"EC",
    "crv":"secp256k1",
    "d":"y0zUV7bLeUG_kDOvACFHnSmtH7j8MSJek25R2wJbWWg",
    "x":"BBobbZkiC8E4C4EYekPNJkcXFCsMNHhh0AV2USy_xSs",
    "y":"VQcPHjIQClX0b5TLluFl6jpIf9U-norWC0oEvIQRNyU"
  }"#;
  let tv_claims: &[u8] = br#"{"key":"value"}"#;

  let header: JwsHeader = serde_json::from_str(tv_header).unwrap();
  let jwk: Jwk = serde_json::from_str(tv_private_key).unwrap();
  let encoder: jws::CompactJwsEncoder<'_> = jws::CompactJwsEncoder::new(tv_claims, &header).unwrap();
  let signing_input: &[u8] = encoder.signing_input();
  let encoded: String = {
    let signature = es256k1::sign(signing_input, &jwk);
    encoder.into_jws(signature.as_ref())
  };

  let jws_verifier = EcDSAJwsVerifier::default();
  let jwk: Jwk = serde_json::from_str(tv_private_key).unwrap();
  let decoder = jws::Decoder::new();
  assert!(decoder
    .decode_compact_serialization(encoded.as_bytes(), None)
    .and_then(|decoded| decoded.verify(&jws_verifier, &jwk))
    .is_ok());
}

/// In the absence of official test vectors for secp256k1,
/// this ensures we can verify JWTs created by other libraries.
mod test_es256k_josekit {
  use identity_verification::jws;
  use josekit::jwk::alg::ec::EcKeyPair;
  use josekit::jwk::Jwk;
  use josekit::jws::JwsHeader;
  use josekit::jwt::JwtPayload;

  use crate::EcDSAJwsVerifier;

  #[test]
  fn test_es256k_josekit() {
    let alg = josekit::jws::ES256K;

    let private_key: &str = r#"
    {
      "kty":"EC",
      "crv":"secp256k1",
      "d":"y0zUV7bLeUG_kDOvACFHnSmtH7j8MSJek25R2wJbWWg",
      "x":"BBobbZkiC8E4C4EYekPNJkcXFCsMNHhh0AV2USy_xSs",
      "y":"VQcPHjIQClX0b5TLluFl6jpIf9U-norWC0oEvIQRNyU"
    }"#;
    let josekit_jwk: Jwk = serde_json::from_str(private_key).unwrap();
    let mut src_header = JwsHeader::new();
    src_header.set_token_type("JWT");
    let mut src_payload = JwtPayload::new();
    src_payload.set_claim("key", Some("value".into())).unwrap();
    let eckp = EcKeyPair::from_jwk(&josekit_jwk).unwrap();
    let signer = alg.signer_from_jwk(&eckp.to_jwk_key_pair()).unwrap();
    let jwt_string = josekit::jwt::encode_with_signer(&src_payload, &src_header, &signer).unwrap();

    let jws_verifier = EcDSAJwsVerifier::default();
    let decoder = jws::Decoder::new();
    let jwk: identity_verification::jwk::Jwk = serde_json::from_str(private_key).unwrap();
    assert!(decoder
      .decode_compact_serialization(jwt_string.as_bytes(), None)
      .and_then(|decoded| decoded.verify(&jws_verifier, &jwk))
      .is_ok());
  }
}
