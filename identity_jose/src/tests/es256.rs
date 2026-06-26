// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::ops::Deref;

use crate::jwk::EcCurve;
use crate::jwk::Jwk;
use crate::jwk::JwkParamsEc;
use crate::jws::SignatureVerificationError;
use crate::jws::SignatureVerificationErrorKind;
use crate::jws::VerificationInput;
use crate::jwu;
use p256::ecdsa::Signature;
use p256::ecdsa::SigningKey;
use p256::ecdsa::VerifyingKey;
use p256::PublicKey;
use p256::SecretKey;

pub(crate) fn expand_p256_jwk(jwk: &Jwk) -> (SecretKey, PublicKey) {
  let params: &JwkParamsEc = jwk.try_ec_params().unwrap();

  if params.try_ec_curve().unwrap() != EcCurve::P256 {
    panic!("expected a P256 curve");
  }

  let sk_bytes = params.d.as_ref().map(jwu::decode_b64).unwrap().unwrap();
  let sk = SecretKey::from_slice(&sk_bytes).unwrap();

  // Transformation according to section 2.3.3 from http://www.secg.org/sec1-v2.pdf.
  let pk_bytes: Vec<u8> = [0x04]
    .into_iter()
    .chain(jwu::decode_b64(&params.x).unwrap())
    .chain(jwu::decode_b64(&params.y).unwrap())
    .collect();

  let pk = PublicKey::from_sec1_bytes(&pk_bytes).unwrap();

  assert_eq!(sk.public_key(), pk);

  (sk, pk)
}

pub(crate) fn sign(message: &[u8], private_key: &Jwk) -> impl AsRef<[u8]> {
  let (sk, _): (SecretKey, PublicKey) = expand_p256_jwk(private_key);
  let signing_key: SigningKey = SigningKey::from(sk);
  let signature: Signature = signature::Signer::sign(&signing_key, message);
  signature.to_bytes()
}

pub(crate) fn verify(verification_input: VerificationInput, jwk: &Jwk) -> Result<(), SignatureVerificationError> {
  let (_, public_key) = expand_p256_jwk(jwk);
  let verifying_key = VerifyingKey::from(public_key);

  let signature = Signature::try_from(verification_input.decoded_signature.deref()).unwrap();

  match signature::Verifier::verify(&verifying_key, &verification_input.signing_input, &signature) {
    Ok(()) => Ok(()),
    Err(err) => Err(SignatureVerificationError::new(SignatureVerificationErrorKind::InvalidSignature).with_source(err)),
  }
}
