// Copyright 2020-2024 IOTA Stiftung, Filancore GmbH
// SPDX-License-Identifier: Apache-2.0

use std::ops::Deref;

use identity_verification::jwk::JwkParamsEc;
use identity_verification::jws::SignatureVerificationError;
use identity_verification::jws::SignatureVerificationErrorKind;
use identity_verification::jwu::{self};
use p256::ecdsa::Signature;
use p256::ecdsa::VerifyingKey;
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::elliptic_curve::subtle::CtOption;
use p256::EncodedPoint;
use p256::PublicKey;

/// A verifier that can handle the
/// [`JwsAlgorithm::ES256`](identity_verification::jws::JwsAlgorithm::ES256)
/// algorithm.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct Secp256R1Verifier {}

impl Secp256R1Verifier {
  /// Verify a JWS signature secured with the
  /// [`JwsAlgorithm::ES256`](identity_verification::jws::JwsAlgorithm::ES256)
  /// algorithm.
  ///
  /// This function is useful when one is building a
  /// [`JwsVerifier`](identity_verification::jws::JwsVerifier) that
  /// handles the
  /// [`JwsAlgorithm::ES256`](identity_verification::jws::JwsAlgorithm::ES256)
  /// in the same manner as the [`Secp256R1Verifier`] hence extending its
  /// capabilities.
  ///
  /// # Warning
  ///
  /// This function does not check whether `alg = ES256` in the protected
  /// header. Callers are expected to assert this prior to calling the
  /// function.
  pub fn verify(
    input: &identity_verification::jws::VerificationInput,
    public_key: &identity_verification::jwk::Jwk,
  ) -> Result<(), SignatureVerificationError> {
    // Obtain a P256 public key.
    let params: &JwkParamsEc = public_key
      .try_ec_params()
      .map_err(|_| SignatureVerificationErrorKind::UnsupportedKeyType)?;

    // Concatenate x and y coordinates as required by
    // EncodedPoint::from_untagged_bytes.
    let public_key_bytes = jwu::decode_b64(&params.x)
      .map_err(|err| {
        SignatureVerificationError::new(SignatureVerificationErrorKind::KeyDecodingFailure).with_source(err)
      })?
      .into_iter()
      .chain(jwu::decode_b64(&params.y).map_err(|err| {
        SignatureVerificationError::new(SignatureVerificationErrorKind::KeyDecodingFailure).with_source(err)
      })?)
      .collect();

    // The JWK contains the uncompressed x and y coordinates, so we can create the
    // encoded point directly without prefixing an SEC1 tag.
    let encoded_point: EncodedPoint = EncodedPoint::from_untagged_bytes(&public_key_bytes);
    let public_key: PublicKey = {
      let opt_public_key: CtOption<PublicKey> = PublicKey::from_encoded_point(&encoded_point);
      if opt_public_key.is_none().into() {
        return Err(SignatureVerificationError::new(
          SignatureVerificationErrorKind::KeyDecodingFailure,
        ));
      } else {
        opt_public_key.unwrap()
      }
    };

    let verifying_key: VerifyingKey = VerifyingKey::from(public_key);

    let signature: Signature = Signature::try_from(input.decoded_signature.deref()).map_err(|err| {
      SignatureVerificationError::new(SignatureVerificationErrorKind::InvalidSignature).with_source(err)
    })?;

    match signature::Verifier::verify(&verifying_key, &input.signing_input, &signature) {
      Ok(()) => Ok(()),
      Err(err) => {
        Err(SignatureVerificationError::new(SignatureVerificationErrorKind::InvalidSignature).with_source(err))
      }
    }
  }
}
