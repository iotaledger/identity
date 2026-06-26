// Copyright 2020-2024 IOTA Stiftung, Filancore GmbH
// SPDX-License-Identifier: Apache-2.0

use identity_verification::jws::JwsAlgorithm;
use identity_verification::jws::JwsVerifier;
use identity_verification::jws::SignatureVerificationErrorKind;

/// An implementor of [`JwsVerifier`](identity_verification::jws::JwsVerifier)
/// that can handle a selection of EcDSA algorithms.
///
/// The following algorithms are supported, if the respective feature on the
/// crate is activated:
///
/// - [`JwsAlgorithm::ES256`](identity_verification::jws::JwsAlgorithm::ES256).
/// - [`JwsAlgorithm::ES256K`](identity_verification::jws::JwsAlgorithm::ES256K).
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct EcDSAJwsVerifier {}

impl JwsVerifier for EcDSAJwsVerifier {
  fn verify(
    &self,
    input: identity_verification::jws::VerificationInput,
    public_key: &identity_verification::jwk::Jwk,
  ) -> Result<(), identity_verification::jws::SignatureVerificationError> {
    match input.alg {
      #[cfg(feature = "es256")]
      JwsAlgorithm::ES256 => crate::Secp256R1Verifier::verify(&input, public_key),
      #[cfg(feature = "es256k")]
      JwsAlgorithm::ES256K => crate::Secp256K1Verifier::verify(&input, public_key),
      _ => Err(SignatureVerificationErrorKind::UnsupportedAlg.into()),
    }
  }
}
