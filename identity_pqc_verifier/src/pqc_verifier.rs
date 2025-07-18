// Copyright 2020-2025 IOTA Stiftung, Fondazione Links
// SPDX-License-Identifier: Apache-2.0

use identity_jose::jwk::Jwk;
use identity_jose::jws::JwsAlgorithm;
use identity_jose::jws::JwsVerifier;
use identity_jose::jws::SignatureVerificationError;
use identity_jose::jws::SignatureVerificationErrorKind;
use identity_jose::jws::VerificationInput;
use oqs::sig::Algorithm;

use crate::OQSVerifier;

/// An implementor of [`JwsVerifier`] that can handle the
/// [`JwsAlgorithm::ML_DSA_44`](identity_jose::jws::JwsAlgorithm::ML_DSA_44)
/// | [`JwsAlgorithm::ML_DSA_65`](identity_jose::jws::JwsAlgorithm::ML_DSA_65)
/// | [`JwsAlgorithm::ML_DSA_87`](identity_jose::jws::JwsAlgorithm::ML_DSA_87)
/// | [`JwsAlgorithm::IdMldsa44Ed25519`](identity_jose::jws::JwsAlgorithm::IdMldsa44Ed25519)
/// | [`JwsAlgorithm::IdMldsa65Ed25519`](identity_jose::jws::JwsAlgorithm::IdMldsa65Ed25519) algorithms.
#[derive(Debug)]
#[non_exhaustive]
pub struct PQCJwsVerifier;

impl Default for PQCJwsVerifier {
  /// Constructs an [`PQCJwsVerifier`]. This is the only way to obtain an [`PQCJwsVerifier`].
  fn default() -> Self {
    Self
  }
}

impl JwsVerifier for PQCJwsVerifier {
  /// This implements verification of JWS signatures signed with the
  /// [`JwsAlgorithm::ML_DSA_44`](identity_jose::jws::JwsAlgorithm::ML_DSA_44)
  /// | [`JwsAlgorithm::ML_DSA_65`](identity_jose::jws::JwsAlgorithm::ML_DSA_65)
  /// | [`JwsAlgorithm::ML_DSA_87`](identity_jose::jws::JwsAlgorithm::ML_DSA_87)
  /// | [`JwsAlgorithm::IdMldsa44Ed25519`](identity_jose::jws::JwsAlgorithm::IdMldsa44Ed25519)
  /// | [`JwsAlgorithm::IdMldsa65Ed25519`](identity_jose::jws::JwsAlgorithm::IdMldsa65Ed25519) algorithms.
  // Allow unused variables in case of no-default-features.
  #[allow(unused_variables)]
  fn verify(&self, input: VerificationInput, public_key: &Jwk) -> std::result::Result<(), SignatureVerificationError> {
    match input.alg {
      JwsAlgorithm::ML_DSA_44 => OQSVerifier::verify(input, public_key, Algorithm::MlDsa44),
      JwsAlgorithm::ML_DSA_65 => OQSVerifier::verify(input, public_key, Algorithm::MlDsa65),
      JwsAlgorithm::ML_DSA_87 => OQSVerifier::verify(input, public_key, Algorithm::MlDsa87),
      JwsAlgorithm::IdMldsa44Ed25519 => OQSVerifier::verify_hybrid_signature(input, public_key, Algorithm::MlDsa44),
      JwsAlgorithm::IdMldsa65Ed25519 => OQSVerifier::verify_hybrid_signature(input, public_key, Algorithm::MlDsa65),

      _ => Err(SignatureVerificationErrorKind::UnsupportedAlg.into()),
    }
  }
}
