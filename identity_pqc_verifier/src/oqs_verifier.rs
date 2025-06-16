// Copyright 2024 Fondazione Links
// SPDX-License-Identifier: Apache-2.0

use identity_jose::jwk::CompositeAlgId;
use identity_jose::jwk::Jwk;
use identity_jose::jwk::JwkParamsAkp;
use identity_jose::jws::SignatureVerificationError;
use identity_jose::jws::SignatureVerificationErrorKind;
use identity_jose::jws::VerificationInput;
use oqs::sig::Algorithm;
use oqs::sig::Sig;
use std::ops::Deref;

/// A verifier that can handle the [`Algorithm`] PQC algorithms.
#[derive(Debug)]
#[non_exhaustive]
pub struct OQSVerifier;

impl OQSVerifier {
  /// Verify a JWS signature secured with the [`Algorithm`] defined in liboqs.
  pub fn verify(input: VerificationInput, public_key: &Jwk, alg: Algorithm) -> Result<(), SignatureVerificationError> {
    
    let params: &JwkParamsAkp = public_key
      .try_akp_params()
      .map_err(|_| SignatureVerificationErrorKind::UnsupportedKeyType)?;

    let pk = identity_jose::jwu::decode_b64(params.public.as_str()).map_err(|_| {
      SignatureVerificationError::new(SignatureVerificationErrorKind::KeyDecodingFailure)
        .with_custom_message("could not decode 'pub' parameter from jwk")
    })?;

    oqs::init();

    let scheme = Sig::new(alg).map_err(|_| {
      SignatureVerificationError::new(SignatureVerificationErrorKind::Unspecified)
        .with_custom_message("signature scheme init failed")
    })?;

    let public_key = scheme
      .public_key_from_bytes(&pk)
      .ok_or(SignatureVerificationError::new(
        SignatureVerificationErrorKind::KeyDecodingFailure,
      ))?;

    let signature = scheme
      .signature_from_bytes(input.decoded_signature.deref())
      .ok_or(SignatureVerificationErrorKind::InvalidSignature)?;

    Ok(
      scheme
        .verify(&input.signing_input, signature, public_key)
        .map_err(|_| SignatureVerificationErrorKind::InvalidSignature)?,
    )
  }

    /// Verify a JWS signature signed with a ctx and secured with the [`Algorithm`] defined in liboqs, used in hybrid signature.
    /// The ctx value is set as the Domain separator value for binding the signature to the Composite OID.
    pub fn verify_hybrid_signature(input: VerificationInput, public_key: &Jwk, alg: Algorithm) -> Result<(), SignatureVerificationError> {
      
      let params: &JwkParamsAkp = public_key
        .try_akp_params()
        .map_err(|_| SignatureVerificationErrorKind::UnsupportedKeyType)?;
  
      let pk = identity_jose::jwu::decode_b64(params.public.as_str()).map_err(|_| {
        SignatureVerificationError::new(SignatureVerificationErrorKind::KeyDecodingFailure)
          .with_custom_message("could not decode 'pub' parameter from jwk")
      })?;
  
      oqs::init();
  
      let scheme = Sig::new(alg).map_err(|_| {
        SignatureVerificationError::new(SignatureVerificationErrorKind::Unspecified)
          .with_custom_message("signature scheme init failed")
      })?;
  
      let public_key = scheme
        .public_key_from_bytes(&pk)
        .ok_or(SignatureVerificationError::new(
          SignatureVerificationErrorKind::KeyDecodingFailure,
        ))?;
  
      let signature = scheme
        .signature_from_bytes(input.decoded_signature.deref())
        .ok_or(SignatureVerificationErrorKind::InvalidSignature)?;

      let ctx = match  alg {
        Algorithm::MlDsa44 => CompositeAlgId::IdMldsa44Ed25519.domain(),
        Algorithm::MlDsa65 => CompositeAlgId::IdMldsa65Ed25519.domain(),
        _ => return Err(SignatureVerificationError::new(SignatureVerificationErrorKind::UnsupportedKeyType)),
      };
  
      Ok(
        scheme
          .verify_with_ctx_str(&input.signing_input, signature, ctx, public_key)
          .map_err(|_| SignatureVerificationErrorKind::InvalidSignature)?,
      )
    }
}

#[cfg(test)]
mod tests {
    use oqs::sig::{Algorithm, Sig};
 
  #[test]
  fn test_sig_and_verify(){
    oqs::init();
    let scheme = Sig::new(Algorithm::MlDsa44).unwrap();
    let (pk, sk) = scheme.keypair().unwrap();
    let message = b"test_message";
    let signature = scheme.sign(message, &sk).unwrap();
    assert!(scheme.verify(message, &signature, &pk).is_ok());
  }

  #[test]
  fn test_sig_and_invalid_verify(){
    oqs::init();
    let scheme = Sig::new(Algorithm::MlDsa87).unwrap();
    let (pk, sk) = scheme.keypair().unwrap();
    let message = b"test_message";
    let wrong_message = b"wrong_message";
    let signature = scheme.sign(message, &sk).unwrap();
    assert!(scheme.verify(wrong_message, &signature, &pk).is_err());
  }
}
 
