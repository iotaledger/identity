// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_core::common::Object;
use identity_core::convert::FromJson;
use identity_did::DID;
use identity_verification::jws::Decoder;
use serde_json::Value;
use std::str::FromStr;

use crate::credential::Jwt;
use crate::presentation::JwtPresentationV2Claims;
use crate::presentation::Presentation;
use crate::presentation::PresentationJwtClaims;
use crate::validator::jwt_credential_validation::JwtValidationError;
use crate::validator::jwt_credential_validation::SignerContext;

/// Utility functions for verifying JWT presentations.
#[non_exhaustive]
pub struct JwtPresentationValidatorUtils;

impl JwtPresentationValidatorUtils {
  /// Attempt to extract the holder of the presentation.
  ///
  /// # Errors:
  /// * If deserialization/decoding of the presentation fails.
  /// * If the holder can't be parsed as DIDs.
  pub fn extract_holder<H: DID>(presentation: &Jwt) -> std::result::Result<H, JwtValidationError>
  where
    <H as FromStr>::Err: std::error::Error + Send + Sync + 'static,
  {
    let validation_item = Decoder::new()
      .decode_compact_serialization(presentation.as_str().as_bytes(), None)
      .map_err(JwtValidationError::JwsDecodingError)?;

    // Try V1 first.
    let maybe_holder =
      if let Ok(claims) = PresentationJwtClaims::<Value, Object>::from_json_slice(&validation_item.claims()) {
        H::from_str(claims.iss.as_str())
      } else if let Ok(claims) = JwtPresentationV2Claims::<Value, Object>::from_json_slice(&validation_item.claims()) {
        H::from_str(claims.vp.holder.as_str())
      } else {
        return Err(JwtValidationError::PresentationStructure(
          crate::error::Error::JwtClaimsSetDeserializationError(
            "Failed to deserialize JWT presentation claims to either a v1 or v2 Verifiable Presentation".into(),
          ),
        ));
      };

    maybe_holder.map_err(|err| JwtValidationError::SignerUrl {
      signer_ctx: SignerContext::Holder,
      source: err.into(),
    })
  }

  /// Validates the semantic structure of the `Presentation`.
  pub fn check_structure<U>(presentation: &Presentation<U>) -> Result<(), JwtValidationError> {
    presentation
      .check_structure()
      .map_err(JwtValidationError::PresentationStructure)
  }
}
