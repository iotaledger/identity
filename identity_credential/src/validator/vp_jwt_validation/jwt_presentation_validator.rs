// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_core::common::Object;
use identity_core::common::Timestamp;
use identity_core::common::Url;
use identity_core::convert::FromJson;
use identity_did::CoreDID;
use identity_did::DID;
use identity_document::document::CoreDocument;
use identity_verification::jws::DecodedJws;
use identity_verification::jws::Decoder;
use identity_verification::jws::EdDSAJwsVerifier;
use identity_verification::jws::JwsVerifier;
use std::str::FromStr;

use crate::credential::Jwt;
use crate::presentation::Presentation;
use crate::presentation::PresentationJwtClaims;
use crate::validator::vc_jwt_validation::JwtValidationError;
use crate::validator::vc_jwt_validation::SignerContext;

use super::CompoundJwtPresentationValidationError;
use super::DecodedJwtPresentation;
use super::JwtPresentationValidationOptions;

/// Struct for validating [`Presentation`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct JwtPresentationValidator<V: JwsVerifier = EdDSAJwsVerifier>(V);

impl JwtPresentationValidator {
  /// Creates a new [`JwtPresentationValidator`].
  pub fn new() -> Self {
    Self(EdDSAJwsVerifier::default())
  }
}
impl Default for JwtPresentationValidator {
  fn default() -> Self {
    Self::new()
  }
}

impl<V> JwtPresentationValidator<V>
where
  V: JwsVerifier,
{
  /// Creates a new [`JwtPresentationValidator`] using a specific [`JwsVerifier`].
  pub fn with_signature_verifier(signature_verifier: V) -> Self {
    Self(signature_verifier)
  }

  /// Validates a [`Presentation`].
  ///
  /// The following properties are validated according to `options`:
  /// - the JWT can be decoded into a semantically valid presentation.
  /// - the expiration and issuance date contained in the JWT claims.
  /// - the holder's signature.
  ///
  /// Validation is done with respect to the properties set in `options`.
  ///
  /// # Warning
  ///
  /// * This method does NOT validate the constituent credentials and therefore also not the relationship between the
  /// credentials' subjects and the presentation holder. This can be done with
  /// [`JwtCredentialValidationOptions`](crate::validator::JwtCredentialValidationOptions).
  /// * The lack of an error returned from this method is in of itself not enough to conclude that the presentation can
  /// be trusted. This section contains more information on additional checks that should be carried out before and
  /// after calling this method.
  ///
  /// ## The state of the supplied DID Documents.
  ///
  /// The caller must ensure that the DID Documents in `holder` and `issuers` are up-to-date.
  ///
  /// # Errors
  ///
  /// An error is returned whenever a validated condition is not satisfied or when decoding fails.
  pub fn validate<HDOC, CRED, T>(
    &self,
    presentation: &Jwt,
    holder: &HDOC,
    options: &JwtPresentationValidationOptions,
  ) -> Result<DecodedJwtPresentation<CRED, T>, CompoundJwtPresentationValidationError>
  where
    HDOC: AsRef<CoreDocument> + ?Sized,
    T: ToOwned<Owned = T> + serde::Serialize + serde::de::DeserializeOwned,
    CRED: ToOwned<Owned = CRED> + serde::Serialize + serde::de::DeserializeOwned + Clone,
  {
    // Verify JWS.
    let decoded_jws: DecodedJws<'_> = holder
      .as_ref()
      .verify_jws(
        presentation.as_str(),
        None,
        &self.0,
        &options.presentation_verifier_options,
      )
      .map_err(|err| {
        CompoundJwtPresentationValidationError::one_presentation_error(JwtValidationError::PresentationJwsError(err))
      })?;

    let claims: PresentationJwtClaims<'_, CRED, T> = PresentationJwtClaims::from_json_slice(&decoded_jws.claims)
      .map_err(|err| {
        CompoundJwtPresentationValidationError::one_presentation_error(JwtValidationError::PresentationStructure(
          crate::Error::JwtClaimsSetDeserializationError(err.into()),
        ))
      })?;

    // Verify that holder document matches holder in presentation.
    let holder_did: CoreDID = CoreDID::from_str(claims.iss.as_str()).map_err(|err| {
      CompoundJwtPresentationValidationError::one_presentation_error(JwtValidationError::SignerUrl {
        signer_ctx: SignerContext::Holder,
        source: err.into(),
      })
    })?;

    if &holder_did != <CoreDocument>::id(holder.as_ref()) {
      return Err(CompoundJwtPresentationValidationError::one_presentation_error(
        JwtValidationError::DocumentMismatch(SignerContext::Holder),
      ));
    }

    // Check the expiration date.
    let expiration_date: Option<Timestamp> = claims
      .exp
      .map(|exp| {
        Timestamp::from_unix(exp).map_err(|err| {
          CompoundJwtPresentationValidationError::one_presentation_error(JwtValidationError::PresentationStructure(
            crate::Error::JwtClaimsSetDeserializationError(err.into()),
          ))
        })
      })
      .transpose()?;

    (expiration_date.is_none() || expiration_date >= Some(options.earliest_expiry_date.unwrap_or_default()))
      .then_some(())
      .ok_or(CompoundJwtPresentationValidationError::one_presentation_error(
        JwtValidationError::ExpirationDate,
      ))?;

    // Check issuance date.
    let issuance_date: Option<Timestamp> = match claims.issuance_date {
      Some(iss) => {
        if iss.iat.is_some() || iss.nbf.is_some() {
          Some(iss.to_issuance_date().map_err(|err| {
            CompoundJwtPresentationValidationError::one_presentation_error(JwtValidationError::PresentationStructure(
              crate::Error::JwtClaimsSetDeserializationError(err.into()),
            ))
          })?)
        } else {
          None
        }
      }
      None => None,
    };

    (issuance_date.is_none() || issuance_date <= Some(options.latest_issuance_date.unwrap_or_default()))
      .then_some(())
      .ok_or(CompoundJwtPresentationValidationError::one_presentation_error(
        JwtValidationError::IssuanceDate,
      ))?;

    let aud: Option<Url> = claims.aud.clone();

    let presentation: Presentation<CRED, T> = claims.try_into_presentation().map_err(|err| {
      CompoundJwtPresentationValidationError::one_presentation_error(JwtValidationError::PresentationStructure(err))
    })?;

    let decoded_jwt_presentation: DecodedJwtPresentation<CRED, T> = DecodedJwtPresentation {
      presentation,
      header: Box::new(decoded_jws.protected),
      expiration_date,
      issuance_date,
      aud,
    };

    Ok(decoded_jwt_presentation)
  }
}

impl JwtPresentationValidator {
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

    let claims: PresentationJwtClaims<'_, identity_core::common::Value, Object> =
      PresentationJwtClaims::from_json_slice(&validation_item.claims()).map_err(|err| {
        JwtValidationError::PresentationStructure(crate::Error::JwtClaimsSetDeserializationError(err.into()))
      })?;

    let holder: H = H::from_str(claims.iss.as_str()).map_err(|err| JwtValidationError::SignerUrl {
      signer_ctx: SignerContext::Holder,
      source: err.into(),
    })?;
    Ok(holder)
  }

  /// Validates the semantic structure of the `Presentation`.
  pub fn check_structure<U>(presentation: &Presentation<U>) -> Result<(), JwtValidationError> {
    presentation
      .check_structure()
      .map_err(JwtValidationError::PresentationStructure)
  }
}
