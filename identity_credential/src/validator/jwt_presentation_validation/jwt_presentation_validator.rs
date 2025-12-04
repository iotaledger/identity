// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_core::common::Timestamp;
use identity_core::convert::FromJson;
use identity_did::CoreDID;
use identity_document::document::CoreDocument;
use identity_verification::jws::DecodedJws;
use identity_verification::jws::JwsVerifier;
use std::str::FromStr;

use crate::credential::Jwt;
use crate::presentation::JwtPresentationV2Claims;
use crate::presentation::PresentationJwtClaims;
use crate::validator::jwt_credential_validation::JwtValidationError;
use crate::validator::jwt_credential_validation::SignerContext;

use super::CompoundJwtPresentationValidationError;
use super::DecodedJwtPresentation;
use super::JwtPresentationValidationOptions;

/// Struct for validating [`Presentation`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct JwtPresentationValidator<V: JwsVerifier>(V);

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
  ///   credentials' subjects and the presentation holder. This can be done with
  ///   [`JwtCredentialValidationOptions`](crate::validator::JwtCredentialValidationOptions).
  /// * The lack of an error returned from this method is in of itself not enough to conclude that the presentation can
  ///   be trusted. This section contains more information on additional checks that should be carried out before and
  ///   after calling this method.
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

    // Try V2 first.
    if let Ok(JwtPresentationV2Claims { vp, aud, iat, exp }) = serde_json::from_slice(&decoded_jws.claims) {
      check_holder(vp.holder.as_str(), holder.as_ref())?;

      return Ok(DecodedJwtPresentation {
        presentation: vp,
        header: Box::new(decoded_jws.protected),
        expiration_date: convert_and_check_exp(exp, options.earliest_expiry_date)?,
        issuance_date: convert_and_check_iat(iat, options.latest_issuance_date)?,
        aud,
        custom_claims: None,
      });
    }

    // Fallback to V1.1
    let mut claims: PresentationJwtClaims<'_, CRED, T> = PresentationJwtClaims::from_json_slice(&decoded_jws.claims)
      .map_err(|err| {
        CompoundJwtPresentationValidationError::one_presentation_error(JwtValidationError::PresentationStructure(
          crate::Error::JwtClaimsSetDeserializationError(err.into()),
        ))
      })?;

    check_holder(claims.iss.as_str(), holder.as_ref())?;
    let expiration_date = convert_and_check_exp(claims.exp, options.earliest_expiry_date)?;
    let issuance_date = claims.issuance_date.and_then(|id| id.to_issuance_date().ok());
    if issuance_date > options.latest_issuance_date {
      return Err(CompoundJwtPresentationValidationError::one_presentation_error(
        JwtValidationError::IssuanceDate,
      ));
    }

    let aud = claims.aud.take();
    let custom_claims = claims.custom.take();

    let presentation = claims.try_into_presentation().map_err(|err| {
      CompoundJwtPresentationValidationError::one_presentation_error(JwtValidationError::PresentationStructure(err))
    })?;

    let decoded_jwt_presentation: DecodedJwtPresentation<CRED, T> = DecodedJwtPresentation {
      presentation,
      header: Box::new(decoded_jws.protected),
      expiration_date,
      issuance_date,
      aud,
      custom_claims,
    };

    Ok(decoded_jwt_presentation)
  }
}

fn check_holder(holder: &str, holder_doc: &CoreDocument) -> Result<(), CompoundJwtPresentationValidationError> {
  let holder_did: CoreDID = CoreDID::from_str(holder).map_err(|err| {
    CompoundJwtPresentationValidationError::one_presentation_error(JwtValidationError::SignerUrl {
      signer_ctx: SignerContext::Holder,
      source: err.into(),
    })
  })?;

  if &holder_did != <CoreDocument>::id(holder_doc) {
    Err(CompoundJwtPresentationValidationError::one_presentation_error(
      JwtValidationError::DocumentMismatch(SignerContext::Holder),
    ))
  } else {
    Ok(())
  }
}

fn convert_and_check_exp(
  exp: Option<i64>,
  earliest_expiry_date: Option<Timestamp>,
) -> Result<Option<Timestamp>, CompoundJwtPresentationValidationError> {
  let Some(exp) = exp else {
    return Ok(None);
  };
  let exp = Timestamp::from_unix(exp).map_err(|e| {
    CompoundJwtPresentationValidationError::one_presentation_error(JwtValidationError::PresentationStructure(
      crate::Error::JwtClaimsSetDeserializationError(e.into()),
    ))
  })?;

  if exp >= earliest_expiry_date.unwrap_or_else(Timestamp::now_utc) {
    Ok(Some(exp))
  } else {
    Err(CompoundJwtPresentationValidationError::one_presentation_error(
      JwtValidationError::ExpirationDate,
    ))
  }
}

fn convert_and_check_iat(
  iat: Option<i64>,
  latest_issuance_date: Option<Timestamp>,
) -> Result<Option<Timestamp>, CompoundJwtPresentationValidationError> {
  let Some(iat) = iat else {
    return Ok(None);
  };
  let iat = Timestamp::from_unix(iat).map_err(|e| {
    CompoundJwtPresentationValidationError::one_presentation_error(JwtValidationError::PresentationStructure(
      crate::Error::JwtClaimsSetDeserializationError(e.into()),
    ))
  })?;

  if iat <= latest_issuance_date.unwrap_or_else(Timestamp::now_utc) {
    Ok(Some(iat))
  } else {
    Err(CompoundJwtPresentationValidationError::one_presentation_error(
      JwtValidationError::IssuanceDate,
    ))
  }
}
