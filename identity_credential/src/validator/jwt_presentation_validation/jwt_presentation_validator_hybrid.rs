// Copyright 2024 Fondazione Links
// SPDX-License-Identifier: Apache-2.0

use identity_core::common::Object;
use identity_core::common::Timestamp;
use identity_core::common::Url;
use identity_core::convert::FromJson;
use identity_did::CoreDID;
use identity_document::document::CoreDocument;
use identity_verification::jws::DecodedJws;
use identity_verification::jws::JwsVerifier;
use std::str::FromStr;

use crate::credential::Jwt;
use crate::presentation::Presentation;
use crate::presentation::PresentationJwtClaims;
use crate::validator::jwt_credential_validation::JwtValidationError;
use crate::validator::jwt_credential_validation::SignerContext;

use super::CompoundJwtPresentationValidationError;
use super::DecodedJwtPresentation;
use super::JwtPresentationValidationOptions;

/// Struct for validating [`Presentation`] signed with a PQ/T signature.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct JwtPresentationValidatorHybrid<TRV: JwsVerifier, PQV: JwsVerifier>(TRV, PQV);

impl<TRV, PQV> JwtPresentationValidatorHybrid<TRV, PQV>
where
  TRV: JwsVerifier,
  PQV: JwsVerifier,
{
  /// Creates a new [`JwtPresentationValidatorHybrid`] using a specific traditional [`JwsVerifier`] and a specific PQ [`JwsVerifier`].
  pub fn with_signature_verifiers(traditional_signature_verifier: TRV, pq_signature_verifier: PQV) -> Self {
    Self(traditional_signature_verifier, pq_signature_verifier)
  }

  /// Validates a [`Presentation`] signed with a PQ/T signature.
  ///
  /// The following properties are validated according to `options`:
  /// - the JWT can be decoded into a semantically valid presentation.
  /// - the expiration and issuance date contained in the JWT claims.
  /// - the holder's PQ/T signature.
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
    T: Clone + serde::Serialize + serde::de::DeserializeOwned,
    CRED: Clone + serde::Serialize + serde::de::DeserializeOwned + Clone,
  {
    // Verify JWS.
    let decoded_jws: DecodedJws<'_> = holder
      .as_ref()
      .verify_jws_hybrid(
        presentation.as_str(),
        None,
        &self.0,
        &self.1,
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

    if expiration_date.is_some_and(|exp| exp < options.earliest_expiry_date.unwrap_or_default()) {
      return Err(CompoundJwtPresentationValidationError::one_presentation_error(
        JwtValidationError::ExpirationDate,
      ));
    }
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

    if issuance_date.is_some_and(|iss| iss > options.latest_issuance_date.unwrap_or_default()){
      return Err(CompoundJwtPresentationValidationError::one_presentation_error(
        JwtValidationError::IssuanceDate,
      ));
    }

    let aud: Option<Url> = claims.aud.clone();
    let custom_claims: Option<Object> = claims.custom.clone();

    let presentation: Presentation<CRED, T> = claims.try_into_presentation().map_err(|err| {
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
