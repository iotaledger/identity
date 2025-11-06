// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr as _;

use identity_core::convert::FromJson;
use identity_did::CoreDID;
use identity_did::DIDUrl;
use identity_document::document::CoreDocument;
use identity_document::verifiable::JwsVerificationOptions;
use identity_verification::jwk::Jwk;
use identity_verification::jws::DecodedJws;
use identity_verification::jws::Decoder;
use identity_verification::jws::JwsValidationItem;
use identity_verification::jws::JwsVerifier;

use super::CompoundCredentialValidationError;
use super::DecodedJwtCredential;
use super::JwtCredentialValidationOptions;
use super::JwtCredentialValidatorUtils;
use super::JwtValidationError;
use super::SignerContext;
use crate::credential::Credential;
use crate::credential::CredentialJwtClaims;
use crate::credential::CredentialT;
use crate::credential::Jwt;
use crate::validator::DecodedJwtCredentialV2;
use crate::validator::FailFast;

/// A type for decoding and validating [`Credential`]s.
#[non_exhaustive]
pub struct JwtCredentialValidator<V: JwsVerifier>(V);

impl<V: JwsVerifier> JwtCredentialValidator<V> {
  /// Create a new [`JwtCredentialValidator`] that delegates cryptographic signature verification to the given
  /// `signature_verifier`.
  pub fn with_signature_verifier(signature_verifier: V) -> Self {
    Self(signature_verifier)
  }

  /// Decodes and validates a [`Credential`] issued as a JWT. A [`DecodedJwtCredential`] is returned upon success.
  ///
  /// The following properties are validated according to `options`:
  /// - the issuer's signature on the JWS,
  /// - the expiration date,
  /// - the issuance date,
  /// - the semantic structure.
  ///
  /// # Warning
  /// The lack of an error returned from this method is in of itself not enough to conclude that the credential can be
  /// trusted. This section contains more information on additional checks that should be carried out before and after
  /// calling this method.
  ///
  /// ## The state of the issuer's DID Document
  /// The caller must ensure that `issuer` represents an up-to-date DID Document.
  ///
  /// ## Properties that are not validated
  ///  There are many properties defined in [The Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/) that are **not** validated, such as:
  /// `proof`, `credentialStatus`, `type`, `credentialSchema`, `refreshService` **and more**.
  /// These should be manually checked after validation, according to your requirements.
  ///
  /// # Errors
  /// An error is returned whenever a validated condition is not satisfied.
  pub fn validate<DOC, T>(
    &self,
    credential_jwt: &Jwt,
    issuer: &DOC,
    options: &JwtCredentialValidationOptions,
    fail_fast: FailFast,
  ) -> Result<DecodedJwtCredential<T>, CompoundCredentialValidationError>
  where
    T: Clone + serde::Serialize + serde::de::DeserializeOwned,
    DOC: AsRef<CoreDocument>,
  {
    let credential_token = self
      .verify_signature(
        credential_jwt,
        std::slice::from_ref(issuer.as_ref()),
        &options.verification_options,
      )
      .map_err(|err| CompoundCredentialValidationError {
        validation_errors: [err].into(),
      })?;

    Self::validate_decoded_credential::<CoreDocument, T>(
      &credential_token.credential,
      std::slice::from_ref(issuer.as_ref()),
      options,
      fail_fast,
    )?;

    Ok(credential_token)
  }

  /// Decodes and validates a [CredentialV2](crate::credential::credential_v2::Credential) issued as a JWT.
  /// A [`DecodedJwtCredentialV2`] is returned upon success.
  ///
  /// The following properties are validated according to `options`:
  /// - the issuer's signature on the JWS,
  /// - the expiration date,
  /// - the issuance date,
  /// - the semantic structure.
  ///
  /// # Warning
  /// The lack of an error returned from this method is in of itself not enough to conclude that the credential can be
  /// trusted. This section contains more information on additional checks that should be carried out before and after
  /// calling this method.
  ///
  /// ## The state of the issuer's DID Document
  /// The caller must ensure that `issuer` represents an up-to-date DID Document.
  ///
  /// ## Properties that are not validated
  ///  There are many properties defined in [The Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/) that are **not** validated, such as:
  /// `proof`, `credentialStatus`, `type`, `credentialSchema`, `refreshService` **and more**.
  /// These should be manually checked after validation, according to your requirements.
  ///
  /// # Errors
  /// An error is returned whenever a validated condition is not satisfied.
  pub fn validate_v2<DOC, T>(
    &self,
    credential_jwt: &Jwt,
    issuer: &DOC,
    options: &JwtCredentialValidationOptions,
    fail_fast: FailFast,
  ) -> Result<DecodedJwtCredentialV2<T>, CompoundCredentialValidationError>
  where
    T: Clone + serde::Serialize + serde::de::DeserializeOwned,
    DOC: AsRef<CoreDocument>,
  {
    let credential_token = Self::verify_signature_with_verifier_v2(
      &self.0,
      credential_jwt,
      std::slice::from_ref(issuer.as_ref()),
      &options.verification_options,
    )
    .map_err(|err| CompoundCredentialValidationError {
      validation_errors: [err].into(),
    })?;

    Self::validate_decoded_credential(
      &credential_token.credential,
      std::slice::from_ref(issuer),
      options,
      fail_fast,
    )?;

    Ok(credential_token)
  }

  /// Decode and verify the JWS signature of a [`Credential`] issued as a JWT using the DID Document of a trusted
  /// issuer.
  ///
  /// A [`DecodedJwtCredential`] is returned upon success.
  ///
  /// # Warning
  /// The caller must ensure that the DID Documents of the trusted issuers are up-to-date.
  ///
  /// ## Proofs
  ///  Only the JWS signature is verified. If the [`Credential`] contains a `proof` property this will not be verified
  /// by this method.
  ///
  /// # Errors
  /// This method immediately returns an error if
  /// the credential issuer' url cannot be parsed to a DID belonging to one of the trusted issuers. Otherwise an attempt
  /// to verify the credential's signature will be made and an error is returned upon failure.
  pub fn verify_signature<DOC, T>(
    &self,
    credential: &Jwt,
    trusted_issuers: &[DOC],
    options: &JwsVerificationOptions,
  ) -> Result<DecodedJwtCredential<T>, JwtValidationError>
  where
    T: ToOwned<Owned = T> + serde::Serialize + serde::de::DeserializeOwned,
    DOC: AsRef<CoreDocument>,
  {
    Self::verify_signature_with_verifier(&self.0, credential, trusted_issuers, options)
  }

  /// Decode and verify the JWS signature of a [Credential](crate::credential::credential_v2::Credential) issued as a
  /// JWT using the DID Document of a trusted issuer.
  ///
  /// A [`DecodedJwtCredentialV2`] is returned upon success.
  ///
  /// # Warning
  /// The caller must ensure that the DID Documents of the trusted issuers are up-to-date.
  ///
  /// ## Proofs
  ///  Only the JWS signature is verified. If the [Credential](crate::credential::credential_v2::Credential) contains a
  /// `proof` property this will not be verified by this method.
  ///
  /// # Errors
  /// This method immediately returns an error if
  /// the credential issuer' url cannot be parsed to a DID belonging to one of the trusted issuers. Otherwise an attempt
  /// to verify the credential's signature will be made and an error is returned upon failure.
  pub fn verify_signature_v2<DOC, T>(
    &self,
    credential: &Jwt,
    trusted_issuers: &[DOC],
    options: &JwsVerificationOptions,
  ) -> Result<DecodedJwtCredentialV2<T>, JwtValidationError>
  where
    T: ToOwned<Owned = T> + serde::Serialize + serde::de::DeserializeOwned,
    DOC: AsRef<CoreDocument>,
  {
    Self::verify_signature_with_verifier_v2(&self.0, credential, trusted_issuers, options)
  }

  // This method takes a slice of issuer's instead of a single issuer in order to better accommodate presentation
  // validation. It also validates the relationship between a holder and the credential subjects when
  // `relationship_criterion` is Some.
  pub(crate) fn validate_decoded_credential<DOC, T>(
    credential: &dyn CredentialT<Properties = T>,
    issuers: &[DOC],
    options: &JwtCredentialValidationOptions,
    fail_fast: FailFast,
  ) -> Result<(), CompoundCredentialValidationError>
  where
    T: Clone + serde::Serialize + serde::de::DeserializeOwned,
    DOC: AsRef<CoreDocument>,
  {
    // Run all single concern Credential validations in turn and fail immediately if `fail_fast` is true.

    let expiry_date_validation = std::iter::once_with(|| {
      JwtCredentialValidatorUtils::check_expires_on_or_after(
        credential,
        options.earliest_expiry_date.unwrap_or_default(),
      )
    });

    let issuance_date_validation = std::iter::once_with(|| {
      JwtCredentialValidatorUtils::check_issued_on_or_before(
        credential,
        options.latest_issuance_date.unwrap_or_default(),
      )
    });

    let structure_validation = std::iter::once_with(|| JwtCredentialValidatorUtils::check_structure(credential));

    let subject_holder_validation = std::iter::once_with(|| {
      options
        .subject_holder_relationship
        .as_ref()
        .map(|(holder, relationship)| {
          JwtCredentialValidatorUtils::check_subject_holder_relationship(credential, holder, *relationship)
        })
        .unwrap_or(Ok(()))
    });

    let validation_units_iter = issuance_date_validation
      .chain(expiry_date_validation)
      .chain(structure_validation)
      .chain(subject_holder_validation);

    #[cfg(feature = "revocation-bitmap")]
    let validation_units_iter = {
      let revocation_validation =
        std::iter::once_with(|| JwtCredentialValidatorUtils::check_status(credential, issuers, options.status));
      validation_units_iter.chain(revocation_validation)
    };

    let validation_units_error_iter = validation_units_iter.filter_map(|result| result.err());
    let validation_errors: Vec<JwtValidationError> = match fail_fast {
      FailFast::FirstError => validation_units_error_iter.take(1).collect(),
      FailFast::AllErrors => validation_units_error_iter.collect(),
    };

    if validation_errors.is_empty() {
      Ok(())
    } else {
      Err(CompoundCredentialValidationError { validation_errors })
    }
  }

  pub(crate) fn parse_jwk<'a, 'i, DOC>(
    jws: &JwsValidationItem<'a>,
    trusted_issuers: &'i [DOC],
    options: &JwsVerificationOptions,
  ) -> Result<(&'a Jwk, DIDUrl), JwtValidationError>
  where
    DOC: AsRef<CoreDocument>,
    'i: 'a,
  {
    let nonce: Option<&str> = options.nonce.as_deref();
    // Validate the nonce
    if jws.nonce() != nonce {
      return Err(JwtValidationError::JwsDecodingError(
        identity_verification::jose::error::Error::InvalidParam("invalid nonce value"),
      ));
    }

    // If no method_url is set, parse the `kid` to a DID Url which should be the identifier
    // of a verification method in a trusted issuer's DID document.
    let method_id: DIDUrl =
      match &options.method_id {
        Some(method_id) => method_id.clone(),
        None => {
          let kid: &str = jws.protected_header().and_then(|header| header.kid()).ok_or(
            JwtValidationError::MethodDataLookupError {
              source: None,
              message: "could not extract kid from protected header",
              signer_ctx: SignerContext::Issuer,
            },
          )?;

          // Convert kid to DIDUrl
          DIDUrl::parse(kid).map_err(|err| JwtValidationError::MethodDataLookupError {
            source: Some(err.into()),
            message: "could not parse kid as a DID Url",
            signer_ctx: SignerContext::Issuer,
          })?
        }
      };

    // locate the corresponding issuer
    let issuer: &CoreDocument = trusted_issuers
      .iter()
      .map(AsRef::as_ref)
      .find(|issuer_doc| <CoreDocument>::id(issuer_doc) == method_id.did())
      .ok_or(JwtValidationError::DocumentMismatch(SignerContext::Issuer))?;

    // Obtain the public key from the issuer's DID document
    issuer
      .resolve_method(&method_id, options.method_scope)
      .and_then(|method| method.data().public_key_jwk())
      .ok_or_else(|| JwtValidationError::MethodDataLookupError {
        source: None,
        message: "could not extract JWK from a method identified by kid",
        signer_ctx: SignerContext::Issuer,
      })
      .map(move |jwk| (jwk, method_id))
  }

  /// Stateless version of [`Self::verify_signature`]
  fn verify_signature_with_verifier<DOC, S, T>(
    signature_verifier: &S,
    credential: &Jwt,
    trusted_issuers: &[DOC],
    options: &JwsVerificationOptions,
  ) -> Result<DecodedJwtCredential<T>, JwtValidationError>
  where
    T: ToOwned<Owned = T> + serde::Serialize + serde::de::DeserializeOwned,
    DOC: AsRef<CoreDocument>,
    S: JwsVerifier,
  {
    // Note the below steps are necessary because `CoreDocument::verify_jws` decodes the JWS and then searches for a
    // method with a fragment (or full DID Url) matching `kid` in the given document. We do not want to carry out
    // that process for potentially every document in `trusted_issuers`.

    // Start decoding the credential
    let decoded: JwsValidationItem<'_> = Self::decode(credential.as_str())?;
    let (public_key, method_id) = Self::parse_jwk(&decoded, trusted_issuers, options)?;

    let credential_token = Self::verify_decoded_signature(decoded, public_key, signature_verifier)?;

    // Check that the DID component of the parsed `kid` does indeed correspond to the issuer in the credential before
    // returning.
    let issuer_id: CoreDID = JwtCredentialValidatorUtils::extract_issuer(&credential_token.credential)?;
    if &issuer_id != method_id.did() {
      return Err(JwtValidationError::IdentifierMismatch {
        signer_ctx: SignerContext::Issuer,
      });
    };
    Ok(credential_token)
  }

  fn verify_signature_with_verifier_v2<DOC, S, T>(
    signature_verifier: &S,
    credential: &Jwt,
    trusted_issuers: &[DOC],
    options: &JwsVerificationOptions,
  ) -> Result<DecodedJwtCredentialV2<T>, JwtValidationError>
  where
    T: ToOwned<Owned = T> + serde::Serialize + serde::de::DeserializeOwned,
    DOC: AsRef<CoreDocument>,
    S: JwsVerifier,
  {
    // Note the below steps are necessary because `CoreDocument::verify_jws` decodes the JWS and then searches for a
    // method with a fragment (or full DID Url) matching `kid` in the given document. We do not want to carry out
    // that process for potentially every document in `trusted_issuers`.

    // Start decoding the credential
    let decoded: JwsValidationItem<'_> = Self::decode(credential.as_str())?;
    let (public_key, method_id) = Self::parse_jwk(&decoded, trusted_issuers, options)?;

    let credential_token = Self::verify_decoded_signature_v2(decoded, public_key, signature_verifier)?;

    // Check that the DID component of the parsed `kid` does indeed correspond to the issuer in the credential before
    // returning.
    let issuer_id: CoreDID = CoreDID::from_str(credential_token.credential.issuer.url().as_str()).map_err(|err| {
      JwtValidationError::SignerUrl {
        signer_ctx: SignerContext::Issuer,
        source: err.into(),
      }
    })?;
    if &issuer_id != method_id.did() {
      return Err(JwtValidationError::IdentifierMismatch {
        signer_ctx: SignerContext::Issuer,
      });
    };
    Ok(credential_token)
  }

  /// Decode the credential into a [`JwsValidationItem`].
  pub(crate) fn decode(credential_jws: &str) -> Result<JwsValidationItem<'_>, JwtValidationError> {
    let decoder: Decoder = Decoder::new();

    decoder
      .decode_compact_serialization(credential_jws.as_bytes(), None)
      .map_err(JwtValidationError::JwsDecodingError)
  }

  pub(crate) fn verify_signature_raw<'a, S: JwsVerifier>(
    decoded: JwsValidationItem<'a>,
    public_key: &Jwk,
    signature_verifier: &S,
  ) -> Result<DecodedJws<'a>, JwtValidationError> {
    decoded
      .verify(signature_verifier, public_key)
      .map_err(|err| JwtValidationError::Signature {
        source: err,
        signer_ctx: SignerContext::Issuer,
      })
  }

  /// Verify the signature using the given `public_key` and `signature_verifier`.
  pub(crate) fn verify_decoded_signature<S: JwsVerifier, T>(
    decoded: JwsValidationItem<'_>,
    public_key: &Jwk,
    signature_verifier: &S,
  ) -> Result<DecodedJwtCredential<T>, JwtValidationError>
  where
    T: ToOwned<Owned = T> + serde::Serialize + serde::de::DeserializeOwned,
  {
    // Verify the JWS signature and obtain the decoded token containing the protected header and raw claims
    let DecodedJws { protected, claims, .. } = Self::verify_signature_raw(decoded, public_key, signature_verifier)?;

    let credential_claims: CredentialJwtClaims<'_, T> =
      CredentialJwtClaims::from_json_slice(&claims).map_err(|err| {
        JwtValidationError::CredentialStructure(crate::Error::JwtClaimsSetDeserializationError(err.into()))
      })?;

    let custom_claims = credential_claims.custom.clone();

    // Construct the credential token containing the credential and the protected header.
    let credential: Credential<T> = credential_claims
      .try_into_credential()
      .map_err(JwtValidationError::CredentialStructure)?;

    Ok(DecodedJwtCredential {
      credential,
      header: Box::new(protected),
      custom_claims,
    })
  }

  pub(crate) fn verify_decoded_signature_v2<S: JwsVerifier, T>(
    decoded: JwsValidationItem<'_>,
    public_key: &Jwk,
    signature_verifier: &S,
  ) -> Result<DecodedJwtCredentialV2<T>, JwtValidationError>
  where
    T: ToOwned<Owned = T> + serde::Serialize + serde::de::DeserializeOwned,
  {
    // Verify the JWS signature and obtain the decoded token containing the protected header and raw claims
    let DecodedJws { protected, claims, .. } = Self::verify_signature_raw(decoded, public_key, signature_verifier)?;

    let credential = serde_json::from_slice(&claims)
      .map_err(|e| JwtValidationError::CredentialStructure(crate::Error::JwtClaimsSetDeserializationError(e.into())))?;

    Ok(DecodedJwtCredentialV2 {
      credential,
      header: Box::new(protected),
    })
  }
}

#[cfg(test)]
mod tests {
  use crate::credential::Subject;
  use crate::validator::SubjectHolderRelationship;
  use identity_core::common::Duration;
  use identity_core::common::Url;
  use once_cell::sync::Lazy;

  // All tests here are essentially adaptations of the old JwtCredentialValidator tests.
  use super::*;
  use identity_core::common::Object;
  use identity_core::common::Timestamp;
  use proptest::proptest;
  const LAST_RFC3339_COMPATIBLE_UNIX_TIMESTAMP: i64 = 253402300799; // 9999-12-31T23:59:59Z
  const FIRST_RFC3999_COMPATIBLE_UNIX_TIMESTAMP: i64 = -62167219200; // 0000-01-01T00:00:00Z

  const SIMPLE_CREDENTIAL_JSON: &str = r#"{
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://www.w3.org/2018/credentials/examples/v1"
    ],
    "id": "http://example.edu/credentials/3732",
    "type": ["VerifiableCredential", "UniversityDegreeCredential"],
    "issuer": "https://example.edu/issuers/14",
    "issuanceDate": "2010-01-01T19:23:24Z",
    "expirationDate": "2020-01-01T19:23:24Z",
    "credentialSubject": {
      "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
      "degree": {
        "type": "BachelorDegree",
        "name": "Bachelor of Science in Mechanical Engineering"
      }
    }
  }"#;

  /// A simple credential shared by some of the tests in this module
  static SIMPLE_CREDENTIAL: Lazy<Credential> =
    Lazy::new(|| Credential::<Object>::from_json(SIMPLE_CREDENTIAL_JSON).unwrap());

  #[test]
  fn issued_on_or_before() {
    assert!(JwtCredentialValidatorUtils::check_issued_on_or_before(
      &*SIMPLE_CREDENTIAL,
      SIMPLE_CREDENTIAL
        .issuance_date
        .checked_sub(Duration::minutes(1))
        .unwrap()
    )
    .is_err());

    // and now with a later timestamp
    assert!(JwtCredentialValidatorUtils::check_issued_on_or_before(
      &*SIMPLE_CREDENTIAL,
      SIMPLE_CREDENTIAL
        .issuance_date
        .checked_add(Duration::minutes(1))
        .unwrap()
    )
    .is_ok());
  }

  #[test]
  fn check_subject_holder_relationship() {
    let mut credential: Credential = SIMPLE_CREDENTIAL.clone();

    // first ensure that holder_url is the subject and set the nonTransferable property
    let actual_holder_url = credential.credential_subject.first().unwrap().id.clone().unwrap();
    assert_eq!(credential.credential_subject.len(), 1);
    credential.non_transferable = Some(true);

    // checking with holder = subject passes for all defined subject holder relationships:
    assert!(JwtCredentialValidatorUtils::check_subject_holder_relationship(
      &credential,
      &actual_holder_url,
      SubjectHolderRelationship::AlwaysSubject
    )
    .is_ok());

    assert!(JwtCredentialValidatorUtils::check_subject_holder_relationship(
      &credential,
      &actual_holder_url,
      SubjectHolderRelationship::SubjectOnNonTransferable
    )
    .is_ok());

    assert!(JwtCredentialValidatorUtils::check_subject_holder_relationship(
      &credential,
      &actual_holder_url,
      SubjectHolderRelationship::Any
    )
    .is_ok());

    // check with a holder different from the subject of the credential:
    let issuer_url = Url::parse("did:core:0x1234567890").unwrap();
    assert!(actual_holder_url != issuer_url);

    assert!(JwtCredentialValidatorUtils::check_subject_holder_relationship(
      &credential,
      &issuer_url,
      SubjectHolderRelationship::AlwaysSubject
    )
    .is_err());

    assert!(JwtCredentialValidatorUtils::check_subject_holder_relationship(
      &credential,
      &issuer_url,
      SubjectHolderRelationship::SubjectOnNonTransferable
    )
    .is_err());

    assert!(JwtCredentialValidatorUtils::check_subject_holder_relationship(
      &credential,
      &issuer_url,
      SubjectHolderRelationship::Any
    )
    .is_ok());

    let mut credential_transferable = credential.clone();

    credential_transferable.non_transferable = Some(false);

    assert!(JwtCredentialValidatorUtils::check_subject_holder_relationship(
      &credential_transferable,
      &issuer_url,
      SubjectHolderRelationship::SubjectOnNonTransferable
    )
    .is_ok());

    credential_transferable.non_transferable = None;

    assert!(JwtCredentialValidatorUtils::check_subject_holder_relationship(
      &credential_transferable,
      &issuer_url,
      SubjectHolderRelationship::SubjectOnNonTransferable
    )
    .is_ok());

    // two subjects (even when they are both the holder) should fail for all defined values except "Any"
    let mut credential_duplicated_holder = credential;
    credential_duplicated_holder
      .credential_subject
      .push(Subject::with_id(actual_holder_url));

    assert!(JwtCredentialValidatorUtils::check_subject_holder_relationship(
      &credential_duplicated_holder,
      &issuer_url,
      SubjectHolderRelationship::AlwaysSubject
    )
    .is_err());

    assert!(JwtCredentialValidatorUtils::check_subject_holder_relationship(
      &credential_duplicated_holder,
      &issuer_url,
      SubjectHolderRelationship::SubjectOnNonTransferable
    )
    .is_err());

    assert!(JwtCredentialValidatorUtils::check_subject_holder_relationship(
      &credential_duplicated_holder,
      &issuer_url,
      SubjectHolderRelationship::Any
    )
    .is_ok());
  }

  #[test]
  fn simple_expires_on_or_after_with_expiration_date() {
    let later_than_expiration_date = SIMPLE_CREDENTIAL
      .expiration_date
      .unwrap()
      .checked_add(Duration::minutes(1))
      .unwrap();
    assert!(
      JwtCredentialValidatorUtils::check_expires_on_or_after(&*SIMPLE_CREDENTIAL, later_than_expiration_date).is_err()
    );
    // and now with an earlier date
    let earlier_date = Timestamp::parse("2019-12-27T11:35:30Z").unwrap();
    assert!(JwtCredentialValidatorUtils::check_expires_on_or_after(&*SIMPLE_CREDENTIAL, earlier_date).is_ok());
  }

  // test with a few timestamps that should be RFC3339 compatible
  proptest! {
    #[test]
    fn property_based_expires_after_with_expiration_date(seconds in 0..1_000_000_000_u32) {
      let after_expiration_date = SIMPLE_CREDENTIAL.expiration_date.unwrap().checked_add(Duration::seconds(seconds)).unwrap();
      let before_expiration_date = SIMPLE_CREDENTIAL.expiration_date.unwrap().checked_sub(Duration::seconds(seconds)).unwrap();
      assert!(JwtCredentialValidatorUtils::check_expires_on_or_after(&*SIMPLE_CREDENTIAL, after_expiration_date).is_err());
      assert!(JwtCredentialValidatorUtils::check_expires_on_or_after(&*SIMPLE_CREDENTIAL, before_expiration_date).is_ok());
    }
  }

  proptest! {
    #[test]
    fn property_based_expires_after_no_expiration_date(seconds in FIRST_RFC3999_COMPATIBLE_UNIX_TIMESTAMP..LAST_RFC3339_COMPATIBLE_UNIX_TIMESTAMP) {
      let mut credential = SIMPLE_CREDENTIAL.clone();
      credential.expiration_date = None;
      // expires after whatever the timestamp may be because the expires_after field is None.
      assert!(JwtCredentialValidatorUtils::check_expires_on_or_after(&credential, Timestamp::from_unix(seconds).unwrap()).is_ok());
    }
  }

  proptest! {
    #[test]
    fn property_based_issued_before(seconds in 0 ..1_000_000_000_u32) {

      let earlier_than_issuance_date = SIMPLE_CREDENTIAL.issuance_date.checked_sub(Duration::seconds(seconds)).unwrap();
      let later_than_issuance_date = SIMPLE_CREDENTIAL.issuance_date.checked_add(Duration::seconds(seconds)).unwrap();
      assert!(JwtCredentialValidatorUtils::check_issued_on_or_before(&*SIMPLE_CREDENTIAL, earlier_than_issuance_date).is_err());
      assert!(JwtCredentialValidatorUtils::check_issued_on_or_before(&*SIMPLE_CREDENTIAL, later_than_issuance_date).is_ok());
    }
  }
}
