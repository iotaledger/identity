// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use identity_document::document::CoreDocument;
use serde::Serialize;

#[cfg(feature = "revocation-bitmap")]
use crate::revocation::RevocationBitmap;
use identity_core::common::OneOrMany;
use identity_core::common::Timestamp;
use identity_core::common::Url;
use identity_did::CoreDID;
use identity_did::DID;
use identity_document::verifiable::VerifierOptions;

use crate::credential::Credential;
#[cfg(feature = "revocation-bitmap")]
use crate::credential::RevocationBitmapStatus;

use super::errors::CompoundCredentialValidationError;
use super::errors::SignerContext;
use super::errors::ValidationError;
#[cfg(feature = "revocation-bitmap")]
use super::validation_options::StatusCheck;
use super::CredentialValidationOptions;
use super::FailFast;
use super::SubjectHolderRelationship;

/// A struct for validating [`Credential`]s.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CredentialValidator;

type ValidationUnitResult = std::result::Result<(), ValidationError>;
type CredentialValidationResult = std::result::Result<(), CompoundCredentialValidationError>;

impl CredentialValidator {
  /// Validates a [`Credential`].
  ///
  /// The following properties are validated according to `options`:
  /// - the issuer's signature,
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
  /// `credentialStatus`, `type`, `credentialSchema`, `refreshService`, **and more**.
  /// These should be manually checked after validation, according to your requirements.
  ///
  /// # Errors
  /// An error is returned whenever a validated condition is not satisfied.
  pub fn validate<T: Serialize, DOC: AsRef<CoreDocument>>(
    credential: &Credential<T>,
    issuer: &DOC,
    options: &CredentialValidationOptions,
    fail_fast: FailFast,
  ) -> CredentialValidationResult {
    Self::validate_extended(
      credential,
      std::slice::from_ref(issuer.as_ref()),
      options,
      None,
      fail_fast,
    )
  }

  /// Validates the semantic structure of the [`Credential`].
  ///
  /// # Warning
  /// This does not validate against the credential's schema nor the structure of the subject claims.
  pub fn check_structure<T>(credential: &Credential<T>) -> ValidationUnitResult {
    credential
      .check_structure()
      .map_err(ValidationError::CredentialStructure)
  }

  /// Validate that the [`Credential`] expires on or after the specified [`Timestamp`].
  pub fn check_expires_on_or_after<T>(credential: &Credential<T>, timestamp: Timestamp) -> ValidationUnitResult {
    let expiration_date: Option<Timestamp> = credential.expiration_date;
    (expiration_date.is_none() || expiration_date >= Some(timestamp))
      .then_some(())
      .ok_or(ValidationError::ExpirationDate)
  }

  /// Validate that the [`Credential`] is issued on or before the specified [`Timestamp`].
  pub fn check_issued_on_or_before<T>(credential: &Credential<T>, timestamp: Timestamp) -> ValidationUnitResult {
    (credential.issuance_date <= timestamp)
      .then_some(())
      .ok_or(ValidationError::IssuanceDate)
  }

  /// Verify the signature using the DID Document of a trusted issuer.
  ///
  /// # Warning
  /// The caller must ensure that the DID Documents of the trusted issuers are up-to-date.
  ///
  /// # Errors
  /// This method immediately returns an error if
  /// the credential issuer' url cannot be parsed to a DID belonging to one of the trusted issuers. Otherwise an attempt
  /// to verify the credential's signature will be made and an error is returned upon failure.
  pub fn verify_signature<DOC: AsRef<CoreDocument>, T: Serialize>(
    credential: &Credential<T>,
    trusted_issuers: &[DOC],
    options: &VerifierOptions,
  ) -> ValidationUnitResult {
    let issuer_did: CoreDID = Self::extract_issuer(credential)?;
    trusted_issuers
      .iter()
      .map(AsRef::as_ref)
      .find(|issuer_doc| <CoreDocument>::id(issuer_doc) == &issuer_did)
      .ok_or(ValidationError::DocumentMismatch(SignerContext::Issuer))
      .and_then(|issuer| {
        issuer
          .verify_data(credential, options)
          .map_err(|err| ValidationError::Signature {
            source: err.into(),
            signer_ctx: SignerContext::Issuer,
          })
      })
  }

  /// Validate that the relationship between the `holder` and the credential subjects is in accordance with
  /// `relationship`.
  pub fn check_subject_holder_relationship<T>(
    credential: &Credential<T>,
    holder: &Url,
    relationship: SubjectHolderRelationship,
  ) -> ValidationUnitResult {
    let url_matches: bool = match &credential.credential_subject {
      OneOrMany::One(ref credential_subject) => credential_subject.id.as_ref() == Some(holder),
      OneOrMany::Many(subjects) => {
        // need to check the case where the Many variant holds a vector of exactly one subject
        if let [credential_subject] = subjects.as_slice() {
          credential_subject.id.as_ref() == Some(holder)
        } else {
          // zero or > 1 subjects is interpreted to mean that the holder is not the subject
          false
        }
      }
    };

    Some(relationship)
      .filter(|relationship| match relationship {
        SubjectHolderRelationship::AlwaysSubject => url_matches,
        SubjectHolderRelationship::SubjectOnNonTransferable => {
          url_matches || !credential.non_transferable.unwrap_or(false)
        }
        SubjectHolderRelationship::Any => true,
      })
      .map(|_| ())
      .ok_or(ValidationError::SubjectHolderRelationship)
  }

  /// Checks whether the credential status has been revoked.
  ///
  /// Only supports `BitmapRevocation2022`.
  #[cfg(feature = "revocation-bitmap")]
  pub fn check_status<DOC: AsRef<CoreDocument>, T>(
    credential: &Credential<T>,
    trusted_issuers: &[DOC],
    status_check: StatusCheck,
  ) -> ValidationUnitResult {
    if status_check == StatusCheck::SkipAll {
      return Ok(());
    }

    match &credential.credential_status {
      None => Ok(()),
      Some(status) => {
        // Check status is supported.
        if status.type_ != RevocationBitmap::TYPE {
          if status_check == StatusCheck::SkipUnsupported {
            return Ok(());
          }
          return Err(ValidationError::InvalidStatus(crate::Error::InvalidStatus(format!(
            "unsupported type '{}'",
            status.type_
          ))));
        }
        let status: RevocationBitmapStatus =
          RevocationBitmapStatus::try_from(status.clone()).map_err(ValidationError::InvalidStatus)?;

        // Check the credential index against the issuer's DID Document.
        let issuer_did: CoreDID = Self::extract_issuer(credential)?;
        trusted_issuers
          .iter()
          .find(|issuer| <CoreDocument>::id(issuer.as_ref()) == &issuer_did)
          .ok_or(ValidationError::DocumentMismatch(SignerContext::Issuer))
          .and_then(|issuer| CredentialValidator::check_revocation_bitmap_status(issuer, status))
      }
    }
  }

  /// Check the given `status` against the matching [`RevocationBitmap`] service in the
  /// issuer's DID Document.
  #[cfg(feature = "revocation-bitmap")]
  fn check_revocation_bitmap_status<DOC: AsRef<CoreDocument> + ?Sized>(
    issuer: &DOC,
    status: RevocationBitmapStatus,
  ) -> ValidationUnitResult {
    use crate::revocation::RevocationDocumentExt;

    let issuer_service_url: identity_did::DIDUrl = status.id().map_err(ValidationError::InvalidStatus)?;

    // Check whether index is revoked.
    let revocation_bitmap: RevocationBitmap = issuer
      .as_ref()
      .resolve_revocation_bitmap(issuer_service_url.into())
      .map_err(|_| ValidationError::ServiceLookupError)?;
    let index: u32 = status.index().map_err(ValidationError::InvalidStatus)?;
    if revocation_bitmap.is_revoked(index) {
      Err(ValidationError::Revoked)
    } else {
      Ok(())
    }
  }

  // This method takes a slice of issuer's instead of a single issuer in order to better accommodate presentation
  // validation. It also validates the relation ship between a holder and the credential subjects when
  // `relationship_criterion` is Some.
  pub(crate) fn validate_extended<DOC: AsRef<CoreDocument>, T: Serialize>(
    credential: &Credential<T>,
    issuers: &[DOC],
    options: &CredentialValidationOptions,
    relationship_criterion: Option<(&Url, SubjectHolderRelationship)>,
    fail_fast: FailFast,
  ) -> CredentialValidationResult {
    // Run all single concern validations in turn and fail immediately if `fail_fast` is true.
    let signature_validation =
      std::iter::once_with(|| Self::verify_signature(credential, issuers, &options.verifier_options));

    let expiry_date_validation = std::iter::once_with(|| {
      Self::check_expires_on_or_after(credential, options.earliest_expiry_date.unwrap_or_default())
    });

    let issuance_date_validation = std::iter::once_with(|| {
      Self::check_issued_on_or_before(credential, options.latest_issuance_date.unwrap_or_default())
    });

    let structure_validation = std::iter::once_with(|| Self::check_structure(credential));

    let subject_holder_validation = std::iter::once_with(|| {
      relationship_criterion
        .map(|(holder, relationship)| Self::check_subject_holder_relationship(credential, holder, relationship))
        .unwrap_or(Ok(()))
    });

    let validation_units_iter = issuance_date_validation
      .chain(expiry_date_validation)
      .chain(structure_validation)
      .chain(subject_holder_validation)
      .chain(signature_validation);

    #[cfg(feature = "revocation-bitmap")]
    let validation_units_iter = {
      let revocation_validation = std::iter::once_with(|| Self::check_status(credential, issuers, options.status));
      validation_units_iter.chain(revocation_validation)
    };

    let validation_units_error_iter = validation_units_iter.filter_map(|result| result.err());
    let validation_errors: Vec<ValidationError> = match fail_fast {
      FailFast::FirstError => validation_units_error_iter.take(1).collect(),
      FailFast::AllErrors => validation_units_error_iter.collect(),
    };

    if validation_errors.is_empty() {
      Ok(())
    } else {
      Err(CompoundCredentialValidationError { validation_errors })
    }
  }

  /// Utility for extracting the issuer field of a [`Credential`] as a DID.
  ///
  /// # Errors
  ///
  /// Fails if the issuer field is not a valid DID.
  pub fn extract_issuer<D: DID, T>(credential: &Credential<T>) -> std::result::Result<D, ValidationError>
  where
    <D as FromStr>::Err: std::error::Error + Send + Sync + 'static,
  {
    D::from_str(credential.issuer.url().as_str()).map_err(|err| ValidationError::SignerUrl {
      signer_ctx: SignerContext::Issuer,
      source: err.into(),
    })
  }
}

#[cfg(test)]
mod tests {
  use identity_core::common::Duration;
  use identity_core::common::Object;
  use identity_core::common::OneOrMany;
  use identity_core::common::Timestamp;
  use identity_core::convert::FromJson;
  use identity_core::crypto::KeyPair;
  use identity_core::crypto::ProofOptions;
  use identity_did::DID;
  use identity_document::document::CoreDocument;
  use identity_document::service::Service;

  use crate::credential::Status;
  use crate::credential::Subject;
  use crate::validator::test_utils;
  use crate::validator::CredentialValidationOptions;

  use super::*;

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

  lazy_static::lazy_static! {
    // A simple credential shared by some of the tests in this module
    static ref SIMPLE_CREDENTIAL: Credential = Credential::<Object>::from_json(SIMPLE_CREDENTIAL_JSON).unwrap();
  }

  // Setup parameters shared by many of the tests in this module
  struct Setup {
    issuer_doc: CoreDocument,
    issuer_key: KeyPair,
    unsigned_credential: Credential,
    issuance_date: Timestamp,
    expiration_date: Timestamp,
  }
  impl Setup {
    fn new() -> Self {
      let (issuer_doc, issuer_key) = test_utils::generate_document_with_keys();
      let (subject_doc, _) = test_utils::generate_document_with_keys();
      let issuance_date = Timestamp::parse("2020-01-01T00:00:00Z").unwrap();
      let expiration_date = Timestamp::parse("2023-01-01T00:00:00Z").unwrap();
      let unsigned_credential =
        test_utils::generate_credential(&issuer_doc, &[subject_doc], issuance_date, expiration_date);
      Self {
        issuer_doc,
        issuer_key,
        unsigned_credential,
        issuance_date,
        expiration_date,
      }
    }
  }

  #[test]
  fn test_full_validation_invalid_expiration_date() {
    let Setup {
      issuer_doc,
      issuer_key,
      unsigned_credential: mut credential,
      expiration_date,
      issuance_date,
    } = Setup::new();
    issuer_doc
      .signer(issuer_key.private())
      .options(ProofOptions::default())
      .method(issuer_doc.methods(None).get(0).unwrap().id())
      .sign(&mut credential)
      .unwrap();

    // declare the credential validation parameters

    let issued_on_or_before = issuance_date;
    // expires_on_or_after > expiration_date
    let expires_on_or_after = expiration_date.checked_add(Duration::seconds(1)).unwrap();
    let options = CredentialValidationOptions::default()
      .latest_issuance_date(issued_on_or_before)
      .earliest_expiry_date(expires_on_or_after);
    // validate and extract the nested error according to our expectations

    let validation_errors = CredentialValidator::validate(&credential, &issuer_doc, &options, FailFast::FirstError)
      .unwrap_err()
      .validation_errors;

    let error = match validation_errors.as_slice() {
      [validation_error] => validation_error,
      _ => unreachable!(),
    };

    assert!(matches!(error, &ValidationError::ExpirationDate));
  }

  #[test]
  fn simple_issued_on_or_before() {
    assert!(CredentialValidator::check_issued_on_or_before(
      &SIMPLE_CREDENTIAL,
      SIMPLE_CREDENTIAL
        .issuance_date
        .checked_sub(Duration::minutes(1))
        .unwrap()
    )
    .is_err());
    // and now with a later timestamp
    assert!(CredentialValidator::check_issued_on_or_before(
      &SIMPLE_CREDENTIAL,
      SIMPLE_CREDENTIAL
        .issuance_date
        .checked_add(Duration::minutes(1))
        .unwrap()
    )
    .is_ok());
  }

  #[test]
  fn test_validate_credential_invalid_issuance_date() {
    let Setup {
      issuer_doc,
      issuer_key,
      unsigned_credential: mut credential,
      expiration_date,
      issuance_date,
    } = Setup::new();
    issuer_doc
      .signer(issuer_key.private())
      .options(ProofOptions::default())
      .method(issuer_doc.methods(None).get(0).unwrap().id())
      .sign(&mut credential)
      .unwrap();

    // declare the credential validation parameters

    // issued_on_or_before < issuance_date
    let issued_on_or_before = issuance_date.checked_sub(Duration::seconds(1)).unwrap();
    let expires_on_or_after = expiration_date;
    let options = CredentialValidationOptions::default()
      .latest_issuance_date(issued_on_or_before)
      .earliest_expiry_date(expires_on_or_after);

    // validate and extract the nested error according to our expectations
    let validation_errors = CredentialValidator::validate(&credential, &issuer_doc, &options, FailFast::FirstError)
      .unwrap_err()
      .validation_errors;

    let error = match validation_errors.as_slice() {
      [validation_error] => validation_error,
      _ => unreachable!(),
    };

    assert!(matches!(error, &ValidationError::IssuanceDate));
  }

  #[test]
  fn test_full_validation() {
    let Setup {
      issuer_doc,
      issuer_key,
      unsigned_credential: mut credential,
      issuance_date,
      expiration_date,
    } = Setup::new();
    issuer_doc
      .signer(issuer_key.private())
      .options(ProofOptions::default())
      .method(issuer_doc.methods(None).get(0).unwrap().id())
      .sign(&mut credential)
      .unwrap();

    // declare the credential validation parameters
    let issued_on_or_before = issuance_date.checked_add(Duration::days(14)).unwrap();
    let expires_on_or_after = expiration_date.checked_sub(Duration::hours(1)).unwrap();
    let options = CredentialValidationOptions::default()
      .latest_issuance_date(issued_on_or_before)
      .earliest_expiry_date(expires_on_or_after);
    assert!(CredentialValidator::validate(&credential, &issuer_doc, &options, FailFast::FirstError).is_ok());
  }

  #[test]
  fn test_matches_issuer_did_unrelated_issuer() {
    let Setup {
      issuer_doc,
      issuer_key,
      unsigned_credential: mut credential,
      issuance_date,
      expiration_date,
    } = Setup::new();
    let (other_doc, _) = test_utils::generate_document_with_keys();
    issuer_doc
      .signer(issuer_key.private())
      .options(ProofOptions::default())
      .method(issuer_doc.methods(None).get(0).unwrap().id())
      .sign(&mut credential)
      .unwrap();

    // the credential was not signed by this issuer
    let _issuer = &(other_doc);

    // check that `verify_signature` returns the expected error
    assert!(matches!(
      CredentialValidator::verify_signature(&credential, &[&other_doc], &VerifierOptions::default()).unwrap_err(),
      ValidationError::DocumentMismatch { .. }
    ));

    // also check that the full validation fails as expected
    let issued_on_or_before = issuance_date.checked_add(Duration::days(14)).unwrap();
    let expires_on_or_after = expiration_date.checked_sub(Duration::hours(1)).unwrap();
    let options = CredentialValidationOptions::default()
      .latest_issuance_date(issued_on_or_before)
      .earliest_expiry_date(expires_on_or_after);

    // validate and extract the nested error according to our expectations
    let validation_errors = CredentialValidator::validate(&credential, &other_doc, &options, FailFast::FirstError)
      .unwrap_err()
      .validation_errors;

    let error = match validation_errors.as_slice() {
      [validation_error] => validation_error,
      _ => unreachable!(),
    };

    assert!(matches!(error, ValidationError::DocumentMismatch { .. }));
  }

  #[test]
  fn test_verify_invalid_signature() {
    let Setup {
      issuer_doc,
      unsigned_credential: mut credential,
      issuance_date,
      expiration_date,
      ..
    } = Setup::new();

    let (_, other_keys) = test_utils::generate_document_with_keys();
    issuer_doc
      .signer(other_keys.private())
      .options(ProofOptions::default())
      .method(issuer_doc.methods(None).get(0).unwrap().id())
      .sign(&mut credential)
      .unwrap();

    // run the validation unit
    assert!(matches!(
      CredentialValidator::verify_signature(&credential, &[&issuer_doc], &VerifierOptions::default()).unwrap_err(),
      ValidationError::Signature { .. }
    ));

    // check that full_validation also fails as expected
    let issued_on_or_before = issuance_date.checked_add(Duration::days(14)).unwrap();
    let expires_on_or_after = expiration_date.checked_sub(Duration::hours(1)).unwrap();
    let options = CredentialValidationOptions::default()
      .latest_issuance_date(issued_on_or_before)
      .earliest_expiry_date(expires_on_or_after);
    // validate and extract the nested error according to our expectations
    let validation_errors = CredentialValidator::validate(&credential, &issuer_doc, &options, FailFast::FirstError)
      .unwrap_err()
      .validation_errors;

    let error = match validation_errors.as_slice() {
      [validation_error] => validation_error,
      _ => unreachable!(),
    };

    assert!(matches!(error, &ValidationError::Signature { .. }));
  }

  #[test]
  fn test_check_subject_holder_relationship() {
    let Setup {
      issuer_doc,
      unsigned_credential: mut credential,
      ..
    } = Setup::new();

    // first ensure that holder_url is the subject and set the nonTransferable property
    let actual_holder_url = credential.credential_subject.first().unwrap().id.clone().unwrap();
    assert_eq!(credential.credential_subject.len(), 1);
    credential.non_transferable = Some(true);

    // checking with holder = subject passes for all defined subject holder relationships:
    assert!(CredentialValidator::check_subject_holder_relationship(
      dbg!(&credential),
      dbg!(&actual_holder_url),
      SubjectHolderRelationship::AlwaysSubject
    )
    .is_ok());

    assert!(CredentialValidator::check_subject_holder_relationship(
      &credential,
      &actual_holder_url,
      SubjectHolderRelationship::SubjectOnNonTransferable
    )
    .is_ok());

    assert!(CredentialValidator::check_subject_holder_relationship(
      &credential,
      &actual_holder_url,
      SubjectHolderRelationship::Any
    )
    .is_ok());

    // check with a holder different from the subject of the credential:
    let issuer_url = Url::parse(issuer_doc.id().as_str()).unwrap();
    assert!(actual_holder_url != issuer_url);

    assert!(CredentialValidator::check_subject_holder_relationship(
      &credential,
      &issuer_url,
      SubjectHolderRelationship::AlwaysSubject
    )
    .is_err());

    assert!(CredentialValidator::check_subject_holder_relationship(
      &credential,
      &issuer_url,
      SubjectHolderRelationship::SubjectOnNonTransferable
    )
    .is_err());

    assert!(CredentialValidator::check_subject_holder_relationship(
      &credential,
      &issuer_url,
      SubjectHolderRelationship::Any
    )
    .is_ok());

    let mut credential_transferable = credential.clone();

    credential_transferable.non_transferable = Some(false);

    assert!(CredentialValidator::check_subject_holder_relationship(
      &credential_transferable,
      &issuer_url,
      SubjectHolderRelationship::SubjectOnNonTransferable
    )
    .is_ok());

    credential_transferable.non_transferable = None;

    assert!(CredentialValidator::check_subject_holder_relationship(
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

    assert!(CredentialValidator::check_subject_holder_relationship(
      &credential_duplicated_holder,
      &issuer_url,
      SubjectHolderRelationship::AlwaysSubject
    )
    .is_err());

    assert!(CredentialValidator::check_subject_holder_relationship(
      &credential_duplicated_holder,
      &issuer_url,
      SubjectHolderRelationship::SubjectOnNonTransferable
    )
    .is_err());

    assert!(CredentialValidator::check_subject_holder_relationship(
      &credential_duplicated_holder,
      &issuer_url,
      SubjectHolderRelationship::Any
    )
    .is_ok());
  }

  #[cfg(feature = "revocation-bitmap")]
  #[test]
  fn test_check_status() {
    use crate::revocation::RevocationDocumentExt;
    let Setup {
      mut issuer_doc,
      unsigned_credential: mut credential,
      ..
    } = Setup::new();
    // 0: missing status always succeeds.
    for status_check in [StatusCheck::Strict, StatusCheck::SkipUnsupported, StatusCheck::SkipAll] {
      assert!(CredentialValidator::check_status(&credential, &[&issuer_doc], status_check).is_ok());
    }

    // 1: unsupported status type.
    credential.credential_status = Some(Status::new(
      Url::parse("https://example.com/").unwrap(),
      "UnsupportedStatus2022".to_owned(),
    ));
    for (status_check, expected) in [
      (StatusCheck::Strict, false),
      (StatusCheck::SkipUnsupported, true),
      (StatusCheck::SkipAll, true),
    ] {
      assert_eq!(
        CredentialValidator::check_status(&credential, &[&issuer_doc], status_check).is_ok(),
        expected
      );
    }

    // Add a RevocationBitmap status to the credential.
    let service_url: identity_did::DIDUrl = issuer_doc.id().to_url().join("#revocation-service").unwrap();
    let index: u32 = 42;
    credential.credential_status = Some(RevocationBitmapStatus::new(service_url.clone(), index).into());

    // 2: missing service in DID Document.
    for (status_check, expected) in [
      (StatusCheck::Strict, false),
      (StatusCheck::SkipUnsupported, false),
      (StatusCheck::SkipAll, true),
    ] {
      assert_eq!(
        CredentialValidator::check_status(&credential, &[&issuer_doc], status_check).is_ok(),
        expected
      );
    }

    // Add a RevocationBitmap service to the issuer.
    let bitmap: RevocationBitmap = RevocationBitmap::new();
    assert!(issuer_doc
      .insert_service(
        Service::builder(Object::new())
          .id(service_url.clone())
          .type_(RevocationBitmap::TYPE)
          .service_endpoint(bitmap.to_endpoint().unwrap())
          .build()
          .unwrap()
      )
      .is_ok());

    // 3: un-revoked index always succeeds.
    for status_check in [StatusCheck::Strict, StatusCheck::SkipUnsupported, StatusCheck::SkipAll] {
      assert!(CredentialValidator::check_status(&credential, &[&issuer_doc], status_check).is_ok());
    }

    // 4: revoked index.
    <CoreDocument as RevocationDocumentExt>::revoke_credentials(&mut issuer_doc, &service_url, &[index]).unwrap();
    for (status_check, expected) in [
      (StatusCheck::Strict, false),
      (StatusCheck::SkipUnsupported, false),
      (StatusCheck::SkipAll, true),
    ] {
      assert_eq!(
        CredentialValidator::check_status(&credential, &[&issuer_doc], status_check).is_ok(),
        expected
      );
    }
  }

  #[test]
  fn test_full_validation_invalid_structure() {
    let Setup {
      issuer_doc,
      issuer_key,
      unsigned_credential: mut credential,
      issuance_date,
      expiration_date,
    } = Setup::new();

    issuer_doc
      .signer(issuer_key.private())
      .options(ProofOptions::default())
      .method(issuer_doc.methods(None).get(0).unwrap().id())
      .sign(&mut credential)
      .unwrap();
    // the credential now has no credential subjects which is not semantically correct
    credential.credential_subject = OneOrMany::default();

    // declare the credential validation parameters

    let issued_on_or_before = issuance_date.checked_add(Duration::days(14)).unwrap();
    let expires_on_or_after = expiration_date.checked_sub(Duration::hours(1)).unwrap();
    let options = CredentialValidationOptions::default()
      .latest_issuance_date(issued_on_or_before)
      .earliest_expiry_date(expires_on_or_after);
    // validate and extract the nested error according to our expectations
    let validation_errors = CredentialValidator::validate(&credential, &issuer_doc, &options, FailFast::FirstError)
      .unwrap_err()
      .validation_errors;

    let error = match validation_errors.as_slice() {
      [validation_error] => validation_error,
      _ => unreachable!(),
    };

    assert!(matches!(error, &ValidationError::CredentialStructure(_)));
  }

  #[test]
  fn test_full_validation_multiple_errors_fail_fast() {
    let Setup {
      issuer_doc,
      issuer_key,
      unsigned_credential: mut credential,
      issuance_date,
      expiration_date,
    } = Setup::new();

    let (other_doc, _) = test_utils::generate_document_with_keys();
    issuer_doc
      .signer(issuer_key.private())
      .options(ProofOptions::default())
      .method(issuer_doc.methods(None).get(0).unwrap().id())
      .sign(&mut credential)
      .unwrap();
    // the credential now has no credential subjects which is not semantically correct
    credential.credential_subject = OneOrMany::default();

    // declare the credential validation parameters

    // issued_on_or_before < issuance_date
    let issued_on_or_before = issuance_date.checked_sub(Duration::seconds(1)).unwrap();

    // expires_on_or_after > expiration_date
    let expires_on_or_after = expiration_date.checked_add(Duration::seconds(1)).unwrap();
    let options = CredentialValidationOptions::default()
      .latest_issuance_date(issued_on_or_before)
      .earliest_expiry_date(expires_on_or_after);
    // validate and extract the nested error according to our expectations
    // Note: the credential was not issued by `other_issuer`
    let validation_errors = CredentialValidator::validate(&credential, &other_doc, &options, FailFast::FirstError)
      .unwrap_err()
      .validation_errors;

    assert!(validation_errors.len() == 1);
  }

  #[test]
  fn test_full_validation_multiple_errors_accumulate_all_errors() {
    let Setup {
      issuer_doc,
      issuer_key,
      unsigned_credential: mut credential,
      issuance_date,
      expiration_date,
    } = Setup::new();

    let (other_doc, _) = test_utils::generate_document_with_keys();
    issuer_doc
      .signer(issuer_key.private())
      .options(ProofOptions::default())
      .method(issuer_doc.methods(None).get(0).unwrap().id())
      .sign(&mut credential)
      .unwrap();
    // the credential now has no credential subjects which is not semantically correct
    credential.credential_subject = OneOrMany::default();

    // declare the credential validation parameters

    // issued_on_or_before < issuance_date
    let issued_on_or_before = issuance_date.checked_sub(Duration::seconds(1)).unwrap();

    // expires_on_or_after > expiration_date
    let expires_on_or_after = expiration_date.checked_add(Duration::seconds(1)).unwrap();
    let options = CredentialValidationOptions::default()
      .latest_issuance_date(issued_on_or_before)
      .earliest_expiry_date(expires_on_or_after);

    // validate and extract the nested error according to our expectations
    // Note: the credential was not issued by `other_issuer`
    let validation_errors = CredentialValidator::validate(&credential, &other_doc, &options, FailFast::AllErrors)
      .unwrap_err()
      .validation_errors;

    assert!(validation_errors.len() >= 4);
  }
}
