// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_core::common::Duration;
use identity_core::common::Object;
use identity_core::common::StringOrUrl;
use identity_core::common::Timestamp;
use identity_core::convert::FromJson;
use identity_credential::credential::Credential;
use identity_credential::credential::Jwt;
use identity_credential::presentation::JwtPresentationOptions;
use identity_credential::presentation::Presentation;
use identity_credential::presentation::PresentationBuilder;
use identity_credential::validator::DecodedJwtPresentation;
use identity_credential::validator::JwtPresentationValidationOptions;
use identity_credential::validator::JwtPresentationValidator;
use identity_credential::validator::JwtPresentationValidatorUtils;
use identity_credential::validator::JwtValidationError;
use identity_did::CoreDID;
use identity_did::DID;
use identity_document::document::CoreDocument;
use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_verification::jws::JwsAlgorithm;
use identity_verification::MethodScope;
use once_cell::sync::Lazy;

use crate::key_storage::JwkMemStore;
use crate::storage::tests::test_utils::generate_credential;
use crate::storage::tests::test_utils::setup_coredocument;
use crate::storage::tests::test_utils::setup_iotadocument;
use crate::storage::tests::test_utils::Setup;
use crate::JwkDocumentExt;
use crate::JwsSignatureOptions;

use super::test_utils::CredentialSetup;

static JWT_PRESENTATION_VALIDATOR_ED25519: Lazy<JwtPresentationValidator<EdDSAJwsVerifier>> =
  Lazy::new(|| JwtPresentationValidator::with_signature_verifier(EdDSAJwsVerifier::default()));

#[tokio::test]
async fn test_valid_presentation() {
  test_valid_presentation_impl(setup_coredocument(None, None).await).await;
  test_valid_presentation_impl(setup_iotadocument(None, None).await).await;
}
async fn test_valid_presentation_impl<T>(setup: Setup<T, T>)
where
  T: JwkDocumentExt + AsRef<CoreDocument>,
{
  let credential: CredentialSetup = generate_credential(&setup.issuer_doc, &[&setup.subject_doc], None, None);
  let jws = sign_credential(&setup, &credential.credential).await;

  let presentation: Presentation<Jwt> =
    PresentationBuilder::new(setup.subject_doc.as_ref().id().to_url().into(), Object::new())
      .credential(jws)
      .build()
      .unwrap();

  let mut custom_claims = Object::new();
  custom_claims.insert(
    "test-key".to_owned(),
    serde_json::Value::String("test-value".to_owned()),
  );

  let presentation_options = JwtPresentationOptions {
    expiration_date: Some(Timestamp::now_utc().checked_add(Duration::hours(10)).unwrap()),
    issuance_date: Some(Timestamp::now_utc().checked_sub(Duration::hours(10)).unwrap()),
    audience: Some(StringOrUrl::parse("did:test:123").unwrap()),
    custom_claims: Some(custom_claims),
  };

  let presentation_jwt = setup
    .subject_doc
    .create_presentation_jwt(
      &presentation,
      &setup.subject_storage,
      &setup.subject_method_fragment,
      &JwsSignatureOptions::default(),
      &presentation_options,
    )
    .await
    .unwrap();

  let decoded_presentation: DecodedJwtPresentation<Jwt> = JWT_PRESENTATION_VALIDATOR_ED25519
    .validate::<_, Jwt, Object>(
      &presentation_jwt,
      &setup.subject_doc,
      &JwtPresentationValidationOptions::default(),
    )
    .unwrap();

  assert_eq!(
    decoded_presentation.expiration_date,
    presentation_options.expiration_date
  );
  assert_eq!(decoded_presentation.issuance_date, presentation_options.issuance_date);
  assert_eq!(decoded_presentation.aud, presentation_options.audience);
  assert_eq!(decoded_presentation.custom_claims, presentation_options.custom_claims);
}

#[tokio::test]
async fn test_extract_holder() {
  test_extract_holder_impl(setup_coredocument(None, None).await).await;
  test_extract_holder_impl(setup_iotadocument(None, None).await).await;
}
async fn test_extract_holder_impl<T>(setup: Setup<T, T>)
where
  T: JwkDocumentExt + AsRef<CoreDocument>,
{
  let credential: CredentialSetup = generate_credential(&setup.issuer_doc, &[&setup.subject_doc], None, None);

  let issuer_2 = CoreDocument::from_json(r#"{"id": "did:test:123"}"#).unwrap();
  let credential_2: CredentialSetup = generate_credential(&issuer_2, &[&setup.subject_doc], None, None);
  let jws = sign_credential(&setup, &credential.credential).await;
  let jws_2 = sign_credential(&setup, &credential_2.credential).await;

  let presentation: Presentation<Jwt> =
    PresentationBuilder::new(setup.subject_doc.as_ref().id().to_url().into(), Object::new())
      .credential(jws.clone())
      .credential(jws_2.clone())
      .build()
      .unwrap();

  let presentation_options = JwtPresentationOptions {
    expiration_date: Some(Timestamp::now_utc().checked_add(Duration::hours(10)).unwrap()),
    issuance_date: Some(Timestamp::now_utc().checked_sub(Duration::hours(10)).unwrap()),
    audience: Some(StringOrUrl::parse("did:test:123").unwrap()),
    custom_claims: None,
  };

  let presentation_jwt = setup
    .subject_doc
    .create_presentation_jwt(
      &presentation,
      &setup.subject_storage,
      &setup.subject_method_fragment,
      &JwsSignatureOptions::default(),
      &presentation_options,
    )
    .await
    .unwrap();

  let holder = JwtPresentationValidatorUtils::extract_holder::<CoreDID>(&presentation_jwt).unwrap();
  assert_eq!(holder.to_url(), setup.subject_doc.as_ref().id().to_url());

  let decoded_presentation: DecodedJwtPresentation<Jwt> = JWT_PRESENTATION_VALIDATOR_ED25519
    .validate::<_, _, Object>(
      &presentation_jwt,
      &setup.subject_doc,
      &JwtPresentationValidationOptions::default(),
    )
    .unwrap();
  assert_eq!(decoded_presentation.presentation.verifiable_credential.to_vec()[0], jws);
  assert_eq!(
    decoded_presentation.presentation.verifiable_credential.to_vec()[1],
    jws_2
  );
}

// > Create a VP signed by a verification method with `subject_method_fragment`.
// > Replace the verification method but keep the same fragment.
// > Validation fails due to invalid signature since key material changed.
#[tokio::test]
async fn test_invalid_signature() {
  test_invalid_signature_impl(setup_coredocument(None, None).await).await;
  test_invalid_signature_impl(setup_iotadocument(None, None).await).await;
}
async fn test_invalid_signature_impl<T>(mut setup: Setup<T, T>)
where
  T: JwkDocumentExt + AsRef<CoreDocument>,
{
  let credential: CredentialSetup = generate_credential(&setup.issuer_doc, &[&setup.subject_doc], None, None);
  let jws = sign_credential(&setup, &credential.credential).await;

  let presentation: Presentation<Jwt> =
    PresentationBuilder::new(setup.subject_doc.as_ref().id().to_url().into(), Object::new())
      .credential(jws)
      .build()
      .unwrap();

  let presentation_options = JwtPresentationOptions {
    expiration_date: Some(Timestamp::now_utc().checked_add(Duration::hours(10)).unwrap()),
    issuance_date: Some(Timestamp::now_utc().checked_sub(Duration::hours(10)).unwrap()),
    audience: Some(StringOrUrl::parse("did:test:123").unwrap()),
    custom_claims: None,
  };

  let presentation_jwt = setup
    .subject_doc
    .create_presentation_jwt(
      &presentation,
      &setup.subject_storage,
      &setup.subject_method_fragment,
      &JwsSignatureOptions::default(),
      &presentation_options,
    )
    .await
    .unwrap();

  let method_url = setup
    .subject_doc
    .as_ref()
    .id()
    .to_url()
    .join(format!("#{}", setup.subject_method_fragment.clone()))
    .unwrap();

  setup
    .subject_doc
    .purge_method(&setup.subject_storage, &method_url)
    .await
    .unwrap();

  setup
    .subject_doc
    .generate_method(
      &setup.subject_storage,
      JwkMemStore::ED25519_KEY_TYPE,
      JwsAlgorithm::EdDSA,
      Some(&setup.subject_method_fragment),
      MethodScope::assertion_method(),
    )
    .await
    .unwrap();

  let validation_error: JwtValidationError = JWT_PRESENTATION_VALIDATOR_ED25519
    .validate::<_, Jwt, Object>(
      &presentation_jwt,
      &setup.subject_doc,
      &JwtPresentationValidationOptions::default(),
    )
    .err()
    .unwrap()
    .presentation_validation_errors
    .into_iter()
    .next()
    .unwrap();

  assert!(matches!(
    validation_error,
    JwtValidationError::PresentationJwsError(identity_document::Error::JwsVerificationError(_))
  ));
}

#[tokio::test]
async fn expiration_date() {
  expiration_date_impl(setup_coredocument(None, None).await).await;
  expiration_date_impl(setup_iotadocument(None, None).await).await;
}
async fn expiration_date_impl<T>(setup: Setup<T, T>)
where
  T: JwkDocumentExt + AsRef<CoreDocument> + Clone,
{
  let credential: CredentialSetup = generate_credential(&setup.issuer_doc, &[&setup.subject_doc], None, None);
  let jws = sign_credential(&setup, &credential.credential).await;

  let presentation: Presentation<Jwt> =
    PresentationBuilder::new(setup.subject_doc.as_ref().id().to_url().into(), Object::new())
      .credential(jws)
      .build()
      .unwrap();

  // Presentation expired in the past must be invalid.
  let presentation_options = JwtPresentationOptions {
    issuance_date: None,
    expiration_date: Some(Timestamp::now_utc().checked_sub(Duration::days(1)).unwrap()),
    audience: None,
    custom_claims: None,
  };

  let presentation_jwt = setup
    .subject_doc
    .create_presentation_jwt(
      &presentation,
      &setup.subject_storage,
      &setup.subject_method_fragment,
      &JwsSignatureOptions::default(),
      &presentation_options,
    )
    .await
    .unwrap();

  let validation_error: JwtValidationError = JWT_PRESENTATION_VALIDATOR_ED25519
    .validate::<_, Jwt, Object>(
      &presentation_jwt,
      &setup.subject_doc,
      &JwtPresentationValidationOptions::default(),
    )
    .err()
    .unwrap()
    .presentation_validation_errors
    .into_iter()
    .next()
    .unwrap();

  println!("{validation_error:?}");
  assert!(matches!(validation_error, JwtValidationError::ExpirationDate));

  // Set Validation options to allow expired presentation that were valid 2 hours back.
  let mut validation_options = JwtPresentationValidationOptions::default();
  validation_options =
    validation_options.earliest_expiry_date(Timestamp::now_utc().checked_sub(Duration::days(2)).unwrap());

  JWT_PRESENTATION_VALIDATOR_ED25519
    .validate::<_, Jwt, Object>(&presentation_jwt, &setup.subject_doc, &validation_options)
    .unwrap();
}

#[tokio::test]
async fn issuance_date() {
  issuance_date_impl(setup_coredocument(None, None).await).await;
  issuance_date_impl(setup_iotadocument(None, None).await).await;
}

async fn issuance_date_impl<T>(setup: Setup<T, T>)
where
  T: JwkDocumentExt + AsRef<CoreDocument> + Clone,
{
  let credential: CredentialSetup = generate_credential(&setup.issuer_doc, &[&setup.subject_doc], None, None);
  let jws = sign_credential(&setup, &credential.credential).await;

  let presentation: Presentation<Jwt> =
    PresentationBuilder::new(setup.subject_doc.as_ref().id().to_url().into(), Object::new())
      .credential(jws)
      .build()
      .unwrap();

  // Presentation issued in the future must be invalid.
  let presentation_options = JwtPresentationOptions {
    issuance_date: Some(Timestamp::now_utc().checked_add(Duration::hours(1)).unwrap()),
    expiration_date: None,
    audience: None,
    custom_claims: None,
  };

  let presentation_jwt = setup
    .subject_doc
    .create_presentation_jwt(
      &presentation,
      &setup.subject_storage,
      &setup.subject_method_fragment,
      &JwsSignatureOptions::default(),
      &presentation_options,
    )
    .await
    .unwrap();

  let validation_error: JwtValidationError = JWT_PRESENTATION_VALIDATOR_ED25519
    .validate::<_, Jwt, Object>(
      &presentation_jwt,
      &setup.subject_doc,
      &JwtPresentationValidationOptions::default(),
    )
    .err()
    .unwrap()
    .presentation_validation_errors
    .into_iter()
    .next()
    .unwrap();

  assert!(matches!(validation_error, JwtValidationError::IssuanceDate));

  // Set Validation options to allow presentation "issued" 2 hours in the future.
  let mut validation_options = JwtPresentationValidationOptions::default();
  validation_options =
    validation_options.latest_issuance_date(Timestamp::now_utc().checked_add(Duration::hours(2)).unwrap());

  let validation_ok: bool = JWT_PRESENTATION_VALIDATOR_ED25519
    .validate::<_, Jwt, Object>(&presentation_jwt, &setup.subject_doc, &validation_options)
    .is_ok();
  assert!(validation_ok);
}

#[tokio::test]
async fn presentation_jws_error() {
  presentation_jws_error_impl(setup_coredocument(None, None).await).await;
  presentation_jws_error_impl(setup_iotadocument(None, None).await).await;
}

async fn presentation_jws_error_impl<T>(setup: Setup<T, T>)
where
  T: JwkDocumentExt + AsRef<CoreDocument> + Clone,
{
  let credential: CredentialSetup = generate_credential(&setup.issuer_doc, &[&setup.subject_doc], None, None);
  let jws = sign_credential(&setup, &credential.credential).await;

  let presentation: Presentation<Jwt> =
    PresentationBuilder::new(setup.subject_doc.as_ref().id().to_url().into(), Object::new())
      .credential(jws)
      .build()
      .unwrap();

  // Sign presentation using the issuer's method and try to verify it using the holder's document.
  // Since the holder's document doesn't include that verification method, `MethodNotFound`is returned.

  let presentation_jwt = setup
    .issuer_doc
    .create_presentation_jwt(
      &presentation,
      &setup.issuer_storage,
      &setup.issuer_method_fragment,
      &JwsSignatureOptions::default(),
      &JwtPresentationOptions::default(),
    )
    .await
    .unwrap();

  let validation_error: JwtValidationError = JWT_PRESENTATION_VALIDATOR_ED25519
    .validate::<_, Jwt, Object>(
      &presentation_jwt,
      &setup.subject_doc,
      &JwtPresentationValidationOptions::default(),
    )
    .err()
    .unwrap()
    .presentation_validation_errors
    .into_iter()
    .next()
    .unwrap();

  assert!(matches!(
    validation_error,
    JwtValidationError::PresentationJwsError(identity_document::Error::MethodNotFound)
  ));
}

async fn sign_credential<T>(setup: &Setup<T, T>, credential: &Credential) -> Jwt
where
  T: JwkDocumentExt + AsRef<CoreDocument>,
{
  setup
    .issuer_doc
    .create_credential_jwt(
      credential,
      &setup.issuer_storage,
      &setup.issuer_method_fragment,
      &JwsSignatureOptions::default(),
      None,
    )
    .await
    .unwrap()
}
