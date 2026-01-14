// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::test_utils::setup_iotadocument;
use super::test_utils::Setup;
use crate::JwkDocumentExt;
use crate::JwsSignatureOptions;
use identity_core::common::Duration;
use identity_core::common::Object;
use identity_core::common::Timestamp;
use identity_core::common::Url;
use identity_core::convert::FromJson;
use identity_core::convert::ToJson;
use identity_credential::credential::Credential;
use identity_credential::credential::CredentialBuilder;
use identity_credential::credential::Jws;
use identity_credential::credential::Subject;
use identity_credential::sd_jwt_payload::KeyBindingJwtClaims;
use identity_credential::sd_jwt_payload::SdJwt;
use identity_credential::sd_jwt_payload::SdObjectDecoder;
use identity_credential::sd_jwt_payload::SdObjectEncoder;
use identity_credential::sd_jwt_payload::Sha256Hasher;
use identity_credential::validator::FailFast;
use identity_credential::validator::JwtCredentialValidationOptions;
use identity_credential::validator::KeyBindingJwtValidationOptions;
use identity_credential::validator::KeyBindingJwtError;
use identity_credential::validator::SdJwtCredentialValidator;
use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_iota_core::IotaDocument;
use serde_json::json;

const NONCE: &str = "nonce-test";
const VERIFIER_ID: &str = "did:test:verifier";

async fn setup_test() -> (Setup<IotaDocument, IotaDocument>, Credential, SdJwt) {
  let setup: Setup<IotaDocument, IotaDocument> = setup_iotadocument(None, None).await;

  let subject: Subject = Subject::from_json_value(json!({
    "id": setup.subject_doc.id().to_string(),
    "degree": {
      "type": "BachelorDegree",
      "name": "Bachelor of Science in Mechanical Engineering"
    }
  }))
  .unwrap();

  // Build credential using subject above and issuer.
  let credential: Credential = CredentialBuilder::default()
    .id(Url::parse("https://example.edu/credentials/3732").unwrap())
    .issuer(Url::parse(setup.issuer_doc.id().to_string()).unwrap())
    .type_("AddressCredential")
    .subject(subject)
    .build()
    .unwrap();

  let payload = credential.serialize_jwt(None).unwrap();

  let mut encoder = SdObjectEncoder::new(&payload).unwrap();
  let disclosures = vec![
    encoder.conceal("/vc/credentialSubject/degree/type", None).unwrap(),
    encoder.conceal("/vc/credentialSubject/degree/name", None).unwrap(),
  ];
  encoder.add_sd_alg_property();
  let encoded_payload = encoder.try_to_string().unwrap();

  let jwt: Jws = setup
    .issuer_doc
    .create_jws(
      &setup.issuer_storage,
      &setup.issuer_method_fragment,
      encoded_payload.as_bytes(),
      &JwsSignatureOptions::default(),
    )
    .await
    .unwrap();

  let disclosures: Vec<String> = disclosures
    .clone()
    .into_iter()
    .map(|disclosure| disclosure.to_string())
    .collect();

  let binding_claims = KeyBindingJwtClaims::new(
    &Sha256Hasher::new(),
    jwt.as_str().to_string(),
    disclosures.clone(),
    NONCE.to_string(),
    VERIFIER_ID.to_string(),
    Timestamp::now_utc().to_unix(),
  )
  .to_json()
  .unwrap();

  // Setting the `typ` in the header is required.
  let options = JwsSignatureOptions::new().typ(KeyBindingJwtClaims::KB_JWT_HEADER_TYP);

  // Create the KB-JWT.
  let kb_jwt: Jws = setup
    .subject_doc
    .create_jws(
      &setup.subject_storage,
      &setup.subject_method_fragment,
      binding_claims.as_bytes(),
      &options,
    )
    .await
    .unwrap();
  let sd_jwt_obj = SdJwt::new(jwt.into(), disclosures.clone(), Some(kb_jwt.into()));
  (setup, credential, sd_jwt_obj)
}

#[tokio::test]
async fn sd_jwt_validation() {
  let (setup, credential, sd_jwt) = setup_test().await;
  let decoder = SdObjectDecoder::new_with_sha256();
  let validator = SdJwtCredentialValidator::with_signature_verifier(EdDSAJwsVerifier::default(), decoder);
  let validation = validator
    .validate_credential::<_, Object>(
      &sd_jwt,
      &setup.issuer_doc,
      &JwtCredentialValidationOptions::default(),
      FailFast::FirstError,
    )
    .unwrap();
  assert_eq!(validation.credential, credential);
}

#[tokio::test]
async fn kb_validation() {
  let (setup, _credential, sd_jwt) = setup_test().await;
  let decoder = SdObjectDecoder::new_with_sha256();
  let validator = SdJwtCredentialValidator::with_signature_verifier(EdDSAJwsVerifier::default(), decoder);
  let options = KeyBindingJwtValidationOptions::new().nonce(NONCE).aud(VERIFIER_ID);
  let _kb_validation = validator
    .validate_key_binding_jwt(&sd_jwt, &setup.subject_doc, &options)
    .expect("KB validation failed!");
}

#[tokio::test]
async fn kb_too_early() {
  let (setup, _credential, sd_jwt) = setup_test().await;
  let decoder = SdObjectDecoder::new_with_sha256();
  let validator = SdJwtCredentialValidator::with_signature_verifier(EdDSAJwsVerifier::default(), decoder);
  let timestamp = Timestamp::now_utc().checked_add(Duration::seconds(1)).unwrap();
  let options = KeyBindingJwtValidationOptions::new()
    .nonce(NONCE)
    .aud(VERIFIER_ID)
    .earliest_issuance_date(timestamp);
  let kb_validation = validator.validate_key_binding_jwt(&sd_jwt, &setup.subject_doc, &options);
  // let err =
  assert!(matches!(
    kb_validation.err().unwrap(),
    KeyBindingJwtError::IssuanceDate(_)
  ));
}

#[tokio::test]
async fn kb_too_late() {
  let (setup, _credential, sd_jwt) = setup_test().await;
  let decoder = SdObjectDecoder::new_with_sha256();
  let validator = SdJwtCredentialValidator::with_signature_verifier(EdDSAJwsVerifier::default(), decoder);
  let timestamp = Timestamp::now_utc().checked_sub(Duration::seconds(20)).unwrap();
  let options = KeyBindingJwtValidationOptions::new()
    .nonce(NONCE)
    .aud(VERIFIER_ID)
    .latest_issuance_date(timestamp);
  let kb_validation = validator.validate_key_binding_jwt(&sd_jwt, &setup.subject_doc, &options);
  assert!(matches!(
    kb_validation.err().unwrap(),
    KeyBindingJwtError::IssuanceDate(_)
  ));
}

#[tokio::test]
async fn kb_in_the_future() {
  let (setup, _credential, sd_jwt) = setup_test().await;
  let binding_claims = KeyBindingJwtClaims::new(
    &Sha256Hasher::new(),
    sd_jwt.jwt.as_str().to_string(),
    sd_jwt.disclosures.clone(),
    NONCE.to_string(),
    VERIFIER_ID.to_string(),
    Timestamp::now_utc()
      .checked_add(Duration::seconds(30))
      .unwrap()
      .to_unix(),
  )
  .to_json()
  .unwrap();

  // Setting the `typ` in the header is required.
  let options = JwsSignatureOptions::new().typ(KeyBindingJwtClaims::KB_JWT_HEADER_TYP);

  // Create the KB-JWT.
  let kb_jwt: Jws = setup
    .subject_doc
    .create_jws(
      &setup.subject_storage,
      &setup.subject_method_fragment,
      binding_claims.as_bytes(),
      &options,
    )
    .await
    .unwrap();
  let sd_jwt = SdJwt::new(sd_jwt.jwt, sd_jwt.disclosures.clone(), Some(kb_jwt.into()));

  let decoder = SdObjectDecoder::new_with_sha256();
  let validator = SdJwtCredentialValidator::with_signature_verifier(EdDSAJwsVerifier::default(), decoder);
  let options = KeyBindingJwtValidationOptions::new()
    .nonce(NONCE.to_string())
    .aud(VERIFIER_ID.to_string());
  let kb_validation = validator.validate_key_binding_jwt(&sd_jwt, &setup.subject_doc, &options);
  assert!(matches!(
    kb_validation.err().unwrap(),
    KeyBindingJwtError::IssuanceDate(_)
  ));
}

#[tokio::test]
async fn kb_aud() {
  let (setup, _credential, sd_jwt) = setup_test().await;
  let decoder = SdObjectDecoder::new_with_sha256();
  let validator = SdJwtCredentialValidator::with_signature_verifier(EdDSAJwsVerifier::default(), decoder);
  let options = KeyBindingJwtValidationOptions::new().nonce(NONCE).aud("wrong verifier");
  let kb_validation = validator.validate_key_binding_jwt(&sd_jwt, &setup.subject_doc, &options);
  assert!(matches!(
    kb_validation.err().unwrap(),
    KeyBindingJwtError::AudienceMismatch
  ));
}

#[tokio::test]
async fn kb_nonce() {
  let (setup, _credential, sd_jwt) = setup_test().await;
  let decoder = SdObjectDecoder::new_with_sha256();
  let validator = SdJwtCredentialValidator::with_signature_verifier(EdDSAJwsVerifier::default(), decoder);
  let options = KeyBindingJwtValidationOptions::new()
    .nonce("wrong nonce")
    .aud(VERIFIER_ID);
  let kb_validation = validator.validate_key_binding_jwt(&sd_jwt, &setup.subject_doc, &options);
  assert!(matches!(kb_validation.err().unwrap(), KeyBindingJwtError::InvalidNonce));
}
