// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::test_utils::setup_iotadocument;
use super::test_utils::Setup;
use crate::StorageSigner;
use identity_core::common::Duration;
use identity_core::common::Object;
use identity_core::common::Timestamp;
use identity_core::common::Url;
use identity_core::convert::FromJson;
use identity_credential::credential::Credential;
use identity_credential::credential::CredentialBuilder;
use identity_credential::credential::Subject;
use identity_credential::sd_jwt_payload::SdJwt;
use identity_credential::sd_jwt_payload::Sha256Hasher;
use identity_credential::validator::JwtCredentialValidationOptions;
use identity_credential::validator::KeyBindingJwtError;
use identity_credential::validator::KeyBindingJwtValidationOptions;
use identity_credential::validator::SdJwtCredentialValidator;
use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_iota_core::IotaDocument;
use sd_jwt::KeyBindingJwtBuilder;
use sd_jwt::RequiredKeyBinding;
use sd_jwt::SdJwtBuilder;
use serde_json::json;

const NONCE: &str = "nonce-test";
const VERIFIER_ID: &str = "did:test:verifier";

async fn setup_test() -> anyhow::Result<(Setup<IotaDocument, IotaDocument>, Credential, SdJwt)> {
  let setup: Setup<IotaDocument, IotaDocument> = setup_iotadocument(Some("issuer-key"), Some("holder-key")).await;

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

  let issuer_signer =
    StorageSigner::new_from_vm_fragment(&setup.issuer_storage, &setup.issuer_doc, &setup.issuer_method_fragment)
      .await?;
  let holder_kid = format!("{}#{}", setup.subject_doc.id(), &setup.subject_method_fragment);
  let mut sd_jwt = SdJwtBuilder::new(credential.to_jwt_claims(None)?)?
    .make_concealable("/vc/credentialSubject/degree/type")?
    .make_concealable("/vc/credentialSubject/degree/name")?
    .header(
      "kid",
      format!("{}#{}", setup.issuer_doc.id(), &setup.issuer_method_fragment),
    )
    .require_key_binding(RequiredKeyBinding::Kid(holder_kid.clone()))
    .finish(&issuer_signer, "EdDSA")
    .await?;

  let holder_signer = StorageSigner::new_from_vm_fragment(
    &setup.subject_storage,
    &setup.subject_doc,
    &setup.subject_method_fragment,
  )
  .await?;
  let kb_jwt = KeyBindingJwtBuilder::new()
    .aud(VERIFIER_ID)
    .nonce(NONCE)
    .iat(Timestamp::now_utc().to_unix())
    .header("kid", holder_kid)
    .finish(&sd_jwt, &Sha256Hasher, "EdDSA", &holder_signer)
    .await?;

  sd_jwt.attach_key_binding_jwt(kb_jwt);

  Ok((setup, credential, sd_jwt))
}

#[tokio::test]
async fn sd_jwt_validation() -> anyhow::Result<()> {
  let (setup, credential, sd_jwt) = setup_test().await?;
  let validator = SdJwtCredentialValidator::new(EdDSAJwsVerifier::default(), Sha256Hasher);
  let decoded_credential = validator
    .validate_credential::<_, Object>(
      &sd_jwt,
      std::slice::from_ref(&setup.issuer_doc),
      &JwtCredentialValidationOptions::default(),
    )
    .unwrap();
  assert_eq!(decoded_credential, credential);

  Ok(())
}

#[tokio::test]
async fn kb_validation() -> anyhow::Result<()> {
  let (setup, _credential, sd_jwt) = setup_test().await?;
  let validator = SdJwtCredentialValidator::new(EdDSAJwsVerifier::default(), Sha256Hasher);
  let options = KeyBindingJwtValidationOptions::new().nonce(NONCE).aud(VERIFIER_ID);
  let _kb_validation = validator.validate_key_binding_jwt(&sd_jwt, &setup.subject_doc, &options)?;

  Ok(())
}

#[tokio::test]
async fn kb_too_early() -> anyhow::Result<()> {
  let (setup, _credential, sd_jwt) = setup_test().await?;
  let validator = SdJwtCredentialValidator::new(EdDSAJwsVerifier::default(), Sha256Hasher);
  let timestamp = Timestamp::now_utc().checked_add(Duration::seconds(1)).unwrap();
  let options = KeyBindingJwtValidationOptions::new()
    .nonce(NONCE)
    .aud(VERIFIER_ID)
    .earliest_issuance_date(timestamp);
  let kb_validation = validator.validate_key_binding_jwt(&sd_jwt, &setup.subject_doc, &options);
  assert!(matches!(
    kb_validation.err().unwrap(),
    KeyBindingJwtError::IssuanceDate(_)
  ));

  Ok(())
}

#[tokio::test]
async fn kb_too_late() -> anyhow::Result<()> {
  let (setup, _credential, sd_jwt) = setup_test().await?;
  let validator = SdJwtCredentialValidator::new(EdDSAJwsVerifier::default(), Sha256Hasher);
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

  Ok(())
}
