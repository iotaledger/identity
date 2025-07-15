// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use examples::create_did_document;
use examples::get_funded_client;
use examples::get_memstorage;
use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_iota::core::FromJson;
use identity_iota::core::Object;
use identity_iota::core::ToJson;
use identity_iota::core::Url;
use identity_iota::credential::status_list_2021::StatusList2021;
use identity_iota::credential::status_list_2021::StatusList2021Credential;
use identity_iota::credential::status_list_2021::StatusList2021CredentialBuilder;
use identity_iota::credential::status_list_2021::StatusList2021Entry;
use identity_iota::credential::status_list_2021::StatusPurpose;
use identity_iota::credential::Credential;
use identity_iota::credential::CredentialBuilder;
use identity_iota::credential::FailFast;
use identity_iota::credential::Issuer;
use identity_iota::credential::Jwt;
use identity_iota::credential::JwtCredentialValidationOptions;
use identity_iota::credential::JwtCredentialValidator;
use identity_iota::credential::JwtCredentialValidatorUtils;
use identity_iota::credential::JwtValidationError;
use identity_iota::credential::Status;
use identity_iota::credential::StatusCheck;
use identity_iota::credential::Subject;
use identity_iota::did::DID;
use identity_iota::storage::JwkDocumentExt;
use identity_iota::storage::JwsSignatureOptions;

use serde_json::json;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  // ===========================================================================
  // Create a Verifiable Credential.
  // ===========================================================================

  // create new issuer account with did document
  let issuer_storage = get_memstorage()?;
  let issuer_identity_client = get_funded_client(&issuer_storage).await?;
  let (issuer_document, issuer_vm_fragment) = create_did_document(&issuer_identity_client, &issuer_storage).await?;

  // create new holder account with did document
  let holder_storage = get_memstorage()?;
  let holder_identity_client = get_funded_client(&holder_storage).await?;
  let (holder_document, _) = create_did_document(&holder_identity_client, &holder_storage).await?;

  // Create a new empty status list. No credentials have been revoked yet.
  let status_list: StatusList2021 = StatusList2021::default();

  // Create a status list credential so that the status list can be stored anywhere.
  // The issuer makes this credential available on `http://example.com/credential/status`.
  // For the purposes of this example, the credential will be used directly without fetching.
  let status_list_credential: StatusList2021Credential = StatusList2021CredentialBuilder::new(status_list)
    .purpose(StatusPurpose::Revocation)
    .subject_id(Url::parse("http://example.com/credential/status")?)
    .issuer(Issuer::Url(issuer_document.id().to_url().into()))
    .build()?;

  println!("Status list credential > {status_list_credential:#}");

  // Create a credential subject indicating the degree earned by Alice.
  let subject: Subject = Subject::from_json_value(json!({
    "id": holder_document.id().as_str(),
    "name": "Alice",
    "degree": {
      "type": "BachelorDegree",
      "name": "Bachelor of Science and Arts",
    },
    "GPA": "4.0",
  }))?;

  // Create an unsigned `UniversityDegree` credential for Alice.
  // The issuer also chooses a unique `StatusList2021` index to be able to revoke it later.
  let credential_index: usize = 420;
  let status: Status = StatusList2021Entry::new(
    status_list_credential.id().cloned().unwrap(),
    status_list_credential.purpose(),
    credential_index,
    None,
  )
  .into();

  // Build credential using subject above, status, and issuer.
  let mut credential: Credential = CredentialBuilder::default()
    .id(Url::parse("https://example.edu/credentials/3732")?)
    .issuer(Url::parse(issuer_document.id().as_str())?)
    .type_("UniversityDegreeCredential")
    .status(status)
    .subject(subject)
    .build()?;

  println!("Credential JSON > {credential:#}");

  let credential_jwt: Jwt = issuer_document
    .create_credential_jwt(
      &credential,
      &issuer_storage,
      &issuer_vm_fragment,
      &JwsSignatureOptions::default(),
      None,
    )
    .await?;

  let validator: JwtCredentialValidator<EdDSAJwsVerifier> =
    JwtCredentialValidator::with_signature_verifier(EdDSAJwsVerifier::default());

  // The validator has no way of retrieving the status list to check for the
  // revocation of the credential. Let's skip that pass and perform the operation manually.
  let mut validation_options = JwtCredentialValidationOptions::default();
  validation_options.status = StatusCheck::SkipUnsupported;
  // Validate the credential's signature using the issuer's DID Document.
  validator.validate::<_, Object>(
    &credential_jwt,
    &issuer_document,
    &validation_options,
    FailFast::FirstError,
  )?;
  // Check manually for revocation
  JwtCredentialValidatorUtils::check_status_with_status_list_2021(
    &credential,
    &status_list_credential,
    StatusCheck::Strict,
  )?;
  println!("Credential is valid.");

  let status_list_credential_json = status_list_credential.to_json().unwrap();

  // ===========================================================================
  // Revocation of the Verifiable Credential.
  // ===========================================================================

  // At a later time, the issuer university found out that Alice cheated in her final exam.
  // The issuer will revoke Alice's credential.

  // The issuer retrieves the status list credential.
  let mut status_list_credential =
    serde_json::from_str::<StatusList2021Credential>(status_list_credential_json.as_str()).unwrap();

  // Set the value of the chosen index entry to true to revoke the credential
  status_list_credential.set_credential_status(&mut credential, credential_index, true)?;

  // validate the credential and check for revocation
  validator.validate::<_, Object>(
    &credential_jwt,
    &issuer_document,
    &validation_options,
    FailFast::FirstError,
  )?;
  let revocation_result = JwtCredentialValidatorUtils::check_status_with_status_list_2021(
    &credential,
    &status_list_credential,
    StatusCheck::Strict,
  );

  assert!(revocation_result.is_err_and(|e| matches!(e, JwtValidationError::Revoked)));
  println!("The credential has been successfully revoked.");

  Ok(())
}
