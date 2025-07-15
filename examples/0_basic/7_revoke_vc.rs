// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! This example shows how to revoke a verifiable credential.
//! It demonstrates two methods for revocation. The first uses a revocation bitmap of type `RevocationBitmap2022`,
//! while the second method simply removes the verification method (public key) that signed the credential
//! from the DID Document of the issuer.
//!
//! Note: make sure `API_ENDPOINT` and `FAUCET_ENDPOINT` are set to the correct network endpoints.
//!
//! cargo run --release --example 7_revoke_vc

use anyhow::anyhow;
use examples::create_did_document;
use examples::get_funded_client;
use examples::get_memstorage;
use examples::TEST_GAS_BUDGET;
use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_iota::core::json;
use identity_iota::core::FromJson;
use identity_iota::core::Object;
use identity_iota::core::Url;
use identity_iota::credential::CompoundCredentialValidationError;
use identity_iota::credential::Credential;
use identity_iota::credential::CredentialBuilder;
use identity_iota::credential::DecodedJwtCredential;
use identity_iota::credential::FailFast;
use identity_iota::credential::Jwt;
use identity_iota::credential::JwtCredentialValidationOptions;
use identity_iota::credential::JwtCredentialValidator;
use identity_iota::credential::JwtCredentialValidatorUtils;
use identity_iota::credential::JwtValidationError;
use identity_iota::credential::RevocationBitmap;
use identity_iota::credential::RevocationBitmapStatus;
use identity_iota::credential::Status;
use identity_iota::credential::Subject;
use identity_iota::did::DIDUrl;
use identity_iota::did::DID;
use identity_iota::document::Service;
use identity_iota::iota::IotaDocument;
use identity_iota::prelude::IotaDID;
use identity_iota::resolver::Resolver;
use identity_iota::storage::JwkDocumentExt;
use identity_iota::storage::JwsSignatureOptions;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  // ===========================================================================
  // Create a Verifiable Credential.
  // ===========================================================================

  // create new issuer account with did document
  let issuer_storage = get_memstorage()?;
  let issuer_identity_client = get_funded_client(&issuer_storage).await?;
  let (mut issuer_document, issuer_vm_fragment) = create_did_document(&issuer_identity_client, &issuer_storage).await?;

  // create new holder account with did document
  let holder_storage = get_memstorage()?;
  let holder_identity_client = get_funded_client(&holder_storage).await?;
  let (holder_document, _) = create_did_document(&holder_identity_client, &holder_storage).await?;

  // Create a new empty revocation bitmap. No credential is revoked yet.
  let revocation_bitmap: RevocationBitmap = RevocationBitmap::new();

  // Add the revocation bitmap to the DID document of the issuer as a service.
  let service_id: DIDUrl = issuer_document.id().to_url().join("#my-revocation-service")?;
  let service: Service = revocation_bitmap.to_service(service_id)?;

  assert!(issuer_document.insert_service(service).is_ok());

  // Resolve the latest output and update it with the given document.
  issuer_document = issuer_identity_client
    .publish_did_document_update(issuer_document.clone(), TEST_GAS_BUDGET)
    .await?;

  println!("DID Document > {issuer_document:#}");

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
  // The issuer also chooses a unique `RevocationBitmap` index to be able to revoke it later.
  let service_url = issuer_document.id().to_url().join("#my-revocation-service")?;
  let credential_index: u32 = 5;
  let status: Status = RevocationBitmapStatus::new(service_url, credential_index).into();

  // Build credential using subject above and issuer.
  let credential: Credential = CredentialBuilder::default()
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
  // Validate the credential's signature using the issuer's DID Document.
  validator.validate::<_, Object>(
    &credential_jwt,
    &issuer_document,
    &JwtCredentialValidationOptions::default(),
    FailFast::FirstError,
  )?;

  // ===========================================================================
  // Revocation of the Verifiable Credential.
  // ===========================================================================

  // Update the RevocationBitmap service in the issuer's DID Document.
  // This revokes the credential's unique index.
  issuer_document.revoke_credentials("my-revocation-service", &[credential_index])?;

  // Publish the changes.
  issuer_document = issuer_identity_client
    .publish_did_document_update(issuer_document.clone(), TEST_GAS_BUDGET)
    .await?;

  let validation_result: std::result::Result<DecodedJwtCredential, CompoundCredentialValidationError> = validator
    .validate(
      &credential_jwt,
      &issuer_document,
      &JwtCredentialValidationOptions::default(),
      FailFast::FirstError,
    );

  // We expect validation to no longer succeed because the credential was revoked.
  assert!(matches!(
    validation_result.unwrap_err().validation_errors[0],
    JwtValidationError::Revoked
  ));

  // ===========================================================================
  // Alternative revocation of the Verifiable Credential.
  // ===========================================================================

  // By removing the verification method, that signed the credential, from the issuer's DID document,
  // we effectively revoke the credential, as it will no longer be possible to validate the signature.
  let original_method: DIDUrl = issuer_document
    .resolve_method(&issuer_vm_fragment, None)
    .ok_or_else(|| anyhow!("expected method to exist"))?
    .id()
    .clone();
  issuer_document
    .remove_method(&original_method)
    .ok_or_else(|| anyhow!("expected method to exist"))?;

  // Publish the changes.
  issuer_identity_client
    .publish_did_document_update(issuer_document.clone(), TEST_GAS_BUDGET)
    .await?;

  // We expect the verifiable credential to be revoked.
  let mut resolver: Resolver<IotaDocument> = Resolver::new();
  resolver.attach_iota_handler((*holder_identity_client).clone());
  let resolved_issuer_did: IotaDID = JwtCredentialValidatorUtils::extract_issuer_from_jwt(&credential_jwt)?;
  let resolved_issuer_doc: IotaDocument = resolver.resolve(&resolved_issuer_did).await?;

  let validation_result = validator.validate::<_, Object>(
    &credential_jwt,
    &resolved_issuer_doc,
    &JwtCredentialValidationOptions::default(),
    FailFast::FirstError,
  );

  println!("VC validation result: {validation_result:?}");
  assert!(validation_result.is_err());

  println!("Credential successfully revoked!");

  Ok(())
}
