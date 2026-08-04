// Copyright 2020-2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context as _;
use examples::create_did_document;
use examples::get_funded_client;
use examples::get_iota_endpoint;
use examples::get_memstorage;
use examples::get_notarization_client;
use examples::MemStorage;
use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_iota::core::FromJson as _;
use identity_iota::core::Object;
use identity_iota::core::ToJson;
use identity_iota::credential::bitstring_status_list_v1::BitstringStatusListCredential;
use identity_iota::credential::bitstring_status_list_v1::BitstringStatusListCredentialBuilder;
use identity_iota::credential::bitstring_status_list_v1::BitstringStatusListEntry;
use identity_iota::credential::bitstring_status_list_v1::BitstringStatusListEntryBuilder;
use identity_iota::credential::bitstring_status_list_v1::StatusPurpose;
use identity_iota::credential::CredentialBuilder;
use identity_iota::credential::CredentialV2;
use identity_iota::credential::DecodedJwtCredentialV2;
use identity_iota::credential::FailFast;
use identity_iota::credential::FailFast::FirstError;
use identity_iota::credential::JwtCredentialValidationOptions;
use identity_iota::credential::JwtCredentialValidator;
use identity_iota::credential::JwtVcV2;
use identity_iota::credential::StatusCheck;
use identity_iota::credential::Subject;
use identity_iota::did::DID;
use identity_iota::iota::IotaDID;
use identity_iota::iota::IotaDocument;
use identity_iota::iota_interaction::IotaKeySignature;
use identity_storage::JwkDocumentExt as _;
use identity_storage::JwsSignatureOptions;
use iota_caip::iota::resolver::Resolver as IotaResourceResolver;
use iota_caip::iota::IotaNetwork;
use iota_sdk_types::ObjectId;
use notarization::core::types::OnChainNotarization;
use notarization::core::types::State;
use notarization::NotarizationClient;
use product_common::core_client::CoreClient as _;
use secret_storage::Signer;
use serde_json::json;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  let issuer_storage = get_memstorage()?;
  let issuer_client = get_funded_client(&issuer_storage).await?;
  let (issuer_document, issuer_vm_fragment) = create_did_document(&issuer_client, &issuer_storage).await?;
  let notarization_client = get_notarization_client(issuer_client.signer().clone()).await?;

  let holder_storage = get_memstorage()?;
  let holder_client = get_funded_client(&holder_storage).await?;
  let (holder_document, _holder_vm_fragment) = create_did_document(&holder_client, &holder_storage).await?;

  // Create and notarize a Bitstring Status List Credential to handle VC revocations.
  let (notarized_status_list, mut status_list_credential) = create_notarized_bitstring_status_list(
    &issuer_document,
    &issuer_storage,
    &issuer_vm_fragment,
    &notarization_client,
  )
  .await?;
  let status_list_irl = notarized_status_list
    .iota_resource_locator_builder(issuer_client.network())
    .data();

  // Create a Bitstring Status List entry referencing the notarized status list credential.
  let status_list_entry = BitstringStatusListEntryBuilder::new()
    .credential(status_list_irl.into())
    .index(42)
    .status_purpose(StatusPurpose::Revocation)
    .build()?;

  let revocable_credential = make_revocable_credential(
    &issuer_document,
    &issuer_storage,
    &issuer_vm_fragment,
    holder_document.id(),
    &status_list_entry,
  )
  .await?;

  // Validate credential, ensuring it is not revoked.
  println!("Validating credential...");
  let options = JwtCredentialValidationOptions::default().status_check(StatusCheck::SkipAll);
  let DecodedJwtCredentialV2 { credential, .. } = JwtCredentialValidator::with_signature_verifier(
    EdDSAJwsVerifier::default(),
  )
  .validate_v2(&revocable_credential, &issuer_document, &options, FirstError)?;
  assert!(check_credential_status(&credential, issuer_client.network(), &issuer_document).await?);
  println!("Credential is valid and not revoked!");

  // Revoke the credential.
  status_list_credential.update().set_entry(&status_list_entry, true)?;
  update_notarized_bitstring_status_list(
    &issuer_document,
    &issuer_storage,
    &issuer_vm_fragment,
    *notarized_status_list.id.object_id(),
    &status_list_credential,
    &notarization_client,
  )
  .await?;
  println!("Issuer revokes the credential...");

  // Validate the credential status again, this time ensuring it is revoked.
  println!("Validating credential...");
  assert!(!check_credential_status(&credential, issuer_client.network(), &issuer_document).await?);
  println!("Invalid credential status detected! Credential has been revoked.");

  Ok(())
}

async fn create_notarized_bitstring_status_list<S>(
  issuer_document: &IotaDocument,
  issuer_storage: &MemStorage,
  issuer_fragment: &str,
  notarization_client: &NotarizationClient<S>,
) -> anyhow::Result<(OnChainNotarization, BitstringStatusListCredential)>
where
  S: Signer<IotaKeySignature> + Sync,
{
  let status_list_credential = BitstringStatusListCredentialBuilder::new()
    .issuer(issuer_document.id().to_url())
    .status_purposes(StatusPurpose::Revocation)
    .build()?;
  let jwt_status_list_credential = issuer_document
    .create_credential_v2_jwt(
      &status_list_credential.clone().into(),
      &issuer_storage,
      &issuer_fragment,
      &JwsSignatureOptions::default(),
    )
    .await?;

  Ok((
    notarization_client
      .create_dynamic_notarization()
      .with_string_state(jwt_status_list_credential.as_str().to_owned(), None)
      .finish()
      .build_and_execute(notarization_client)
      .await?
      .output,
    status_list_credential,
  ))
}

async fn update_notarized_bitstring_status_list<S>(
  issuer_document: &IotaDocument,
  issuer_storage: &MemStorage,
  issuer_fragment: &str,
  notarization_id: ObjectId,
  status_list_credential: &BitstringStatusListCredential,
  notarization_client: &NotarizationClient<S>,
) -> anyhow::Result<()>
where
  S: Signer<IotaKeySignature> + Sync,
{
  let jwt = issuer_document
    .create_credential_v2_jwt(
      &status_list_credential.clone().into(),
      &issuer_storage,
      &issuer_fragment,
      &JwsSignatureOptions::default(),
    )
    .await?;

  notarization_client
    .update_state(State::from_string(jwt.as_str().to_owned(), None), notarization_id)
    .build_and_execute(notarization_client)
    .await?;

  Ok(())
}

async fn make_revocable_credential(
  issuer_document: &IotaDocument,
  issuer_storage: &MemStorage,
  issuer_fragment: &str,
  holder_id: &IotaDID,
  status_entry: &BitstringStatusListEntry,
) -> anyhow::Result<JwtVcV2> {
  let credential = CredentialBuilder::new(Object::new())
    .id("https://example.org/credentials/1872".parse()?)
    .issuer(issuer_document.id().to_url())
    .subject(Subject::from_json_value(json!({
      "id": holder_id.as_str(),
      "name": "Alice",
      "degree": {
        "type": "BachelorDegree",
        "name": "Bachelor of Science and Arts",
      },
      "GPA": "4.0",
    }))?)
    .status(status_entry.clone())
    .build_v2()?;

  println!("Issuing credential: {}", credential.to_json_pretty()?);

  Ok(
    issuer_document
      .create_credential_v2_jwt(
        &credential,
        issuer_storage,
        issuer_fragment,
        &JwsSignatureOptions::default(),
      )
      .await?,
  )
}

async fn check_credential_status(
  credential: &CredentialV2,
  network: &str,
  issuer_document: &IotaDocument,
) -> anyhow::Result<bool> {
  let Some(status) = &credential.credential_status else {
    return Ok(true);
  };
  let status_entry = BitstringStatusListEntry::try_from(status)?;
  let custom_network = IotaNetwork::custom(network).expect("valid IOTA network");
  let iota_resource_resolver =
    IotaResourceResolver::new_with_custom_networks(vec![(custom_network, get_iota_endpoint())]);

  let jwt_status_list_credential = iota_resource_resolver
    .resolve(status_entry.status_list_credential())
    .await?
    .as_str()
    .context("failed to resolve status list credential")
    .and_then(|jwt| JwtVcV2::parse(jwt).context("failed to parse status list credential"))?;
  let status_list_credential = JwtCredentialValidator::with_signature_verifier(EdDSAJwsVerifier::default())
    .validate_v2(
      &jwt_status_list_credential,
      issuer_document,
      &JwtCredentialValidationOptions::default(),
      FailFast::FirstError,
    )
    .context("failed to validate status list credential")
    .and_then(|decoded| {
      BitstringStatusListCredential::try_from(decoded.credential)
        .context("failed to convert to BitstringStatusListCredential")
    })?;

  Ok(
    status_list_credential
      .entry(status_entry.status_list_index(), status_entry.status_purpose())?
      .valid,
  )
}
