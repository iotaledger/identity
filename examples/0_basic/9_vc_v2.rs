// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! This example shows how to create a Verifiable Credential and validate it.
//! In this example, alice takes the role of the subject, while we also have an issuer.
//! The issuer signs a UniversityDegreeCredential type verifiable credential with Alice's name and DID.
//! This Verifiable Credential can be verified by anyone, allowing Alice to take control of it and share it with
//! whomever they please.
//!
//! cargo run --release --example 9_vc_v2

use examples::create_did_document;
use examples::get_funded_client;
use examples::get_memstorage;
use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_iota::core::Object;

use identity_iota::credential::DecodedJwtCredentialV2;
use identity_iota::credential::Jwt;
use identity_iota::credential::JwtCredentialValidationOptions;
use identity_iota::credential::JwtCredentialValidator;
use identity_iota::storage::JwkDocumentExt;
use identity_iota::storage::JwsSignatureOptions;

use identity_iota::core::json;
use identity_iota::core::FromJson;
use identity_iota::core::Url;
use identity_iota::credential::CredentialBuilder;
use identity_iota::credential::CredentialV2;
use identity_iota::credential::FailFast;
use identity_iota::credential::Subject;
use identity_iota::did::DID;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  // create new issuer account with did document
  let issuer_storage = get_memstorage()?;
  let issuer_identity_client = get_funded_client(&issuer_storage).await?;
  let (issuer_document, issuer_vm_fragment) = create_did_document(&issuer_identity_client, &issuer_storage).await?;

  // create new holder account with did document
  let holder_storage = get_memstorage()?;
  let holder_identity_client = get_funded_client(&holder_storage).await?;
  let (holder_document, _) = create_did_document(&holder_identity_client, &holder_storage).await?;

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

  // Build credential using subject above and issuer.
  let credential: CredentialV2 = CredentialBuilder::default()
    .id(Url::parse("https://example.edu/credentials/3732")?)
    .issuer(Url::parse(issuer_document.id().as_str())?)
    .type_("UniversityDegreeCredential")
    .subject(subject)
    .build_v2()?;

  let credential_jwt: Jwt = issuer_document
    .create_credential_jwt(
      &credential,
      &issuer_storage,
      &issuer_vm_fragment,
      &JwsSignatureOptions::default(),
      None,
    )
    .await?;

  // Before sending this credential to the holder the issuer wants to validate that some properties
  // of the credential satisfy their expectations.

  // Validate the credential's signature using the issuer's DID Document, the credential's semantic structure,
  // that the issuance date is not in the future and that the expiration date is not in the past:
  let decoded_credential: DecodedJwtCredentialV2<Object> =
    JwtCredentialValidator::with_signature_verifier(EdDSAJwsVerifier::default())
      .validate_v2::<_, Object>(
        &credential_jwt,
        &issuer_document,
        &JwtCredentialValidationOptions::default(),
        FailFast::FirstError,
      )
      .unwrap();

  println!("VC successfully validated");

  println!("Credential JSON > {:#}", decoded_credential.credential);

  Ok(())
}
