// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//!  This example shows how to create a Verifiable Presentation and validate it.
//!  A Verifiable Presentation is the format in which a (collection of) Verifiable Credential(s) gets shared.
//!  It is signed by the subject, to prove control over the Verifiable Credential with a nonce or timestamp.
//!
//! cargo run --release --example 6_create_vp

use std::collections::HashMap;

use examples::create_did_document;
use examples::get_funded_client;
use examples::get_memstorage;
use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_iota::core::Object;
use identity_iota::credential::DecodedJwtCredential;
use identity_iota::credential::DecodedJwtPresentation;
use identity_iota::credential::Jwt;
use identity_iota::credential::JwtCredentialValidatorUtils;
use identity_iota::credential::JwtPresentationOptions;
use identity_iota::credential::JwtPresentationValidationOptions;
use identity_iota::credential::JwtPresentationValidator;
use identity_iota::credential::JwtPresentationValidatorUtils;
use identity_iota::credential::Presentation;
use identity_iota::credential::PresentationBuilder;
use identity_iota::did::CoreDID;
use identity_iota::document::verifiable::JwsVerificationOptions;
use identity_iota::storage::JwkDocumentExt;
use identity_iota::storage::JwsSignatureOptions;

use identity_iota::core::json;
use identity_iota::core::Duration;
use identity_iota::core::FromJson;
use identity_iota::core::Timestamp;
use identity_iota::core::Url;
use identity_iota::credential::Credential;
use identity_iota::credential::CredentialBuilder;
use identity_iota::credential::FailFast;
use identity_iota::credential::JwtCredentialValidationOptions;
use identity_iota::credential::JwtCredentialValidator;
use identity_iota::credential::Subject;
use identity_iota::credential::SubjectHolderRelationship;
use identity_iota::did::DID;
use identity_iota::iota::IotaDocument;
use identity_iota::resolver::Resolver;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  // ===========================================================================
  // Step 1: Create identities for the issuer and the holder.
  // ===========================================================================

  // create new issuer account with did document
  let issuer_storage = get_memstorage()?;
  let issuer_identity_client = get_funded_client(&issuer_storage).await?;
  let (issuer_document, issuer_vm_fragment) = create_did_document(&issuer_identity_client, &issuer_storage).await?;

  // create new holder account with did document
  let holder_storage = get_memstorage()?;
  let holder_identity_client = get_funded_client(&holder_storage).await?;
  let (holder_document, holder_vm_fragment) = create_did_document(&holder_identity_client, &holder_storage).await?;

  // create new client for verifier
  // new client actually not necessary, but shows, that client is independent from issuer and holder
  let verifier_storage = &get_memstorage()?;
  let verifier_client = get_funded_client(verifier_storage).await?;

  // ===========================================================================
  // Step 2: Issuer creates and signs a Verifiable Credential.
  // ===========================================================================

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
  let credential: Credential = CredentialBuilder::default()
    .id(Url::parse("https://example.edu/credentials/3732")?)
    .issuer(Url::parse(issuer_document.id().as_str())?)
    .type_("UniversityDegreeCredential")
    .subject(subject)
    .build()?;

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
  JwtCredentialValidator::with_signature_verifier(EdDSAJwsVerifier::default())
    .validate::<_, Object>(
      &credential_jwt,
      &issuer_document,
      &JwtCredentialValidationOptions::default(),
      FailFast::FirstError,
    )
    .unwrap();

  println!("VC successfully validated");

  // ===========================================================================
  // Step 3: Issuer sends the Verifiable Credential to the holder.
  // ===========================================================================
  println!("Sending credential (as JWT) to the holder: {credential:#}");

  // ===========================================================================
  // Step 4: Verifier sends the holder a challenge and requests a signed Verifiable Presentation.
  // ===========================================================================

  // A unique random challenge generated by the requester per presentation can mitigate replay attacks.
  let challenge: &str = "475a7984-1bb5-4c4c-a56f-822bccd46440";

  // The verifier and holder also agree that the signature should have an expiry date
  // 10 minutes from now.
  let expires: Timestamp = Timestamp::now_utc().checked_add(Duration::minutes(10)).unwrap();

  // ===========================================================================
  // Step 5: Holder creates and signs a verifiable presentation from the issued credential.
  // ===========================================================================

  // Create an unsigned Presentation from the previously issued Verifiable Credential.
  let presentation: Presentation<Jwt> =
    PresentationBuilder::new(holder_document.id().to_url().into(), Default::default())
      .credential(credential_jwt)
      .build()?;

  // Create a JWT verifiable presentation using the holder's verification method
  // and include the requested challenge and expiry timestamp.
  let presentation_jwt: Jwt = holder_document
    .create_presentation_jwt(
      &presentation,
      &holder_storage,
      &holder_vm_fragment,
      &JwsSignatureOptions::default().nonce(challenge.to_owned()),
      &JwtPresentationOptions::default().expiration_date(expires),
    )
    .await?;

  // ===========================================================================
  // Step 6: Holder sends a verifiable presentation to the verifier.
  // ===========================================================================
  println!("Sending presentation (as JWT) to the verifier: {presentation:#}");

  // ===========================================================================
  // Step 7: Verifier receives the Verifiable Presentation and verifies it.
  // ===========================================================================

  // The verifier wants the following requirements to be satisfied:
  // - JWT verification of the presentation (including checking the requested challenge to mitigate replay attacks)
  // - JWT verification of the credentials.
  // - The presentation holder must always be the subject, regardless of the presence of the nonTransferable property
  // - The issuance date must not be in the future.

  let presentation_verifier_options: JwsVerificationOptions =
    JwsVerificationOptions::default().nonce(challenge.to_owned());

  let mut resolver: Resolver<IotaDocument> = Resolver::new();
  resolver.attach_iota_handler((*verifier_client).clone());

  // Resolve the holder's document.
  let holder_did: CoreDID = JwtPresentationValidatorUtils::extract_holder(&presentation_jwt)?;
  let holder: IotaDocument = resolver.resolve(&holder_did).await?;

  // Validate presentation. Note that this doesn't validate the included credentials.
  let presentation_validation_options =
    JwtPresentationValidationOptions::default().presentation_verifier_options(presentation_verifier_options);
  let presentation: DecodedJwtPresentation<Jwt> = JwtPresentationValidator::with_signature_verifier(
    EdDSAJwsVerifier::default(),
  )
  .validate(&presentation_jwt, &holder, &presentation_validation_options)?;

  // Concurrently resolve the issuers' documents.
  let jwt_credentials: &Vec<Jwt> = &presentation.presentation.verifiable_credential;
  let issuers: Vec<CoreDID> = jwt_credentials
    .iter()
    .map(JwtCredentialValidatorUtils::extract_issuer_from_jwt)
    .collect::<Result<Vec<CoreDID>, _>>()?;
  let issuers_documents: HashMap<CoreDID, IotaDocument> = resolver.resolve_multiple(&issuers).await?;

  // Validate the credentials in the presentation.
  let credential_validator: JwtCredentialValidator<EdDSAJwsVerifier> =
    JwtCredentialValidator::with_signature_verifier(EdDSAJwsVerifier::default());
  let validation_options: JwtCredentialValidationOptions = JwtCredentialValidationOptions::default()
    .subject_holder_relationship(holder_did.to_url().into(), SubjectHolderRelationship::AlwaysSubject);

  for (index, jwt_vc) in jwt_credentials.iter().enumerate() {
    // SAFETY: Indexing should be fine since we extracted the DID from each credential and resolved it.
    let issuer_document: &IotaDocument = &issuers_documents[&issuers[index]];

    let _decoded_credential: DecodedJwtCredential<Object> = credential_validator
      .validate::<_, Object>(jwt_vc, issuer_document, &validation_options, FailFast::FirstError)
      .unwrap();
  }

  // Since no errors were thrown by `verify_presentation` we know that the validation was successful.
  println!("VP successfully validated: {:#?}", presentation.presentation);

  // Note that we did not declare a latest allowed issuance date for credentials. This is because we only want to
  // check // that the credentials do not have an issuance date in the future which is a default check.
  Ok(())
}
