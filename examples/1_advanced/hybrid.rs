// Copyright 2020-2025 IOTA Stiftung, Fondazione Links
// SPDX-License-Identifier: Apache-2.0

use examples::get_funded_client;
use examples::get_memstorage;
use examples::MemStorage;
use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_iota::core::Duration;
use identity_iota::core::FromJson;
use identity_iota::core::Object;
use identity_iota::core::Timestamp;
use identity_iota::core::Url;
use identity_iota::credential::Credential;
use identity_iota::credential::CredentialBuilder;
use identity_iota::credential::DecodedJwtCredential;
use identity_iota::credential::DecodedJwtPresentation;
use identity_iota::credential::FailFast;
use identity_iota::credential::Jwt;
use identity_iota::credential::JwtCredentialValidationOptions;
use identity_iota::credential::JwtCredentialValidatorHybrid;
use identity_iota::credential::JwtCredentialValidatorUtils;
use identity_iota::credential::JwtPresentationOptions;
use identity_iota::credential::JwtPresentationValidationOptions;
use identity_iota::credential::JwtPresentationValidatorHybrid;
use identity_iota::credential::JwtPresentationValidatorUtils;
use identity_iota::credential::Presentation;
use identity_iota::credential::PresentationBuilder;
use identity_iota::credential::Subject;
use identity_iota::credential::SubjectHolderRelationship;
use identity_iota::did::CoreDID;
use identity_iota::did::DID;
use identity_iota::document::verifiable::JwsVerificationOptions;
use identity_iota::iota::rebased::client::IdentityClient;
use identity_iota::iota::IotaDocument;
use identity_iota::iota_interaction::IotaKeySignature;
use identity_iota::resolver::Resolver;
use identity_iota::storage::JwkDocumentExtHybrid;
use identity_iota::storage::JwsSignatureOptions;
use identity_iota::verification::jwk::CompositeAlgId;
use identity_iota::verification::MethodScope;
use identity_pqc_verifier::PQCJwsVerifier;
use product_common::core_client::CoreClientReadOnly as _;
use secret_storage::Signer;
use serde_json::json;
use std::collections::HashMap;

async fn create_did_document<S>(
  client: &IdentityClient<S>,
  storage: &MemStorage,
  alg_id: CompositeAlgId,
) -> anyhow::Result<(IotaDocument, String)>
where
  S: Signer<IotaKeySignature> + Sync,
{
  // Create a new DID document with a placeholder DID.
  let mut document = IotaDocument::new(client.network_name());

  // New Verification Method containing a PQC key
  let fragment = document
    .generate_method_hybrid(storage, alg_id, None, MethodScope::VerificationMethod)
    .await?;

  let identity = client
    .create_identity(document)
    .finish()
    .build_and_execute(client)
    .await?
    .output;
  let did_document = identity.into();
  println!("Published DID document: {did_document:#}");

  Ok((did_document, fragment))
}

/// Demonstrates how to create a DID Document and publish it in a new Alias Output.
///
/// In this example we connect to a locally running private network, but it can be adapted
/// to run on any IOTA node by setting the network and faucet endpoints.
///
/// See the following instructions on running your own private network
/// https://github.com/iotaledger/hornet/tree/develop/private_tangle
#[tokio::main]
async fn main() -> anyhow::Result<()> {
  let issuer_storage = get_memstorage()?;
  let issuer_client = get_funded_client(&issuer_storage).await?;

  let (issuer_document, issuer_fragment) =
    create_did_document(&issuer_client, &issuer_storage, CompositeAlgId::IdMldsa44Ed25519).await?;

  let holder_storage = get_memstorage()?;
  let holder_client = get_funded_client(&holder_storage).await?;
  let (holder_document, holder_fragment) =
    create_did_document(&holder_client, &holder_storage, CompositeAlgId::IdMldsa44Ed25519).await?;

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
    .create_credential_jwt_hybrid(
      &credential,
      &issuer_storage,
      &issuer_fragment,
      &JwsSignatureOptions::default(),
      None,
    )
    .await?;

  println!("Credential JWT: {}", credential_jwt.as_str());

  // Before sending this credential to the holder the issuer wants to validate that some properties
  // of the credential satisfy their expectations.

  // Validate the credential's signature using the issuer's DID Document, the credential's semantic structure,
  // that the issuance date is not in the future and that the expiration date is not in the past:
  let decoded_credential: DecodedJwtCredential<Object> =
    JwtCredentialValidatorHybrid::with_signature_verifiers(EdDSAJwsVerifier::default(), PQCJwsVerifier::default())
      .validate::<_, Object>(
        &credential_jwt,
        &issuer_document,
        &JwtCredentialValidationOptions::default(),
        FailFast::FirstError,
      )
      .unwrap();

  println!("VC successfully validated");

  println!("Credential JSON > {:#}", decoded_credential.credential);

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
    .create_presentation_jwt_hybrid(
      &presentation,
      &holder_storage,
      &holder_fragment,
      &JwsSignatureOptions::default().nonce(challenge.to_owned()),
      &JwtPresentationOptions::default().expiration_date(expires),
    )
    .await?;

  // ===========================================================================
  // Step 6: Holder sends a verifiable presentation to the verifier.
  // ===========================================================================
  println!(
    "Sending presentation (as JWT) to the verifier: {}",
    presentation_jwt.as_str()
  );

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
  resolver.attach_iota_handler((*issuer_client).clone());

  // Resolve the holder's document.
  let holder_did: CoreDID = JwtPresentationValidatorUtils::extract_holder(&presentation_jwt)?;
  let holder: IotaDocument = resolver.resolve(&holder_did).await?;

  // Validate presentation. Note that this doesn't validate the included credentials.
  let presentation_validation_options =
    JwtPresentationValidationOptions::default().presentation_verifier_options(presentation_verifier_options);
  let presentation: DecodedJwtPresentation<Jwt> =
    JwtPresentationValidatorHybrid::with_signature_verifiers(EdDSAJwsVerifier::default(), PQCJwsVerifier::default())
      .validate(&presentation_jwt, &holder, &presentation_validation_options)?;

  // Concurrently resolve the issuers' documents.
  let jwt_credentials: &Vec<Jwt> = &presentation.presentation.verifiable_credential;
  let issuers: Vec<CoreDID> = jwt_credentials
    .iter()
    .map(JwtCredentialValidatorUtils::extract_issuer_from_jwt)
    .collect::<Result<Vec<CoreDID>, _>>()?;
  let issuers_documents: HashMap<CoreDID, IotaDocument> = resolver.resolve_multiple(&issuers).await?;

  // Validate the credentials in the presentation.
  let credential_validator =
    JwtCredentialValidatorHybrid::with_signature_verifiers(EdDSAJwsVerifier::default(), PQCJwsVerifier::default());
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

  // Note that we did not declare a latest allowed issuance date for credentials. This is because we only want to check
  // that the credentials do not have an issuance date in the future which is a default check.

  Ok(())
}
