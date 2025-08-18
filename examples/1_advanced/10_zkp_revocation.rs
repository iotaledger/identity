// Copyright 2020-2024 IOTA Stiftung, Fondazione Links
// SPDX-License-Identifier: Apache-2.0

use examples::get_funded_client;
use examples::MemStorage;
use examples::TEST_GAS_BUDGET;

use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_iota::core::json;
use identity_iota::core::Duration;
use identity_iota::core::FromJson;
use identity_iota::core::Object;
use identity_iota::core::Timestamp;
use identity_iota::core::Url;
use identity_iota::credential::Credential;
use identity_iota::credential::CredentialBuilder;
use identity_iota::credential::DecodedJwtPresentation;
use identity_iota::credential::FailFast;
use identity_iota::credential::Jpt;
use identity_iota::credential::JptCredentialValidationOptions;
use identity_iota::credential::JptCredentialValidator;
use identity_iota::credential::JptCredentialValidatorUtils;
use identity_iota::credential::JptPresentationValidationOptions;
use identity_iota::credential::JptPresentationValidator;
use identity_iota::credential::JptPresentationValidatorUtils;
use identity_iota::credential::JwpCredentialOptions;
use identity_iota::credential::JwpPresentationOptions;
use identity_iota::credential::Jwt;
use identity_iota::credential::JwtPresentationOptions;
use identity_iota::credential::JwtPresentationValidationOptions;
use identity_iota::credential::JwtPresentationValidator;
use identity_iota::credential::JwtPresentationValidatorUtils;
use identity_iota::credential::JwtValidationError;
use identity_iota::credential::Presentation;
use identity_iota::credential::PresentationBuilder;
use identity_iota::credential::RevocationBitmap;
use identity_iota::credential::RevocationTimeframeStatus;
use identity_iota::credential::SelectiveDisclosurePresentation;
use identity_iota::credential::Status;
use identity_iota::credential::StatusCheck;
use identity_iota::credential::Subject;
use identity_iota::credential::SubjectHolderRelationship;
use identity_iota::did::CoreDID;
use identity_iota::did::DIDUrl;
use identity_iota::did::DID;
use identity_iota::document::verifiable::JwsVerificationOptions;
use identity_iota::document::Service;
use identity_iota::iota::rebased::client::IdentityClient;
use identity_iota::iota::rebased::client::IotaKeySignature;
use identity_iota::iota::IotaDocument;
use identity_iota::iota_interaction::OptionalSync;
use identity_iota::resolver::Resolver;
use identity_iota::storage::JwkDocumentExt;
use identity_iota::storage::JwkMemStore;
use identity_iota::storage::JwpDocumentExt;
use identity_iota::storage::JwsSignatureOptions;
use identity_iota::storage::KeyIdMemstore;
use identity_iota::storage::KeyType;
use identity_iota::storage::TimeframeRevocationExtension;
use identity_iota::verification::jws::JwsAlgorithm;
use identity_iota::verification::MethodScope;
use identity_storage::Storage;
use jsonprooftoken::jpa::algs::ProofAlgorithm;
use product_common::network_name::NetworkName;
use product_common::transaction::TransactionOutput;
use secret_storage::Signer;
use std::thread;
use std::time::Duration as SleepDuration;

async fn create_did<K, I, S>(
  identity_client: &IdentityClient<S>,
  storage: &Storage<K, I>,
  key_type: KeyType,
  alg: Option<JwsAlgorithm>,
  proof_alg: Option<ProofAlgorithm>,
) -> anyhow::Result<(IotaDocument, String)>
where
  K: identity_storage::JwkStorage + identity_storage::JwkStorageBbsPlusExt,
  I: identity_storage::KeyIdStorage,
  S: Signer<IotaKeySignature> + OptionalSync,
{
  // Get the network name.
  let network_name: &NetworkName = identity_client.network();

  // Create a new DID document with a placeholder DID.
  let mut unpublished: IotaDocument = IotaDocument::new(network_name);

  // New Verification Method containing a BBS+ key
  let fragment = if let Some(alg) = alg {
    unpublished
      .generate_method(storage, key_type, alg, None, MethodScope::VerificationMethod)
      .await?
  } else if let Some(proof_alg) = proof_alg {
    let fragment = unpublished
      .generate_method_jwp(storage, key_type, proof_alg, None, MethodScope::VerificationMethod)
      .await?;

    // Create a new empty revocation bitmap. No credential is revoked yet.
    let revocation_bitmap: RevocationBitmap = RevocationBitmap::new();

    // Add the revocation bitmap to the DID document of the issuer as a service.
    let service_id: DIDUrl = unpublished.id().to_url().join("#my-revocation-service")?;
    let service: Service = revocation_bitmap.to_service(service_id)?;

    assert!(unpublished.insert_service(service).is_ok());

    fragment
  } else {
    return Err(anyhow::Error::msg("You have to pass at least one algorithm"));
  };

  let TransactionOutput::<IotaDocument> { output: document, .. } = identity_client
    .publish_did_document(unpublished)
    .with_gas_budget(TEST_GAS_BUDGET)
    .build_and_execute(identity_client)
    .await?;

  println!("Published DID document: {document:#}");

  Ok((document, fragment))
}

/// Demonstrates how to revoke a credential.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
  // ===========================================================================
  // Step 1: Create identities and for the issuer and the holder.
  // ===========================================================================
  let storage_issuer: MemStorage = MemStorage::new(JwkMemStore::new(), KeyIdMemstore::new());

  let storage_holder: MemStorage = MemStorage::new(JwkMemStore::new(), KeyIdMemstore::new());

  let issuer_identity_client = get_funded_client(&storage_issuer).await?;

  let holder_identity_client = get_funded_client(&storage_holder).await?;

  let (mut issuer_document, fragment_issuer): (IotaDocument, String) = create_did(
    &issuer_identity_client,
    &storage_issuer,
    JwkMemStore::BLS12381G2_KEY_TYPE,
    None,
    Some(ProofAlgorithm::BBS),
  )
  .await?;

  let (holder_document, fragment_holder): (IotaDocument, String) = create_did(
    &holder_identity_client,
    &storage_holder,
    JwkMemStore::ED25519_KEY_TYPE,
    Some(JwsAlgorithm::EdDSA),
    None,
  )
  .await?;

  // Create a credential subject indicating the degree earned by Alice.
  let subject: Subject = Subject::from_json_value(json!({
      "id": holder_document.id().as_str(),
      "name": "Alice",
      "mainCourses": ["Object-oriented Programming", "Mathematics"],
      "degree": {
      "type": "BachelorDegree",
      "name": "Bachelor of Science and Arts",
      },
      "GPA": "4.0",
  }))?;

  // =========================================================================================
  // Step 1: Create a new RevocationTimeframeStatus containing the current validityTimeframe
  // =======================================================================================
  let duration = Duration::minutes(1);
  // The issuer also chooses a unique `RevocationBitmap` index to be able to revoke it later.
  let service_url = issuer_document.id().to_url().join("#my-revocation-service")?;
  let credential_index: u32 = 5;

  let start_validity_timeframe = Timestamp::now_utc();
  let status: Status = RevocationTimeframeStatus::new(
    Some(start_validity_timeframe),
    duration,
    service_url.into(),
    credential_index,
  )?
  .into();

  // Build credential using subject above and issuer.
  let credential: Credential = CredentialBuilder::default()
    .id(Url::parse("https://example.edu/credentials/3732")?)
    .issuer(Url::parse(issuer_document.id().as_str())?)
    .type_("UniversityDegreeCredential")
    .subject(subject)
    .status(status)
    .build()?;

  let credential_jpt: Jpt = issuer_document
    .create_credential_jpt(
      &credential,
      &storage_issuer,
      &fragment_issuer,
      &JwpCredentialOptions::default(),
      None,
    )
    .await?;

  // Validate the credential's proof using the issuer's DID Document, the credential's semantic structure,
  // that the issuance date is not in the future and that the expiration date is not in the past:
  let decoded_jpt = JptCredentialValidator::validate::<_, Object>(
    &credential_jpt,
    &issuer_document,
    &JptCredentialValidationOptions::default(),
    FailFast::FirstError,
  )
  .unwrap();

  assert_eq!(credential, decoded_jpt.credential);

  //  Issuer sends the Verifiable Credential to the holder.
  println!(
    "Sending credential (as JPT) to the holder: {}\n",
    credential_jpt.as_str()
  );

  // Holder validate the credential and retrieve the JwpIssued, needed to construct the JwpPresented

  let validation_result = JptCredentialValidator::validate::<_, Object>(
    &credential_jpt,
    &issuer_document,
    &JptCredentialValidationOptions::default(),
    FailFast::FirstError,
  );

  let decoded_credential = validation_result.unwrap();

  // ===========================================================================
  // Credential's Status check
  // ===========================================================================

  // Timeframe check
  let timeframe_result = JptCredentialValidatorUtils::check_timeframes_with_validity_timeframe_2024(
    &decoded_credential.credential,
    None,
    StatusCheck::Strict,
  );

  assert!(timeframe_result.is_ok());

  let revocation_result = JptCredentialValidatorUtils::check_revocation_with_validity_timeframe_2024(
    &decoded_credential.credential,
    &issuer_document,
    StatusCheck::Strict,
  );

  assert!(revocation_result.is_ok());

  // Both checks

  let revocation_result = JptCredentialValidatorUtils::check_timeframes_and_revocation_with_validity_timeframe_2024(
    &decoded_credential.credential,
    &issuer_document,
    None,
    StatusCheck::Strict,
  );

  assert!(revocation_result.is_ok());

  let challenge: &str = "475a7984-1bb5-4c4c-a56f-822bccd46440";

  let method_id = decoded_credential
    .decoded_jwp
    .get_issuer_protected_header()
    .kid()
    .unwrap();

  let mut selective_disclosure_presentation = SelectiveDisclosurePresentation::new(&decoded_credential.decoded_jwp);
  selective_disclosure_presentation
    .conceal_in_subject("mainCourses[1]")
    .unwrap();
  selective_disclosure_presentation
    .conceal_in_subject("degree.name")
    .unwrap();

  let presentation_jpt: Jpt = issuer_document
    .create_presentation_jpt(
      &mut selective_disclosure_presentation,
      method_id,
      &JwpPresentationOptions::default().nonce(challenge),
    )
    .await?;

  // Holder sends a Presentation JPT to the Verifier.
  println!(
    "Sending presentation (as JPT) to the verifier: {}\n",
    presentation_jpt.as_str()
  );

  // ===========================================================================
  // Step 2a: Verifier receives the Presentation and verifies it.
  // ===========================================================================

  let presentation_validation_options = JptPresentationValidationOptions::default().nonce(challenge);

  // Verifier validate the Presented Credential and retrieve the JwpPresented
  let decoded_presented_credential = JptPresentationValidator::validate::<_, Object>(
    &presentation_jpt,
    &issuer_document,
    &presentation_validation_options,
    FailFast::FirstError,
  )
  .unwrap();

  // Check validityTimeframe

  let timeframe_result = JptPresentationValidatorUtils::check_timeframes_with_validity_timeframe_2024(
    &decoded_presented_credential.credential,
    None,
    StatusCheck::Strict,
  );

  assert!(timeframe_result.is_ok());

  // Since no errors were thrown by `verify_presentation` we know that the validation was successful.
  println!(
    "Presented Credential successfully validated: {:#}",
    decoded_presented_credential.credential
  );

  // ===========================================================================
  // Step 2b: Waiting for the next validityTimeframe, will result in the Credential timeframe interval NOT valid
  // ===========================================================================

  thread::sleep(SleepDuration::from_secs(63));

  let timeframe_result = JptPresentationValidatorUtils::check_timeframes_with_validity_timeframe_2024(
    &decoded_presented_credential.credential,
    None,
    StatusCheck::Strict,
  );

  // We expect validation to no longer succeed because the credential was NOT updated.
  if matches!(timeframe_result.unwrap_err(), JwtValidationError::OutsideTimeframe) {
    println!("Validity Timeframe interval NOT valid\n");
  }

  // ===========================================================================
  // 3: Update credential
  // ===========================================================================

  // ===========================================================================
  // 3.1: Issuer sends the holder a challenge and requests a signed Verifiable Presentation.
  // ===========================================================================

  // A unique random challenge generated by the requester per presentation can mitigate replay attacks.
  let challenge: &str = "475a7984-1bb5-4c4c-a56f-822bccd46440";

  // The Holder and Issuer also agree that the signature should have an expiry date
  // 10 minutes from now.
  let expires: Timestamp = Timestamp::now_utc().checked_add(Duration::minutes(10)).unwrap();

  // ===========================================================================
  // 3.2: Holder creates and signs a verifiable presentation from the issued credential.
  // ===========================================================================

  // Create an unsigned Presentation from the previously issued ZK Verifiable Credential.
  let presentation: Presentation<Jpt> =
    PresentationBuilder::new(holder_document.id().to_url().into(), Default::default())
      .credential(credential_jpt)
      .build()?;

  // Create a JWT verifiable presentation using the holder's verification method
  // and include the requested challenge and expiry timestamp.
  let presentation_jwt: Jwt = holder_document
    .create_presentation_jwt(
      &presentation,
      &storage_holder,
      &fragment_holder,
      &JwsSignatureOptions::default().nonce(challenge.to_owned()),
      &JwtPresentationOptions::default().expiration_date(expires),
    )
    .await?;

  // ===========================================================================
  // 3.3: Holder sends a verifiable presentation to the verifier.
  // ===========================================================================
  println!(
    "Sending presentation (as JWT) to the Issuer: {}\n",
    presentation_jwt.as_str()
  );

  // ===========================================================================
  // 3.4: Issuer validate Verifiable Presentation and ZK Verifiable Credential.
  // ===========================================================================

  // ================================================
  // 3.4.1: Issuer validate Verifiable Presentation.
  // ================================================

  let presentation_verifier_options: JwsVerificationOptions =
    JwsVerificationOptions::default().nonce(challenge.to_owned());

  let mut resolver: Resolver<IotaDocument> = Resolver::new();
  resolver.attach_iota_handler((*holder_identity_client).clone());

  // Resolve the holder's document.
  let holder_did: CoreDID = JwtPresentationValidatorUtils::extract_holder(&presentation_jwt)?;
  let holder: IotaDocument = resolver.resolve(&holder_did).await?;

  // Validate presentation. Note that this doesn't validate the included credentials.
  let presentation_validation_options =
    JwtPresentationValidationOptions::default().presentation_verifier_options(presentation_verifier_options);
  let presentation: DecodedJwtPresentation<Jpt> = JwtPresentationValidator::with_signature_verifier(
    EdDSAJwsVerifier::default(),
  )
  .validate(&presentation_jwt, &holder, &presentation_validation_options)?;

  // =======================================================================
  // 3.4.2: Issuer validate ZK Verifiable Credential inside the Presentation.
  // ========================================================================

  let validation_options: JptCredentialValidationOptions = JptCredentialValidationOptions::default()
    .subject_holder_relationship(holder_did.to_url().into(), SubjectHolderRelationship::AlwaysSubject);

  let jpt_credentials: &Vec<Jpt> = &presentation.presentation.verifiable_credential;

  // Extract ZK Verifiable Credential in JPT format
  let jpt_vc = jpt_credentials.first().unwrap();

  // Issuer checks the Credential integrity.
  let mut verified_credential_result =
    JptCredentialValidator::validate::<_, Object>(jpt_vc, &issuer_document, &validation_options, FailFast::FirstError)
      .unwrap();

  // Issuer checks if the Credential has been revoked
  let revocation_result = JptCredentialValidatorUtils::check_revocation_with_validity_timeframe_2024(
    &verified_credential_result.credential,
    &issuer_document,
    StatusCheck::Strict,
  );

  assert!(!revocation_result.is_err_and(|e| matches!(e, JwtValidationError::Revoked)));

  // ===========================================================================
  // 3.5: Issuer ready for Update.
  // ===========================================================================

  // Since no errors were thrown during the Verifiable Presentation validation and the verification of inner Credentials
  println!(
    "Ready for Update - VP successfully validated: {:#?}",
    presentation.presentation
  );

  // Issuer updates the credential
  let new_credential_jpt = issuer_document
    .update(
      &storage_issuer,
      &fragment_issuer,
      None,
      duration,
      &mut verified_credential_result.decoded_jwp,
    )
    .await?;

  // Issuer sends back the credential updated

  println!(
    "Sending updated credential (as JPT) to the holder: {}\n",
    new_credential_jpt.as_str()
  );

  // Holder check validity of the updated credential

  let validation_result = JptCredentialValidator::validate::<_, Object>(
    &new_credential_jpt,
    &issuer_document,
    &JptCredentialValidationOptions::default(),
    FailFast::FirstError,
  )
  .unwrap();

  let timeframe_result = JptCredentialValidatorUtils::check_timeframes_with_validity_timeframe_2024(
    &validation_result.credential,
    None,
    StatusCheck::Strict,
  );

  assert!(!timeframe_result
    .as_ref()
    .is_err_and(|e| matches!(e, JwtValidationError::OutsideTimeframe)));
  println!("Updated credential is VALID!");

  // ===========================================================================
  // Issuer decides to Revoke Holder's Credential
  // ===========================================================================

  println!("Issuer decides to revoke the Credential");

  // Update the RevocationBitmap service in the issuer's DID Document.
  // This revokes the credential's unique index.

  issuer_document.revoke_credentials("my-revocation-service", &[credential_index])?;

  // Publish the changes.
  issuer_identity_client
    .publish_did_document_update(issuer_document.clone(), TEST_GAS_BUDGET)
    .await?;

  // Holder checks if his credential has been revoked by the Issuer
  let revocation_result = JptCredentialValidatorUtils::check_revocation_with_validity_timeframe_2024(
    &decoded_credential.credential,
    &issuer_document,
    StatusCheck::Strict,
  );
  assert!(revocation_result.is_err_and(|e| matches!(e, JwtValidationError::Revoked)));

  println!("Credential Revoked!");
  Ok(())
}
