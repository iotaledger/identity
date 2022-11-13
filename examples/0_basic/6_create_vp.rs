// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//!  This example shows how to create a Verifiable Presentation and validate it.
//!  A Verifiable Presentation is the format in which a (collection of) Verifiable Credential(s) gets shared.
//!  It is signed by the subject, to prove control over the Verifiable Credential with a nonce or timestamp.
//!
//! cargo run --example 6_create_vp

use iota_client::block::address::Address;
use iota_client::secret::stronghold::StrongholdSecretManager;
use iota_client::secret::SecretManager;
use iota_client::Client;

use examples::create_did;
use examples::random_stronghold_path;
use examples::API_ENDPOINT;
use identity_iota::core::json;
use identity_iota::core::Duration;
use identity_iota::core::FromJson;
use identity_iota::core::Timestamp;
use identity_iota::core::ToJson;
use identity_iota::core::Url;
use identity_iota::credential::Credential;
use identity_iota::credential::CredentialBuilder;
use identity_iota::credential::CredentialValidationOptions;
use identity_iota::credential::CredentialValidator;
use identity_iota::credential::FailFast;
use identity_iota::credential::Presentation;
use identity_iota::credential::PresentationBuilder;
use identity_iota::credential::PresentationValidationOptions;
use identity_iota::credential::Subject;
use identity_iota::credential::SubjectHolderRelationship;
use identity_iota::crypto::KeyPair;
use identity_iota::crypto::ProofOptions;
use identity_iota::did::verifiable::VerifierOptions;
use identity_iota::did::DID;
use identity_iota::iota::IotaDocument;
use identity_iota::resolver::Resolver;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  // ===========================================================================
  // Step 1: Create identities for the issuer and the holder.
  // ===========================================================================

  // Create a new client to interact with the IOTA ledger.
  let client: Client = Client::builder().with_primary_node(API_ENDPOINT, None)?.finish()?;

  // Create an identity for the issuer with one verification method `key-1`.
  let mut secret_manager_issuer: SecretManager = SecretManager::Stronghold(
    StrongholdSecretManager::builder()
      .password("secure_password_1")
      .build(random_stronghold_path())?,
  );
  let (_, issuer_document, key_pair_issuer): (Address, IotaDocument, KeyPair) =
    create_did(&client, &mut secret_manager_issuer).await?;

  // Create an identity for the holder, in this case also the subject.
  let mut secret_manager_alice: SecretManager = SecretManager::Stronghold(
    StrongholdSecretManager::builder()
      .password("secure_password_2")
      .build(random_stronghold_path())?,
  );
  let (_, alice_document, key_pair_alice): (Address, IotaDocument, KeyPair) =
    create_did(&client, &mut secret_manager_alice).await?;

  // ===========================================================================
  // Step 2: Issuer creates and signs a Verifiable Credential.
  // ===========================================================================

  // Create a credential subject indicating the degree earned by Alice.
  let subject: Subject = Subject::from_json_value(json!({
    "id": alice_document.id().as_str(),
    "name": "Alice",
    "degree": {
      "type": "BachelorDegree",
      "name": "Bachelor of Science and Arts",
    },
    "GPA": "4.0",
  }))?;

  // Build credential using subject above and issuer.
  let mut credential: Credential = CredentialBuilder::default()
    .id(Url::parse("https://example.edu/credentials/3732")?)
    .issuer(Url::parse(issuer_document.id().as_str())?)
    .type_("UniversityDegreeCredential")
    .subject(subject)
    .build()?;

  // Sign the Credential with the issuer's verification method.
  issuer_document.sign_data(
    &mut credential,
    key_pair_issuer.private(),
    "#key-1",
    ProofOptions::default(),
  )?;
  println!("Credential JSON > {:#}", credential);

  // Before sending this credential to the holder the issuer wants to validate that some properties
  // of the credential satisfy their expectations.

  // Validate the credential's signature using the issuer's DID Document, the credential's semantic structure,
  // that the issuance date is not in the future and that the expiration date is not in the past:
  CredentialValidator::validate(
    &credential,
    &issuer_document,
    &CredentialValidationOptions::default(),
    FailFast::FirstError,
  )
  .unwrap();

  println!("VC successfully validated");

  // ===========================================================================
  // Step 3: Issuer sends the Verifiable Credential to the holder.
  // ===========================================================================

  // The issuer is now sure that the credential they are about to issue satisfies their expectations.
  // The credential is then serialized to JSON and transmitted to the subject in a secure manner.
  let credential_json: String = credential.to_json()?;

  // ===========================================================================
  // Step 4: Verifier sends the holder a challenge and requests a signed Verifiable Presentation.
  // ===========================================================================

  // A unique random challenge generated by the requester per presentation can mitigate replay attacks
  let challenge: &str = "475a7984-1bb5-4c4c-a56f-822bccd46440";

  // The verifier and holder also agree that the signature should have an expiry date
  // 10 minutes from now.
  let expires: Timestamp = Timestamp::now_utc().checked_add(Duration::minutes(10)).unwrap();

  // ===========================================================================
  // Step 5: Holder creates and signs a verifiable presentation from the issued credential.
  // ===========================================================================

  // Deserialize the credential.
  let credential: Credential = Credential::from_json(credential_json.as_str())?;

  // Create an unsigned Presentation from the previously issued Verifiable Credential.
  let mut presentation: Presentation = PresentationBuilder::default()
    .holder(Url::parse(alice_document.id().as_ref())?)
    .credential(credential)
    .build()?;

  // Sign the verifiable presentation using the holder's verification method
  // and include the requested challenge and expiry timestamp.
  alice_document.sign_data(
    &mut presentation,
    key_pair_alice.private(),
    "#key-1",
    ProofOptions::new().challenge(challenge.to_string()).expires(expires),
  )?;

  // ===========================================================================
  // Step 6: Holder sends a verifiable presentation to the verifier.
  // ===========================================================================

  // Convert the Verifiable Presentation to JSON to send it to the verifier.
  let presentation_json: String = presentation.to_json()?;

  // ===========================================================================
  // Step 7: Verifier receives the Verifiable Presentation and verifies it.
  // ===========================================================================

  // Deserialize the presentation from the holder:
  let presentation: Presentation = Presentation::from_json(&presentation_json)?;

  // The verifier wants the following requirements to be satisfied:
  // - Signature verification (including checking the requested challenge to mitigate replay attacks)
  // - Presentation validation must fail if credentials expiring within the next 10 hours are encountered
  // - The presentation holder must always be the subject, regardless of the presence of the nonTransferable property
  // - The issuance date must not be in the future.

  let presentation_verifier_options: VerifierOptions = VerifierOptions::new()
    .challenge(challenge.to_owned())
    .allow_expired(false);

  // Do not allow credentials that expire within the next 10 hours.
  let credential_validation_options: CredentialValidationOptions = CredentialValidationOptions::default()
    .earliest_expiry_date(Timestamp::now_utc().checked_add(Duration::hours(10)).unwrap());

  let presentation_validation_options = PresentationValidationOptions::default()
    .presentation_verifier_options(presentation_verifier_options)
    .shared_validation_options(credential_validation_options)
    .subject_holder_relationship(SubjectHolderRelationship::AlwaysSubject);

  // Resolve issuer and holder documents and verify presentation.
  // Passing the holder and issuer to `verify_presentation` will bypass the resolution step.
  let mut resolver: Resolver<IotaDocument> = Resolver::new();
  resolver.attach_iota_handler(client);
  resolver
    .verify_presentation(
      &presentation,
      &presentation_validation_options,
      FailFast::FirstError,
      None,
      None,
    )
    .await?;

  // Since no errors were thrown by `verify_presentation` we know that the validation was successful.
  println!("VP successfully validated");

  // Note that we did not declare a latest allowed issuance date for credentials. This is because we only want to check
  // that the credentials do not have an issuance date in the future which is a default check.

  Ok(())
}
