// Copyright 2020-2024 IOTA Stiftung, Fondazione Links
// SPDX-License-Identifier: Apache-2.0

use examples::get_funded_client;

use examples::get_memstorage;
use examples::TEST_GAS_BUDGET;
use identity_iota::core::json;
use identity_iota::core::FromJson;
use identity_iota::core::Object;
use identity_iota::core::Url;
use identity_iota::credential::Credential;
use identity_iota::credential::CredentialBuilder;
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
use identity_iota::credential::SelectiveDisclosurePresentation;
use identity_iota::credential::Subject;
use identity_iota::did::CoreDID;
use identity_iota::did::DID;
use identity_iota::iota_interaction::OptionalSync;

use identity_iota::iota::IotaDocument;
use identity_iota::resolver::Resolver;
use identity_iota::storage::JwkMemStore;
use identity_iota::storage::JwpDocumentExt;
use identity_iota::storage::KeyType;
use identity_iota::verification::MethodScope;

use identity_iota::iota::rebased::client::IdentityClient;
use identity_iota::iota::rebased::client::IotaKeySignature;
use identity_storage::Storage;
use jsonprooftoken::jpa::algs::ProofAlgorithm;
use product_common::transaction::TransactionOutput;
use secret_storage::Signer;

// Creates a DID with a JWP verification method.
pub async fn create_did<K, I, S>(
  identity_client: &IdentityClient<S>,
  storage: &Storage<K, I>,
  key_type: KeyType,
  alg: ProofAlgorithm,
) -> anyhow::Result<(IotaDocument, String)>
where
  K: identity_storage::JwkStorage + identity_storage::JwkStorageBbsPlusExt,
  I: identity_storage::KeyIdStorage,
  S: Signer<IotaKeySignature> + OptionalSync,
{
  // Create a new DID document with a placeholder DID.
  let mut unpublished: IotaDocument = IotaDocument::new(identity_client.network());

  let verification_method_fragment = unpublished
    .generate_method_jwp(storage, key_type, alg, None, MethodScope::VerificationMethod)
    .await?;

  let TransactionOutput::<IotaDocument> { output: document, .. } = identity_client
    .publish_did_document(unpublished)
    .with_gas_budget(TEST_GAS_BUDGET)
    .build_and_execute(identity_client)
    .await?;

  Ok((document, verification_method_fragment))
}

/// Demonstrates how to create an Anonymous Credential with BBS+.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
  // ===========================================================================
  // Step 1: Create identities and Client
  // ===========================================================================

  let storage_issuer = get_memstorage()?;

  let identity_client = get_funded_client(&storage_issuer).await?;

  let (issuer_document, fragment_issuer): (IotaDocument, String) = create_did(
    &identity_client,
    &storage_issuer,
    JwkMemStore::BLS12381G2_KEY_TYPE,
    ProofAlgorithm::BLS12381_SHA256,
  )
  .await?;

  // ===========================================================================
  // Step 2: Issuer creates and signs a Verifiable Credential with BBS algorithm.
  // ===========================================================================

  // Create a credential subject indicating the degree earned by Alice.
  let subject: Subject = Subject::from_json_value(json!({
    "name": "Alice",
    "mainCourses": ["Object-oriented Programming", "Mathematics"],
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

  // ===========================================================================
  // Step 3: Issuer sends the Verifiable Credential to the holder.
  // ===========================================================================
  println!(
    "Sending credential (as JPT) to the holder: {}\n",
    credential_jpt.as_str()
  );

  // ============================================================================================
  // Step 4: Holder resolves Issuer's DID, retrieve Issuer's document and validate the Credential
  // ============================================================================================

  let mut resolver: Resolver<IotaDocument> = Resolver::new();
  resolver.attach_iota_handler((*identity_client).clone());

  // Holder resolves issuer's DID
  let issuer: CoreDID = JptCredentialValidatorUtils::extract_issuer_from_issued_jpt(&credential_jpt).unwrap();
  let issuer_document: IotaDocument = resolver.resolve(&issuer).await?;

  // Holder validates the credential and retrieve the JwpIssued, needed to construct the JwpPresented
  let decoded_credential = JptCredentialValidator::validate::<_, Object>(
    &credential_jpt,
    &issuer_document,
    &JptCredentialValidationOptions::default(),
    FailFast::FirstError,
  )
  .unwrap();

  // ===========================================================================
  // Step 5: Verifier sends the holder a challenge and requests a Presentation.
  //
  // Please be aware that when we mention "Presentation," we are not alluding to the Verifiable Presentation standard as defined by W3C (https://www.w3.org/TR/vc-data-model/#presentations).
  // Instead, our reference is to a JWP Presentation (https://datatracker.ietf.org/doc/html/draft-ietf-jose-json-web-proof#name-presented-form), which differs from the W3C standard.
  // ===========================================================================

  // A unique random challenge generated by the requester per presentation can mitigate replay attacks.
  let challenge: &str = "475a7984-1bb5-4c4c-a56f-822bccd46440";

  // =========================================================================================================
  // Step 6: Holder engages in the Selective Disclosure of credential's attributes.
  // =========================================================================================================

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

  // =======================================================================================================================================
  // Step 7: Holder needs Issuer's Public Key to compute the Signature Proof of Knowledge and construct the Presentation
  // JPT.
  // =======================================================================================================================================

  // Construct a JPT(JWP in the Presentation form) representing the Selectively Disclosed Verifiable Credential
  let presentation_jpt: Jpt = issuer_document
    .create_presentation_jpt(
      &mut selective_disclosure_presentation,
      method_id,
      &JwpPresentationOptions::default().nonce(challenge),
    )
    .await?;

  // ===========================================================================
  // Step 8: Holder sends a Presentation JPT to the Verifier.
  // ===========================================================================

  println!(
    "Sending presentation (as JPT) to the verifier: {}\n",
    presentation_jpt.as_str()
  );

  // ===========================================================================
  // Step 9: Verifier receives the Presentation and verifies it.
  // ===========================================================================

  // Verifier resolve Issuer DID
  let issuer: CoreDID = JptPresentationValidatorUtils::extract_issuer_from_presented_jpt(&presentation_jpt).unwrap();
  let issuer_document: IotaDocument = resolver.resolve(&issuer).await?;

  let presentation_validation_options = JptPresentationValidationOptions::default().nonce(challenge);

  // Verifier validate the Presented Credential and retrieve the JwpPresented
  let decoded_presented_credential = JptPresentationValidator::validate::<_, Object>(
    &presentation_jpt,
    &issuer_document,
    &presentation_validation_options,
    FailFast::FirstError,
  )
  .unwrap();

  // Since no errors were thrown by `verify_presentation` we know that the validation was successful.
  println!(
    "Presented Credential successfully validated: {:#?}",
    decoded_presented_credential.credential
  );

  Ok(())
}
