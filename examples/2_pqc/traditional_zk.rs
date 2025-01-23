// Copyright 2024 Fondazione Links
// SPDX-License-Identifier: Apache-2.0

use std::{fs::File, path::Path};
use examples::{MemStorage, DID_URL, PATH_DID_FILE};
use identity_iota::{core::{FromJson, Object, Url}, credential::{Credential, CredentialBuilder, FailFast, Jpt, JptCredentialValidationOptions, JptCredentialValidator, JptPresentationValidationOptions, JptPresentationValidator, JptPresentationValidatorUtils, JwpCredentialOptions, JwpPresentationOptions, SelectiveDisclosurePresentation, Subject}, did::{CoreDID, DID}, document::CoreDocument, resolver::Resolver, storage::{DidJwkDocumentExt, JwkMemStore, JwpDocumentExt, KeyIdMemstore}, verification::{jws::JwsAlgorithm, MethodScope}};
use jsonprooftoken::jpa::algs::ProofAlgorithm;
use reqwest::ClientBuilder;
use serde_json::json;
use colored::Colorize;

pub fn write_to_file(doc: &CoreDocument, path: Option<&str>) -> anyhow::Result<()> {
    let path = Path::new(path.unwrap_or_else(|| "did.json"));
    let file = File::create(path)?;
    serde_json::to_writer_pretty(file, doc)?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  let binding = DID_URL.to_owned() + "did_zk.json";
  let did_url: &str = binding.as_str();
  let binding = PATH_DID_FILE.to_owned() + "did_zk.json";
  let path_did_file: &str = binding.as_str();

  println!("{} {} {}", "[Issuer]".red(), ": Create DID (with did:web method) and publish the DID Document at", did_url);

  let client= ClientBuilder::new()
  .danger_accept_invalid_certs(true)
  .build()?;

  let mut issuer_document: CoreDocument = CoreDocument::new_from_url(did_url)?;

  let storage_issuer: MemStorage = MemStorage::new(JwkMemStore::new(), KeyIdMemstore::new());
  let fragment_issuer = issuer_document.generate_method_jwp(
    &storage_issuer,
    JwkMemStore::BLS12381G2_KEY_TYPE,
    ProofAlgorithm::BLS12381_SHA256,
    None,
    MethodScope::VerificationMethod,
  ).await?;

  write_to_file(&issuer_document, Some(path_did_file))?;

  let storage_alice: MemStorage = MemStorage::new(JwkMemStore::new(), KeyIdMemstore::new());

  let (alice_document, _fragment_alice) = CoreDocument::new_did_jwk(
    &storage_alice, 
    JwkMemStore::ED25519_KEY_TYPE, 
    JwsAlgorithm::EdDSA
  ).await?;

  println!("{} {} {}", "[Holder]".blue(), ": Create DID Jwk:", alice_document.id().as_str());

  let subject: Subject = Subject::from_json_value(json!({
    "id": alice_document.id().as_str(),
    "name": "Alice",
    "degree": {
      "type": "BachelorDegree",
      "name": "Bachelor of Science and Arts",
    },
    "GPA": "4.0",
  }))?;

  println!("{} {} {} {}", "[Holder]".blue(), "->", "[Issuer]".red(), ": Request Verifiable Credential (VC)");

  println!("{} {} {}", "[Holder]".blue(), ": Credential information: ", serde_json::to_string_pretty(&subject)?);

  println!("{} {} {} {}", "[Holder]".blue(), "<->", "[Issuer]".red(), ": Challenge-response protocol to authenticate Holder's DID");

  println!("{} {} ","[Issuer]".red(), ": Generate VC");
  
  let credential: Credential = CredentialBuilder::default()
    .id(Url::parse("https://example.edu/credentials/3732")?)
    .issuer(Url::parse(issuer_document.id().as_str())?)
    .type_("UniversityDegreeCredential")
    .subject(subject)
    .build()?;

  let credential_jpt: Jpt = issuer_document.create_credential_jpt(
    &credential,
    &storage_issuer,
    &fragment_issuer,
    &JwpCredentialOptions::default(),
    None,
  ).await?;

  println!("{} {} {} {}", "[Issuer]".red(), " -> [Holder]".blue(), ": Sending VC (as JPT):", credential_jpt.as_str());

  println!("{} {} {}", "[Holder]".blue(), ": Resolve Issuer's DID:", issuer_document.id().as_str());

  println!("{} {} {issuer_document:#}", "[Holder]".blue(), ": Issuer's DID Document:");

  println!("{} {}", "[Holder]".blue(), ": Validate VC");

  let decoded_jpt = JptCredentialValidator::validate::<_, Object>(
      &credential_jpt,
      &issuer_document,
      &JptCredentialValidationOptions::default(),
      FailFast::FirstError,
    ).unwrap();

  println!("{} {}", "[Holder]".blue(), ": Successfull verification");

  println!("{} {} {} {}", "[Holder]".blue(), "->", "[Verifier]".green(), ": Request access with Selective Disclosure of VC attributes");

  let challenge: &str = "475a7984-1bb5-4c4c-a56f-822bccd46440";

  println!("{} {} {} {} {}", "[Verifier]".green(),  "->",  "[Holder]".blue(), ": Send challenge:", challenge);

  println!("{} : Resolve Issuer's Public Key to compute the Signature Proof of Knowledge", "[Holder]".blue());

  let method_id = decoded_jpt
  .decoded_jwp
  .get_issuer_protected_header()
  .kid()
  .unwrap();

  println!("{} : Engages in the Selective Disclosure of credential's attributes", "[Holder]".blue());

  let mut selective_disclosure_presentation = SelectiveDisclosurePresentation::new(&decoded_jpt.decoded_jwp);
  selective_disclosure_presentation
  .conceal_in_subject("GPA")
  .unwrap();

  selective_disclosure_presentation.conceal_in_subject("name").unwrap();

  println!("{} {}", "[Holder]".blue(), ": Compute the Signature Proof of Knowledge and generate the Presentation/zk_proof (JPT encoded)");
  
  let presentation_jpt: Jpt = issuer_document
  .create_presentation_jpt(
    &mut selective_disclosure_presentation,
    method_id,
    &JwpPresentationOptions::default().nonce(challenge),
    )
  .await?;

  println!("{} {} {} {} {}", "[Holder]".blue(), "->",  "[Verifier]".green(),  ": Sending Presentation (as JPT):", presentation_jpt.as_str());

  println!("{} : Resolve Issuer's DID and verifies the Presentation/zk_proof (JPT encoded)","[Verifier]".green());
  
  let mut resolver_web: Resolver<CoreDocument> = Resolver::new();
  let _ = resolver_web.attach_web_handler(client)?;

  let issuer: CoreDID = JptPresentationValidatorUtils::extract_issuer_from_presented_jpt(&presentation_jpt).unwrap();
  let issuer_document: CoreDocument = resolver_web.resolve(&issuer).await?;

  let presentation_validation_options = JptPresentationValidationOptions::default().nonce(challenge);

  let _decoded_presented_credential = JptPresentationValidator::validate::<_, Object>(
    &presentation_jpt,
    &issuer_document,
    &presentation_validation_options,
    FailFast::FirstError,
  ).unwrap();

  println!("{} : JPT successfully verified, access granted", "[Verifier]".green());

  Ok(())
}
