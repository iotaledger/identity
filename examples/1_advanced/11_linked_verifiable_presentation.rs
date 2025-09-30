// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;

use examples::create_did_document;
use examples::get_funded_client;
use examples::get_iota_endpoint;
use examples::get_memstorage;
use examples::get_notarization_client;
use examples::MemStorage;
use examples::TEST_GAS_BUDGET;

use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_iota::core::FromJson;
use identity_iota::core::Object;
use identity_iota::core::Url;
use identity_iota::credential::CompoundJwtPresentationValidationError;
use identity_iota::credential::CredentialBuilder;
use identity_iota::credential::DecodedJwtPresentation;
use identity_iota::credential::Jwt;
use identity_iota::credential::JwtPresentationOptions;
use identity_iota::credential::JwtPresentationValidationOptions;
use identity_iota::credential::JwtPresentationValidator;
use identity_iota::credential::JwtPresentationValidatorUtils;
use identity_iota::credential::LinkedVerifiablePresentationService;
use identity_iota::credential::PresentationBuilder;
use identity_iota::credential::Subject;
use identity_iota::did::CoreDID;
use identity_iota::did::DIDUrl;
use identity_iota::did::DID;
use identity_iota::document::verifiable::JwsVerificationOptions;
use identity_iota::iota::IotaDID;
use identity_iota::iota::IotaDocument;
use identity_iota::resolver::Resolver;
use identity_iota::storage::JwkDocumentExt;
use identity_iota::storage::JwsSignatureOptions;
use iota_caip::iota::resolver::Resolver as IotaResourceResolver;
use iota_caip::iota::IotaNetwork;
use product_common::core_client::CoreClient as _;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  // ===========================================================================
  // Step 1: Create identities and Client
  // ===========================================================================

  let storage = get_memstorage()?;
  let identity_client = get_funded_client(&storage).await?;

  // create new DID document and publish it
  let (mut did_document, fragment) = create_did_document(&identity_client, &storage).await?;

  println!("Published DID document: {did_document:#}");

  let did: IotaDID = did_document.id().clone();

  // =====================================================
  // Create a Verifiable Presentation and host it on-chain
  // =====================================================

  let jwt_vp = make_vp_jwt(&did_document, &storage, &fragment).await?;

  // In this example the created VP is hosted inside an IOTA Notarization
  // but user may host it where ever they choose.

  // We create a notarization client that uses the same address as our identity client.
  let notarization_client = get_notarization_client(identity_client.signer().clone()).await?;
  // Notarize the VP we previously created.
  let notarized_vp = notarization_client
    .create_locked_notarization()
    .with_string_state(jwt_vp.into(), Some("My Linked VP".to_owned()))
    .finish()?
    .build_and_execute(&notarization_client)
    .await?
    .output;

  // =====================================================
  // Create Linked Verifiable Presentation service
  // =====================================================

  // The IOTA Resource Locator that references our notarized JWT-VP.
  let vp_url = Url::parse(format!(
    "iota:{}/{}/state/data",
    notarization_client.network().as_ref(),
    notarized_vp.id.object_id()
  ))?;

  // Create a Linked Verifiable Presentation Service to enable the discovery of the linked VPs through the DID Document.
  // This is optional since it is not a hard requirement by the specs.
  let service_url: DIDUrl = did.clone().join("#linked-vp")?;
  let linked_verifiable_presentation_service =
    LinkedVerifiablePresentationService::new(service_url, [vp_url], Object::new())?;
  did_document.insert_service(linked_verifiable_presentation_service.into())?;

  let updated_did_document: IotaDocument = identity_client
    .publish_did_document_update(did_document, TEST_GAS_BUDGET)
    .await?;

  println!("DID document with linked verifiable presentation service: {updated_did_document:#}");

  // =====================================================
  // Verification
  // =====================================================

  // Init a resolver for resolving DID Documents.
  let mut resolver: Resolver<IotaDocument> = Resolver::new();
  resolver.attach_iota_handler((*identity_client).clone());

  // Resolve the DID Document of the DID that issued the credential.
  let did_document: IotaDocument = resolver.resolve(&did).await?;

  // Get the Linked Verifiable Presentation Services from the DID Document.
  let linked_verifiable_presentation_services: Vec<LinkedVerifiablePresentationService> = did_document
    .service()
    .iter()
    .cloned()
    .filter_map(|service| LinkedVerifiablePresentationService::try_from(service).ok())
    .collect();

  assert_eq!(linked_verifiable_presentation_services.len(), 1);

  // Get the VPs included in the service.
  let vp_url = linked_verifiable_presentation_services
    .first()
    .ok_or_else(|| anyhow::anyhow!("expected verifiable presentation urls"))?
    .verifiable_presentation_urls()
    .first()
    .expect("one linked VP endpoint is present");

  println!("Fetching VP at `{vp_url}`");
  // Fetch the verifiable presentation from the URL. We know it's an IOTA Resource Locator
  // therefore we are gonna use the IOTA Resource Locator Resolver.
  let custom_network = IotaNetwork::custom(identity_client.network().as_ref()).expect("valid IOTA network");
  let iota_resource_resolver =
    IotaResourceResolver::new_with_custom_networks(vec![(custom_network, get_iota_endpoint())]);
  let presentation_jwt = serde_json::from_value(iota_resource_resolver.resolve(vp_url).await?)?;

  // Resolve the holder's document.
  let holder_did: CoreDID = JwtPresentationValidatorUtils::extract_holder(&presentation_jwt)?;
  let holder: IotaDocument = resolver.resolve(&holder_did).await?;

  // Validate linked presentation. Note that this doesn't validate the included credentials.
  let presentation_verifier_options: JwsVerificationOptions = JwsVerificationOptions::default();
  let presentation_validation_options =
    JwtPresentationValidationOptions::default().presentation_verifier_options(presentation_verifier_options);
  let validation_result: Result<DecodedJwtPresentation<Jwt>, CompoundJwtPresentationValidationError> =
    JwtPresentationValidator::with_signature_verifier(EdDSAJwsVerifier::default()).validate(
      &presentation_jwt,
      &holder,
      &presentation_validation_options,
    );

  assert!(validation_result.is_ok());

  Ok(())
}

async fn make_vp_jwt(did_doc: &IotaDocument, storage: &MemStorage, fragment: &str) -> anyhow::Result<Jwt> {
  // first we create a credential encoding it as jwt
  let credential = CredentialBuilder::new(Object::default())
    .id(Url::parse("https://example.edu/credentials/3732")?)
    .issuer(Url::parse(did_doc.id().as_str())?)
    .type_("UniversityDegreeCredential")
    .subject(Subject::from_json_value(serde_json::json!({
      "id": did_doc.id().as_str(),
      "name": "Alice",
      "degree": {
        "type": "BachelorDegree",
        "name": "Bachelor of Science and Arts",
      },
      "GPA": "4.0",
    }))?)
    .build()?;
  let credential = did_doc
    .create_credential_jwt(&credential, storage, fragment, &JwsSignatureOptions::default(), None)
    .await?;
  // then we create a presentation including the just created JWT encoded credential.
  let presentation = PresentationBuilder::new(Url::parse(did_doc.id().as_str())?, Object::default())
    .credential(credential)
    .build()?;
  // we encode the presentation as JWT
  did_doc
    .create_presentation_jwt(
      &presentation,
      storage,
      fragment,
      &JwsSignatureOptions::default(),
      &JwtPresentationOptions::default(),
    )
    .await
    .context("jwt presentation failed")
}
