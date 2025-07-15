// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use _credentials::validate_did_response::Domains;
use _credentials::validate_domain_response::LinkedDids;

use crate::domain_linkage::_credentials::validate_did_response::domains::InvalidDomain;
use crate::domain_linkage::_credentials::validate_did_response::domains::ValidDomain;
use crate::domain_linkage::_credentials::validate_domain_response::linked_dids::ValidDid;
use identity_iota::core::Duration;
use identity_iota::core::FromJson;
use identity_iota::core::Object;
use identity_iota::core::OrderedSet;
use identity_iota::core::Timestamp;
use identity_iota::core::Url;
use identity_iota::credential::Credential;
use identity_iota::credential::DomainLinkageConfiguration;
use identity_iota::credential::DomainLinkageCredentialBuilder;
use identity_iota::credential::Jwt;
use identity_iota::credential::LinkedDomainService;
use identity_iota::did::DIDUrl;
use identity_iota::did::DID;
use identity_iota::iota::IotaDocument;
use identity_storage::JwkDocumentExt;
use identity_storage::JwsSignatureOptions;
use identity_stronghold::StrongholdStorage;

use crate::domain_linkage::_credentials::domain_linkage_client::DomainLinkageClient;

use crate::domain_linkage::_credentials::ValidateDidAgainstDidConfigurationsRequest;
use crate::domain_linkage::_credentials::ValidateDidResponse;
use crate::domain_linkage::_credentials::ValidateDomainAgainstDidConfigurationRequest;
use crate::domain_linkage::_credentials::ValidateDomainResponse;
use crate::helpers::make_stronghold;
use crate::helpers::Entity;
use crate::helpers::TestServer;

mod _credentials {
  tonic::include_proto!("domain_linkage");
}

/// Prepares basically the same test setup as in test `examples/1_advanced/6_domain_linkage.rs`.
async fn prepare_test() -> anyhow::Result<(TestServer, Url, Url, String, Jwt)> {
  let stronghold = StrongholdStorage::new(make_stronghold());
  let server = TestServer::new_with_stronghold(stronghold.clone()).await;
  let api_client = server.client();

  let mut issuer = Entity::new_with_stronghold(stronghold);
  issuer.create_did(api_client).await?;
  let did = issuer
    .document()
    .ok_or_else(|| anyhow::anyhow!("no DID document for issuer"))?;

  let did = did.id().clone();
  // =====================================================
  // Create Linked Domain service
  // =====================================================

  // The DID should be linked to the following domains.
  let domain_1: Url = Url::parse("https://foo.example.com")?;
  let domain_2: Url = Url::parse("https://bar.example.com")?;

  let mut domains: OrderedSet<Url> = OrderedSet::new();
  domains.append(domain_1.clone());
  domains.append(domain_2.clone());

  // Create a Linked Domain Service to enable the discovery of the linked domains through the DID Document.
  // This is optional since it is not a hard requirement by the specs.
  let service_url: DIDUrl = did.clone().join("#domain-linkage")?;
  let linked_domain_service: LinkedDomainService = LinkedDomainService::new(service_url, domains, Object::new())?;
  issuer
    .update_document(api_client, |mut doc| {
      doc.insert_service(linked_domain_service.into()).ok().map(|_| doc)
    })
    .await?;
  let updated_did_document = issuer
    .document()
    .ok_or_else(|| anyhow::anyhow!("no DID document for issuer"))?;

  let did_string = updated_did_document.to_string();

  println!("DID document with linked domain service: {updated_did_document:#}");

  // =====================================================
  // Create DID Configuration resource
  // =====================================================

  // Create the Domain Linkage Credential.
  let domain_linkage_credential: Credential = DomainLinkageCredentialBuilder::new()
    .issuer(updated_did_document.id().clone().into())
    .origin(domain_1.clone())
    .issuance_date(Timestamp::now_utc())
    // Expires after a year.
    .expiration_date(
      Timestamp::now_utc()
        .checked_add(Duration::days(365))
        .ok_or_else(|| anyhow::anyhow!("calculation should not overflow"))?,
    )
    .build()?;

  let jwt: Jwt = updated_did_document
    .create_credential_jwt(
      &domain_linkage_credential,
      issuer.storage(),
      issuer
        .fragment()
        .ok_or_else(|| anyhow::anyhow!("no fragment for issuer"))?,
      &JwsSignatureOptions::default(),
      None,
    )
    .await?;

  Ok((server, domain_1, domain_2, did_string, jwt))
}

#[tokio::test]
async fn can_validate_domain() -> anyhow::Result<()> {
  let (server, linked_domain, _, did, jwt) = prepare_test().await?;
  let configuration_resource: DomainLinkageConfiguration = DomainLinkageConfiguration::new(vec![jwt.clone()]);
  let mut grpc_client = DomainLinkageClient::connect(server.endpoint()).await?;

  let response = grpc_client
    .validate_domain_against_did_configuration(ValidateDomainAgainstDidConfigurationRequest {
      domain: linked_domain.to_string(),
      did_configuration: configuration_resource.to_string(),
    })
    .await?;

  // created and updated are retrieved directly from the contract and not from the given DID document,
  // so we'll replace them with values from the result for the check here
  let validated_did_response = response.into_inner();
  let mut did_document: IotaDocument = IotaDocument::from_json(&did)?;
  let did_id = did_document.id().to_string();
  let response_did_document: IotaDocument =
    serde_json::from_str(&validated_did_response.linked_dids.as_ref().unwrap().valid[0].did).unwrap();
  did_document.metadata.created = response_did_document.metadata.created;
  did_document.metadata.updated = response_did_document.metadata.updated;

  assert_eq!(
    validated_did_response,
    ValidateDomainResponse {
      linked_dids: Some(LinkedDids {
        invalid: vec![],
        valid: vec![ValidDid {
          service_id: did_id,
          did: did_document.to_string().clone(),
          credential: jwt.as_str().to_string(),
        }]
      }),
      domain: linked_domain.to_string(),
    }
  );

  Ok(())
}

#[tokio::test]
async fn can_validate_did() -> anyhow::Result<()> {
  let (server, linked_domain, domain2, issuer_did, jwt) = prepare_test().await?;
  let configuration_resource: DomainLinkageConfiguration = DomainLinkageConfiguration::new(vec![jwt.clone()]);
  let mut grpc_client = DomainLinkageClient::connect(server.endpoint()).await?;
  let did_id = IotaDocument::from_json(&issuer_did)?.id().to_string();

  let response = grpc_client
    .validate_did_against_did_configurations(ValidateDidAgainstDidConfigurationsRequest {
      did: did_id.clone(),
      did_configurations: vec![ValidateDomainAgainstDidConfigurationRequest {
        domain: linked_domain.to_string(),
        did_configuration: configuration_resource.to_string(),
      }],
    })
    .await?;

  let service_id = format!("{}#domain-linkage", did_id);

  let valid_domain = ValidDomain {
    service_id: service_id.clone(),
    url: linked_domain.to_string(),
    credential: jwt.as_str().to_string(),
  };

  let error = format!("could not get domain linkage config: domain linkage error: error sending request for url ({}.well-known/did-configuration.json): error trying to connect: dns error: failed to lookup address information: nodename nor servname provided, or not known", domain2.to_string());

  let invalid_domain = InvalidDomain {
    service_id: service_id.clone(),
    credential: None,
    url: domain2.to_string(),
    error,
  };

  assert_eq!(
    response.into_inner(),
    ValidateDidResponse {
      did: did_id,
      domains: Some(Domains {
        invalid: vec![invalid_domain],
        valid: vec![valid_domain],
      }),
    }
  );

  Ok(())
}
