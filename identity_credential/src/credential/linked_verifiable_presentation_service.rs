// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_core::common::Object;
use identity_core::common::OrderedSet;
use identity_core::common::Url;
use identity_did::DIDUrl;
use identity_document::service::Service;
use identity_document::service::ServiceBuilder;
use identity_document::service::ServiceEndpoint;
use serde::Deserialize;
use serde::Serialize;

use crate::error::Result;
use crate::Error;
use crate::Error::LinkedVerifiablePresentationError;

/// A service wrapper for a [Linked Verifiable Presentation Service Endpoint](https://identity.foundation/linked-vp/#linked-verifiable-presentation-service-endpoint).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "Service", into = "Service")]
pub struct LinkedVerifiablePresentationService(Service);

impl TryFrom<Service> for LinkedVerifiablePresentationService {
  type Error = Error;

  fn try_from(service: Service) -> std::result::Result<Self, Self::Error> {
    LinkedVerifiablePresentationService::check_structure(&service)?;
    Ok(LinkedVerifiablePresentationService(service))
  }
}

impl From<LinkedVerifiablePresentationService> for Service {
  fn from(service: LinkedVerifiablePresentationService) -> Self {
    service.0
  }
}

impl LinkedVerifiablePresentationService {
  pub(crate) fn linked_verifiable_presentation_service_type() -> &'static str {
    "LinkedVerifiablePresentation"
  }

  /// Constructs a new `LinkedVerifiablePresentationService` that wraps a spec compliant
  /// [Linked Verifiable Presentation Service Endpoint](https://identity.foundation/linked-vp/#linked-verifiable-presentation-service-endpoint).
  pub fn new(
    did_url: DIDUrl,
    verifiable_presentation_urls: impl IntoIterator<Item = Url>,
    properties: Object,
  ) -> Result<Self> {
    let verifiable_presentation_urls: OrderedSet<Url> = verifiable_presentation_urls.into_iter().collect();
    let builder: ServiceBuilder = Service::builder(properties)
      .id(did_url)
      .type_(Self::linked_verifiable_presentation_service_type());
    if verifiable_presentation_urls.len() == 1 {
      let vp_url = verifiable_presentation_urls
        .into_iter()
        .next()
        .expect("element 0 exists");
      let service = builder
        .service_endpoint(vp_url)
        .build()
        .map_err(|err| LinkedVerifiablePresentationError(Box::new(err)))?;
      Ok(Self(service))
    } else {
      let service = builder
        .service_endpoint(ServiceEndpoint::Set(verifiable_presentation_urls))
        .build()
        .map_err(|err| LinkedVerifiablePresentationError(Box::new(err)))?;
      Ok(Self(service))
    }
  }

  /// Checks the semantic structure of a Linked Verifiable Presentation Service.
  ///
  /// Note: `{"type": ["LinkedVerifiablePresentation"]}` might be serialized the same way as `{"type":
  /// "LinkedVerifiablePresentation"}` which passes the semantic check.
  pub fn check_structure(service: &Service) -> Result<()> {
    if service.type_().len() != 1 {
      return Err(LinkedVerifiablePresentationError("invalid service type".into()));
    }

    let service_type = service
      .type_()
      .get(0)
      .ok_or_else(|| LinkedVerifiablePresentationError("missing service type".into()))?;

    if service_type != Self::linked_verifiable_presentation_service_type() {
      return Err(LinkedVerifiablePresentationError(
        format!(
          "expected `{}` service type",
          Self::linked_verifiable_presentation_service_type()
        )
        .into(),
      ));
    }

    match service.service_endpoint() {
      ServiceEndpoint::One(_) => Ok(()),
      ServiceEndpoint::Set(_) => Ok(()),
      ServiceEndpoint::Map(_) => Err(LinkedVerifiablePresentationError(
        "service endpoints must be either a string or a set".into(),
      )),
    }
  }

  /// Returns the Verifiable Presentations contained in the Linked Verifiable Presentation Service.
  pub fn verifiable_presentation_urls(&self) -> &[Url] {
    match self.0.service_endpoint() {
      ServiceEndpoint::One(endpoint) => std::slice::from_ref(endpoint),
      ServiceEndpoint::Set(endpoints) => endpoints.as_slice(),
      ServiceEndpoint::Map(_) => {
        unreachable!("the service endpoint is never a map per the `LinkedVerifiablePresentationService` type invariant")
      }
    }
  }

  /// Returns a reference to the `Service` id.
  pub fn id(&self) -> &DIDUrl {
    self.0.id()
  }
}

#[cfg(test)]
mod tests {
  use crate::credential::linked_verifiable_presentation_service::LinkedVerifiablePresentationService;
  use identity_core::common::Object;
  use identity_core::common::OrderedSet;
  use identity_core::common::Url;
  use identity_core::convert::FromJson;
  use identity_did::DIDUrl;
  use identity_document::service::Service;
  use serde_json::json;

  #[test]
  fn test_create_service_single_vp() {
    let mut linked_vps: OrderedSet<Url> = OrderedSet::new();
    linked_vps.append(Url::parse("https://foo.example-1.com").unwrap());

    let service: LinkedVerifiablePresentationService = LinkedVerifiablePresentationService::new(
      DIDUrl::parse("did:example:123#foo").unwrap(),
      linked_vps,
      Object::new(),
    )
    .unwrap();

    let service_from_json: Service = Service::from_json_value(json!({
        "id": "did:example:123#foo",
        "type": "LinkedVerifiablePresentation",
        "serviceEndpoint": "https://foo.example-1.com"
    }))
    .unwrap();
    assert_eq!(Service::from(service), service_from_json);
  }

  #[test]
  fn test_create_service_multiple_vps() {
    let url_1 = "https://foo.example-1.com";
    let url_2 = "https://bar.example-2.com";
    let mut linked_vps = OrderedSet::new();
    linked_vps.append(Url::parse(url_1).unwrap());
    linked_vps.append(Url::parse(url_2).unwrap());

    let service: LinkedVerifiablePresentationService = LinkedVerifiablePresentationService::new(
      DIDUrl::parse("did:example:123#foo").unwrap(),
      linked_vps,
      Object::new(),
    )
    .unwrap();

    let service_from_json: Service = Service::from_json_value(json!({
        "id":"did:example:123#foo",
        "type": "LinkedVerifiablePresentation",
        "serviceEndpoint": [url_1, url_2]
    }))
    .unwrap();
    assert_eq!(Service::from(service), service_from_json);
  }

  #[test]
  fn test_valid_single_vp() {
    let service: Service = Service::from_json_value(json!({
        "id": "did:example:123#foo",
        "type": "LinkedVerifiablePresentation",
        "serviceEndpoint": "https://foo.example-1.com"
    }))
    .unwrap();
    let service: LinkedVerifiablePresentationService = LinkedVerifiablePresentationService::try_from(service).unwrap();
    let linked_vps: Vec<Url> = vec![Url::parse("https://foo.example-1.com").unwrap()];
    assert_eq!(service.verifiable_presentation_urls(), linked_vps);
  }

  #[test]
  fn test_valid_multiple_vps() {
    let service: Service = Service::from_json_value(json!({
        "id": "did:example:123#foo",
        "type": "LinkedVerifiablePresentation",
        "serviceEndpoint": ["https://foo.example-1.com", "https://foo.example-2.com"]
    }))
    .unwrap();
    let service: LinkedVerifiablePresentationService = LinkedVerifiablePresentationService::try_from(service).unwrap();
    let linked_vps: Vec<Url> = vec![
      Url::parse("https://foo.example-1.com").unwrap(),
      Url::parse("https://foo.example-2.com").unwrap(),
    ];
    assert_eq!(service.verifiable_presentation_urls(), linked_vps);
  }
}
