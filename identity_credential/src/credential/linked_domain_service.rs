// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_core::common::Object;
use identity_core::common::OrderedSet;
use identity_core::common::Url;
use identity_did::DIDUrl;
use identity_document::service::Service;
use identity_document::service::ServiceBuilder;
use identity_document::service::ServiceEndpoint;
use indexmap::map::IndexMap;

use crate::error::Result;
use crate::utils::url_only_includes_origin;
use crate::Error;
use crate::Error::DomainLinkageError;

/// A service wrapper for a [Linked Domain Service Endpoint](https://identity.foundation/.well-known/resources/did-configuration/#linked-domain-service-endpoint).
#[derive(Debug, Clone)]
pub struct LinkedDomainService {
  service: Service,
}

impl TryFrom<Service> for LinkedDomainService {
  type Error = Error;

  fn try_from(service: Service) -> std::result::Result<Self, Self::Error> {
    LinkedDomainService::check_structure(&service)?;
    Ok(LinkedDomainService { service })
  }
}

impl From<LinkedDomainService> for Service {
  fn from(service: LinkedDomainService) -> Self {
    service.service
  }
}

impl LinkedDomainService {
  pub(crate) fn domain_linkage_service_type() -> &'static str {
    "LinkedDomains"
  }

  /// Constructs a new `LinkedDomainService` that wraps a spec compliant [Linked Domain Service Endpoint](https://identity.foundation/.well-known/resources/did-configuration/#linked-domain-service-endpoint)
  /// Domain URLs must include the `https` scheme in order to pass the domain linkage validation.
  pub fn new(did_url: DIDUrl, domains: impl Into<OrderedSet<Url>>, properties: Object) -> Result<Self> {
    let domains: OrderedSet<Url> = domains.into();
    for domain in domains.iter() {
      if domain.scheme() != "https" {
        return Err(DomainLinkageError("domain does not include `https` scheme".into()));
      }
    }
    let builder: ServiceBuilder = Service::builder(properties)
      .id(did_url)
      .type_(Self::domain_linkage_service_type());
    if domains.len() == 1 {
      Ok(Self {
        service: builder
          .service_endpoint(ServiceEndpoint::One(
            domains.into_iter().next().expect("the len should be 1"),
          ))
          .build()
          .map_err(|err| DomainLinkageError(Box::new(err)))?,
      })
    } else {
      let mut map: IndexMap<String, OrderedSet<Url>> = IndexMap::new();
      map.insert("origins".to_owned(), domains);
      let service = builder
        .service_endpoint(ServiceEndpoint::Map(map))
        .build()
        .map_err(|err| DomainLinkageError(Box::new(err)))?;
      Ok(Self { service })
    }
  }

  /// Checks the semantic structure of a Linked Domain Service.
  ///
  /// Note: `{"type": ["LinkedDomains"]}` might be serialized the same way as  `{"type": "LinkedDomains"}`
  /// which passes the semantic check.
  pub fn check_structure(service: &Service) -> Result<()> {
    if service.type_().len() != 1 {
      return Err(DomainLinkageError("invalid service type".into()));
    }

    let service_type = service
      .type_()
      .get(0)
      .ok_or_else(|| DomainLinkageError("missing service type".into()))?;

    if service_type != Self::domain_linkage_service_type() {
      return Err(DomainLinkageError(
        format!("expected `{}` service type", Self::domain_linkage_service_type()).into(),
      ));
    }

    match service.service_endpoint() {
      ServiceEndpoint::One(endpoint) => {
        if endpoint.scheme() != "https" {
          Err(DomainLinkageError("domain does not include `https` scheme".into()))?;
        }
        if !url_only_includes_origin(endpoint) {
          Err(DomainLinkageError(
            "domain must not contain any path, query or fragment".into(),
          ))?;
        }
        Ok(())
      }
      ServiceEndpoint::Set(_) => Err(DomainLinkageError(
        "service endpoints must be either a string or an object containing an `origins` property".into(),
      )),
      ServiceEndpoint::Map(endpoint) => {
        if endpoint.is_empty() {
          return Err(DomainLinkageError("empty service endpoint map".into()));
        }
        let origins: &OrderedSet<Url> = endpoint
          .get("origins")
          .ok_or_else(|| DomainLinkageError("missing `origins` property in service endpoint".into()))?;

        for origin in origins.iter() {
          if origin.scheme() != "https" {
            return Err(DomainLinkageError("domain does not include `https` scheme".into()));
          }
          if !url_only_includes_origin(origin) {
            Err(DomainLinkageError(
              "domain must not contain any path, query or fragment".into(),
            ))?;
          }
        }
        Ok(())
      }
    }
  }

  /// Returns the domains contained in the Linked Domain Service.
  pub fn domains(&self) -> &[Url] {
    match self.service.service_endpoint() {
      ServiceEndpoint::One(endpoint) => std::slice::from_ref(endpoint),
      ServiceEndpoint::Set(_) => {
        unreachable!("the service endpoint is never a set per the `LinkedDomainService` type invariant")
      }
      ServiceEndpoint::Map(endpoint) => endpoint
        .get("origins")
        .expect("the `origins` property exists per the `LinkedDomainService` type invariant")
        .as_slice(),
    }
  }

  /// Returns a reference to the `Service` id.
  pub fn id(&self) -> &DIDUrl {
    self.service.id()
  }
}

#[cfg(test)]
mod tests {
  use crate::credential::linked_domain_service::LinkedDomainService;
  use identity_core::common::Object;
  use identity_core::common::OrderedSet;
  use identity_core::common::Url;
  use identity_core::convert::FromJson;
  use identity_did::DIDUrl;
  use identity_document::service::Service;
  use serde_json::json;

  #[test]
  fn test_create_service_multiple_origins() {
    let domain_1 = "https://foo.example-1.com";
    let domain_2 = "https://bar.example-2.com";
    let mut domains = OrderedSet::new();
    domains.append(Url::parse(domain_1).unwrap());
    domains.append(Url::parse(domain_2).unwrap());

    let service: LinkedDomainService =
      LinkedDomainService::new(DIDUrl::parse("did:example:123#foo").unwrap(), domains, Object::new()).unwrap();

    let service_from_json: Service = Service::from_json_value(json!({
        "id":"did:example:123#foo",
        "type": "LinkedDomains",
        "serviceEndpoint": {
          "origins": [domain_1, domain_2]
        }
    }))
    .unwrap();
    assert_eq!(Service::from(service), service_from_json);
  }

  #[test]
  fn test_create_service_single_origin() {
    let mut domains: OrderedSet<Url> = OrderedSet::new();
    domains.append(Url::parse("https://foo.example-1.com").unwrap());

    let service: LinkedDomainService =
      LinkedDomainService::new(DIDUrl::parse("did:example:123#foo").unwrap(), domains, Object::new()).unwrap();

    let service_from_json: Service = Service::from_json_value(json!({
        "id":"did:example:123#foo",
        "type": "LinkedDomains",
        "serviceEndpoint": "https://foo.example-1.com"
    }))
    .unwrap();
    assert_eq!(Service::from(service), service_from_json);
  }

  #[test]
  fn test_valid_domains() {
    let service_1: Service = Service::from_json_value(json!({
        "id":"did:example:123#foo",
        "type": "LinkedDomains",
        "serviceEndpoint": "https://foo.example-1.com"
    }))
    .unwrap();
    let service_1: LinkedDomainService = LinkedDomainService::try_from(service_1).unwrap();
    let domain: Vec<Url> = vec![Url::parse("https://foo.example-1.com").unwrap()];
    assert_eq!(service_1.domains(), domain);

    let service_2: Service = Service::from_json_value(json!({
        "id":"did:example:123#foo",
        "type": "LinkedDomains",
        "serviceEndpoint": { "origins" : ["https://foo.example-1.com", "https://foo.example-2.com"]}
    }))
    .unwrap();
    let service_2: LinkedDomainService = LinkedDomainService::try_from(service_2).unwrap();
    let domains: Vec<Url> = vec![
      Url::parse("https://foo.example-1.com").unwrap(),
      Url::parse("https://foo.example-2.com").unwrap(),
    ];
    assert_eq!(service_2.domains(), domains);
  }

  #[test]
  fn test_extract_domains_invalid_scheme() {
    // http scheme instead of https.
    let service_1: Service = Service::from_json_value(json!({
        "id":"did:example:123#foo",
        "type": "LinkedDomains",
        "serviceEndpoint": "http://foo.example-1.com"
    }))
    .unwrap();
    assert!(LinkedDomainService::try_from(service_1).is_err());

    let service_2: Service = Service::from_json_value(json!({
        "id":"did:example:123#foo",
        "type": "LinkedDomains",
        "serviceEndpoint": { "origins" : ["https://foo.example-1.com", "http://foo.example-2.com"]}
    }))
    .unwrap();
    assert!(LinkedDomainService::try_from(service_2).is_err());
  }

  #[test]
  fn test_extract_domain_type_check() {
    // Valid type.
    let service_1: Service = Service::from_json_value(json!({
        "id":"did:example:123#foo",
        "type": "LinkedDomains",
        "serviceEndpoint": "https://foo.example-1.com"
    }))
    .unwrap();
    assert!(LinkedDomainService::try_from(service_1).is_ok());

    // Invalid type 'LinkedDomain` instead of `LinkedDomains`.
    let service_2: Service = Service::from_json_value(json!({
        "id":"did:example:123#foo",
        "type": "LinkedDomain",
        "serviceEndpoint": "https://foo.example-1.com"
    }))
    .unwrap();
    assert!(LinkedDomainService::try_from(service_2).is_err());
  }
}
