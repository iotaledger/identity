// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_core::common::Object;

use crate::did::CoreDID;
use crate::did::DIDUrl;
use crate::did::DID;
use crate::error::Result;
use crate::service::Service;
use crate::service::ServiceEndpoint;

/// A `ServiceBuilder` is used to generate a customized `Service`.
#[derive(Clone, Debug)]
pub struct ServiceBuilder<D = CoreDID, T = Object>
where
  D: DID,
{
  pub(crate) id: Option<DIDUrl<D>>,
  pub(crate) type_: Option<String>,
  pub(crate) service_endpoint: Option<ServiceEndpoint>,
  pub(crate) properties: T,
}

impl<D, T> ServiceBuilder<D, T>
where
  D: DID,
{
  /// Creates a new `ServiceBuilder`.
  pub fn new(properties: T) -> Self {
    Self {
      id: None,
      type_: None,
      service_endpoint: None,
      properties,
    }
  }

  /// Sets the `id` value of the generated `Service`.
  #[must_use]
  pub fn id(mut self, value: DIDUrl<D>) -> Self {
    self.id = Some(value);
    self
  }

  /// Sets the `type` value of the generated `Service`.
  #[must_use]
  pub fn type_(mut self, value: impl Into<String>) -> Self {
    self.type_ = Some(value.into());
    self
  }

  /// Sets the `serviceEndpoint` value of the generated `Service`.
  #[must_use]
  pub fn service_endpoint(mut self, value: ServiceEndpoint) -> Self {
    self.service_endpoint = Some(value);
    self
  }

  /// Returns a new `Service` based on the `ServiceBuilder` configuration.
  pub fn build(self) -> Result<Service<D, T>> {
    Service::from_builder(self)
  }
}

impl<D, T> Default for ServiceBuilder<D, T>
where
  D: DID,
  T: Default,
{
  fn default() -> Self {
    Self {
      id: None,
      type_: None,
      service_endpoint: None,
      properties: T::default(),
    }
  }
}

#[cfg(test)]
mod tests {
  use crate::Error;
  use identity_core::common::Url;

  use super::*;

  #[test]
  fn test_success() {
    let _: Service = ServiceBuilder::default()
      .id("did:example:123#service".parse().unwrap())
      .type_("ServiceType")
      .service_endpoint(Url::parse("https://example.com").unwrap().into())
      .build()
      .unwrap();
  }

  #[test]
  fn test_missing_id() {
    let result: Result<Service> = ServiceBuilder::default()
      .type_("ServiceType")
      .service_endpoint(Url::parse("https://example.com").unwrap().into())
      .build();
    assert!(matches!(result.unwrap_err(), Error::InvalidService(_)));
  }

  #[test]
  fn test_missing_id_fragment() {
    let result: Result<Service> = ServiceBuilder::default()
      .id("did:example:123".parse().unwrap())
      .type_("ServiceType")
      .service_endpoint(Url::parse("https://example.com").unwrap().into())
      .build();
    assert!(matches!(result.unwrap_err(), Error::InvalidService(_)));
  }

  #[test]
  fn test_missing_type_() {
    let result: Result<Service> = ServiceBuilder::default()
      .id("did:example:123#service".parse().unwrap())
      .service_endpoint(Url::parse("https://example.com").unwrap().into())
      .build();
    assert!(matches!(result.unwrap_err(), Error::InvalidService(_)));
  }

  #[test]
  fn test_missing_service_endpoint() {
    let result: Result<Service> = ServiceBuilder::default()
      .id("did:example:123#service".parse().unwrap())
      .type_("ServiceType")
      .build();
    assert!(matches!(result.unwrap_err(), Error::InvalidService(_)));
  }
}
