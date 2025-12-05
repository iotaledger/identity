// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(deprecated)]

use identity_core::common::Context;
use identity_core::common::Object;
use identity_core::common::Url;
use identity_core::common::Value;

use crate::credential::Credential;
use crate::credential::CredentialV2;
use crate::credential::Policy;
use crate::credential::RefreshService;
use crate::error::Result;

use super::Presentation;

/// A `PresentationBuilder` is used to create a customized [Presentation].
#[derive(Clone, Debug)]
pub struct PresentationBuilder<CRED, T = Object> {
  pub(crate) context: Vec<Context>,
  pub(crate) id: Option<Url>,
  pub(crate) types: Vec<String>,
  pub(crate) credentials: Vec<CRED>,
  pub(crate) holder: Url,
  pub(crate) refresh_service: Vec<RefreshService>,
  pub(crate) terms_of_use: Vec<Policy>,
  pub(crate) properties: T,
}

impl<CRED, T> PresentationBuilder<CRED, T> {
  /// Creates a new `PresentationBuilder`.
  pub fn new(holder: Url, properties: T) -> Self {
    Self {
      context: Vec::new(),
      id: None,
      types: vec![Presentation::<T>::base_type().into()],
      credentials: Vec::new(),
      holder,
      refresh_service: Vec::new(),
      terms_of_use: Vec::new(),
      properties,
    }
  }

  /// Adds a value to the `context` set.
  #[must_use]
  pub fn context(mut self, value: impl Into<Context>) -> Self {
    self.context.push(value.into());
    self
  }

  /// Sets the unique identifier of the presentation.
  #[must_use]
  pub fn id(mut self, value: Url) -> Self {
    self.id = Some(value);
    self
  }

  /// Adds a value to the `type` set.
  #[must_use]
  pub fn type_(mut self, value: impl Into<String>) -> Self {
    self.types.push(value.into());
    self
  }

  /// Adds a value to the `verifiableCredential` set.
  #[must_use]
  pub fn credential(mut self, value: CRED) -> Self {
    self.credentials.push(value);
    self
  }

  /// Adds a value to the `refreshService` set.
  #[must_use]
  pub fn refresh_service(mut self, value: RefreshService) -> Self {
    self.refresh_service.push(value);
    self
  }

  /// Adds a value to the `termsOfUse` set.
  #[must_use]
  pub fn terms_of_use(mut self, value: Policy) -> Self {
    self.terms_of_use.push(value);
    self
  }

  /// Returns a new `Presentation` based on the `PresentationBuilder` configuration.
  /// # Notes
  /// If no context has been set, the base context of VC Data Model 1.1 will be used.
  pub fn build(mut self) -> Result<Presentation<CRED, T>> {
    if self.context.first() != Some(Credential::<()>::base_context())
      || self.context.first() != Some(CredentialV2::<()>::base_context())
    {
      self.context.insert(0, Credential::<()>::base_context().clone());
    }

    Presentation::from_builder(self)
  }

  /// Returns a new `Presentation` based on the `PresentationBuilder` configuration.
  /// # Notes
  /// If no context has been set, the base context of VC Data Model 2.0 will be used.
  pub fn build_v2(mut self) -> Result<Presentation<CRED, T>> {
    if self.context.first() != Some(Credential::<()>::base_context())
      || self.context.first() != Some(CredentialV2::<()>::base_context())
    {
      self.context.insert(0, CredentialV2::<()>::base_context().clone());
    }

    Presentation::from_builder(self)
  }
}

impl PresentationBuilder<Object> {
  /// Adds a new custom property.
  #[must_use]
  pub fn property<K, V>(mut self, key: K, value: V) -> Self
  where
    K: Into<String>,
    V: Into<Value>,
  {
    self.properties.insert(key.into(), value.into());
    self
  }

  /// Adds a series of custom properties.
  #[must_use]
  pub fn properties<K, V, I>(mut self, iter: I) -> Self
  where
    I: IntoIterator<Item = (K, V)>,
    K: Into<String>,
    V: Into<Value>,
  {
    self
      .properties
      .extend(iter.into_iter().map(|(k, v)| (k.into(), v.into())));
    self
  }
}

#[cfg(test)]
mod tests {
  use serde_json::json;
  use serde_json::Value;

  use identity_core::common::Object;
  use identity_core::common::Url;
  use identity_core::convert::FromJson;

  use crate::credential::Credential;
  use crate::credential::CredentialBuilder;
  use crate::credential::Jwt;
  use crate::credential::Subject;
  use crate::presentation::Presentation;
  use crate::presentation::PresentationBuilder;

  fn subject() -> Subject {
    let json: Value = json!({
      "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
      "degree": {
        "type": "BachelorDegree",
        "name": "Bachelor of Science and Arts"
      }
    });

    Subject::from_json_value(json).unwrap()
  }

  fn issuer() -> Url {
    Url::parse("did:example:issuer").unwrap()
  }

  #[test]
  fn test_presentation_builder_valid() {
    let credential: Credential = CredentialBuilder::default()
      .type_("ExampleCredential")
      .subject(subject())
      .issuer(issuer())
      .build()
      .unwrap();

    let credential_jwt = Jwt::new(credential.serialize_jwt(None).unwrap());

    let presentation: Presentation<Jwt> = PresentationBuilder::new(Url::parse("did:test:abc1").unwrap(), Object::new())
      .type_("ExamplePresentation")
      .credential(credential_jwt)
      .build()
      .unwrap();

    assert_eq!(presentation.context.len(), 1);
    assert_eq!(
      presentation.context.get(0).unwrap(),
      Presentation::<Object>::base_context()
    );
    assert_eq!(presentation.types.len(), 2);
    assert_eq!(presentation.types.get(0).unwrap(), Presentation::<Object>::base_type());
    assert_eq!(presentation.types.get(1).unwrap(), "ExamplePresentation");
    assert_eq!(presentation.verifiable_credential.len(), 1);
  }

  #[test]
  fn test_presentation_builder_valid_without_credentials() {
    let presentation: Presentation<Jwt> = PresentationBuilder::new(Url::parse("did:test:abc1").unwrap(), Object::new())
      .type_("ExamplePresentation")
      .build()
      .unwrap();

    assert_eq!(presentation.context.len(), 1);
    assert_eq!(
      presentation.context.get(0).unwrap(),
      Presentation::<Object>::base_context()
    );
    assert_eq!(presentation.types.len(), 2);
    assert_eq!(presentation.types.get(0).unwrap(), Presentation::<Object>::base_type());
    assert_eq!(presentation.types.get(1).unwrap(), "ExamplePresentation");
    assert_eq!(presentation.verifiable_credential.len(), 0);
  }
}
