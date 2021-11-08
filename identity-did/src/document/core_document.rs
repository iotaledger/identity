// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::convert::TryInto as _;
use core::fmt::Display;
use core::fmt::Error as FmtError;
use core::fmt::Formatter;
use core::fmt::Result as FmtResult;

use serde::Serialize;

use identity_core::common::Object;
use identity_core::common::Url;
use identity_core::convert::ToJson;

use crate::did::CoreDID;
use crate::did::CoreDIDUrl;
use crate::document::DocumentBuilder;
use crate::error::Error;
use crate::error::Result;
use crate::service::Service;
use crate::utils::OrderedSet;
use crate::verification::MethodQuery;
use crate::verification::MethodRef;
use crate::verification::MethodScope;
use crate::verification::VerificationMethod;

/// A DID Document.
///
/// [Specification](https://www.w3.org/TR/did-core/#did-document-properties)
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[rustfmt::skip]
pub struct CoreDocument<T = Object, U = Object, V = Object> {
  pub(crate) id: CoreDID,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub(crate) controller: Option<CoreDID>,
  #[serde(default = "Default::default", rename = "alsoKnownAs", skip_serializing_if = "Vec::is_empty")]
  pub(crate) also_known_as: Vec<Url>,
  #[serde(default = "Default::default", rename = "verificationMethod", skip_serializing_if = "OrderedSet::is_empty")]
  pub(crate) verification_method: OrderedSet<VerificationMethod<U>>,
  #[serde(default = "Default::default", skip_serializing_if = "OrderedSet::is_empty")]
  pub(crate) authentication: OrderedSet<MethodRef<U>>,
  #[serde(default = "Default::default", rename = "assertionMethod", skip_serializing_if = "OrderedSet::is_empty")]
  pub(crate) assertion_method: OrderedSet<MethodRef<U>>,
  #[serde(default = "Default::default", rename = "keyAgreement", skip_serializing_if = "OrderedSet::is_empty")]
  pub(crate) key_agreement: OrderedSet<MethodRef<U>>,
  #[serde(default = "Default::default", rename = "capabilityDelegation", skip_serializing_if = "OrderedSet::is_empty")]
  pub(crate) capability_delegation: OrderedSet<MethodRef<U>>,
  #[serde(default = "Default::default", rename = "capabilityInvocation", skip_serializing_if = "OrderedSet::is_empty")]
  pub(crate) capability_invocation: OrderedSet<MethodRef<U>>,
  #[serde(default = "Default::default", skip_serializing_if = "OrderedSet::is_empty")]
  pub(crate) service: OrderedSet<Service<V>>,
  #[serde(flatten)]
  pub(crate) properties: T,
}

impl<T, U, V> CoreDocument<T, U, V> {
  /// Creates a [`DocumentBuilder`] to configure a new `CoreDocument`.
  ///
  /// This is the same as [`DocumentBuilder::new`].
  pub fn builder(properties: T) -> DocumentBuilder<T, U, V> {
    DocumentBuilder::new(properties)
  }

  /// Returns a new `CoreDocument` based on the [`DocumentBuilder`] configuration.
  pub fn from_builder(builder: DocumentBuilder<T, U, V>) -> Result<Self> {
    Ok(Self {
      id: builder.id.ok_or(Error::BuilderInvalidDocumentId)?,
      controller: builder.controller,
      also_known_as: builder.also_known_as,
      verification_method: builder.verification_method.try_into()?,
      authentication: builder.authentication.try_into()?,
      assertion_method: builder.assertion_method.try_into()?,
      key_agreement: builder.key_agreement.try_into()?,
      capability_delegation: builder.capability_delegation.try_into()?,
      capability_invocation: builder.capability_invocation.try_into()?,
      service: builder.service.try_into()?,
      properties: builder.properties,
    })
  }

  /// Returns a reference to the `CoreDocument` id.
  pub fn id(&self) -> &CoreDID {
    &self.id
  }

  /// Returns a mutable reference to the `CoreDocument` id.
  pub fn id_mut(&mut self) -> &mut CoreDID {
    &mut self.id
  }

  /// Returns a reference to the `CoreDocument` controller.
  pub fn controller(&self) -> Option<&CoreDID> {
    self.controller.as_ref()
  }

  /// Returns a mutable reference to the `CoreDocument` controller.
  pub fn controller_mut(&mut self) -> Option<&mut CoreDID> {
    self.controller.as_mut()
  }

  /// Returns a reference to the `CoreDocument` alsoKnownAs set.
  pub fn also_known_as(&self) -> &[Url] {
    &self.also_known_as
  }

  /// Returns a mutable reference to the `CoreDocument` alsoKnownAs set.
  pub fn also_known_as_mut(&mut self) -> &mut Vec<Url> {
    &mut self.also_known_as
  }

  /// Returns a reference to the `CoreDocument` verificationMethod set.
  pub fn verification_method(&self) -> &OrderedSet<VerificationMethod<U>> {
    &self.verification_method
  }

  /// Returns a mutable reference to the `CoreDocument` verificationMethod set.
  pub fn verification_method_mut(&mut self) -> &mut OrderedSet<VerificationMethod<U>> {
    &mut self.verification_method
  }

  /// Returns a reference to the `CoreDocument` authentication set.
  pub fn authentication(&self) -> &OrderedSet<MethodRef<U>> {
    &self.authentication
  }

  /// Returns a mutable reference to the `CoreDocument` authentication set.
  pub fn authentication_mut(&mut self) -> &mut OrderedSet<MethodRef<U>> {
    &mut self.authentication
  }

  /// Returns a reference to the `CoreDocument` assertionMethod set.
  pub fn assertion_method(&self) -> &OrderedSet<MethodRef<U>> {
    &self.assertion_method
  }

  /// Returns a mutable reference to the `CoreDocument` assertionMethod set.
  pub fn assertion_method_mut(&mut self) -> &mut OrderedSet<MethodRef<U>> {
    &mut self.assertion_method
  }

  /// Returns a reference to the `CoreDocument` keyAgreement set.
  pub fn key_agreement(&self) -> &OrderedSet<MethodRef<U>> {
    &self.key_agreement
  }

  /// Returns a mutable reference to the `CoreDocument` keyAgreement set.
  pub fn key_agreement_mut(&mut self) -> &mut OrderedSet<MethodRef<U>> {
    &mut self.key_agreement
  }

  /// Returns a reference to the `CoreDocument` capabilityDelegation set.
  pub fn capability_delegation(&self) -> &OrderedSet<MethodRef<U>> {
    &self.capability_delegation
  }

  /// Returns a mutable reference to the `CoreDocument` capabilityDelegation set.
  pub fn capability_delegation_mut(&mut self) -> &mut OrderedSet<MethodRef<U>> {
    &mut self.capability_delegation
  }

  /// Returns a reference to the `CoreDocument` capabilityInvocation set.
  pub fn capability_invocation(&self) -> &OrderedSet<MethodRef<U>> {
    &self.capability_invocation
  }

  /// Returns a mutable reference to the `CoreDocument` capabilityInvocation set.
  pub fn capability_invocation_mut(&mut self) -> &mut OrderedSet<MethodRef<U>> {
    &mut self.capability_invocation
  }

  /// Returns a reference to the `CoreDocument` service set.
  pub fn service(&self) -> &OrderedSet<Service<V>> {
    &self.service
  }

  /// Returns a mutable reference to the `CoreDocument` service set.
  pub fn service_mut(&mut self) -> &mut OrderedSet<Service<V>> {
    &mut self.service
  }

  /// Returns a reference to the custom `CoreDocument` properties.
  pub fn properties(&self) -> &T {
    &self.properties
  }

  /// Returns a mutable reference to the custom `CoreDocument` properties.
  pub fn properties_mut(&mut self) -> &mut T {
    &mut self.properties
  }

  /// Maps `CoreDocument<T>` to `CoreDocument<U>` by applying a function to the custom
  /// properties.
  pub fn map<A, F>(self, f: F) -> CoreDocument<A, U, V>
  where
    F: FnOnce(T) -> A,
  {
    CoreDocument {
      id: self.id,
      controller: self.controller,
      also_known_as: self.also_known_as,
      verification_method: self.verification_method,
      authentication: self.authentication,
      assertion_method: self.assertion_method,
      key_agreement: self.key_agreement,
      capability_delegation: self.capability_delegation,
      capability_invocation: self.capability_invocation,
      service: self.service,
      properties: f(self.properties),
    }
  }

  /// Fallible version of [`CoreDocument::map`].
  ///
  /// # Errors
  ///
  /// `try_map` can fail if the provided function fails.
  pub fn try_map<A, F, E>(self, f: F) -> Result<CoreDocument<A, U, V>, E>
  where
    F: FnOnce(T) -> Result<A, E>,
  {
    Ok(CoreDocument {
      id: self.id,
      controller: self.controller,
      also_known_as: self.also_known_as,
      verification_method: self.verification_method,
      authentication: self.authentication,
      assertion_method: self.assertion_method,
      key_agreement: self.key_agreement,
      capability_delegation: self.capability_delegation,
      capability_invocation: self.capability_invocation,
      service: self.service,
      properties: f(self.properties)?,
    })
  }

  /// Adds a new [`VerificationMethod`] to the Document.
  pub fn insert_method(&mut self, method: VerificationMethod<U>, scope: MethodScope) -> bool {
    match scope {
      MethodScope::VerificationMethod => self.verification_method.append(method),
      MethodScope::Authentication => self.authentication.append(MethodRef::Embed(method)),
      MethodScope::AssertionMethod => self.assertion_method.append(MethodRef::Embed(method)),
      MethodScope::KeyAgreement => self.key_agreement.append(MethodRef::Embed(method)),
      MethodScope::CapabilityDelegation => self.capability_delegation.append(MethodRef::Embed(method)),
      MethodScope::CapabilityInvocation => self.capability_invocation.append(MethodRef::Embed(method)),
    }
  }

  /// Removes all references to the specified [`VerificationMethod`].
  pub fn remove_method(&mut self, did: &CoreDIDUrl) {
    self.authentication.remove(did);
    self.assertion_method.remove(did);
    self.key_agreement.remove(did);
    self.capability_delegation.remove(did);
    self.capability_invocation.remove(did);
    self.verification_method.remove(did);
  }

  /// Returns an iterator over all embedded verification methods in the DID Document.
  ///
  /// This excludes verification methods that are referenced by the DID Document.
  pub fn methods(&self) -> impl Iterator<Item = &VerificationMethod<U>> {
    fn __filter_ref<T>(method: &MethodRef<T>) -> Option<&VerificationMethod<T>> {
      match method {
        MethodRef::Embed(method) => Some(method),
        MethodRef::Refer(_) => None,
      }
    }

    self
      .verification_method
      .iter()
      .chain(self.authentication.iter().filter_map(__filter_ref))
      .chain(self.assertion_method.iter().filter_map(__filter_ref))
      .chain(self.key_agreement.iter().filter_map(__filter_ref))
      .chain(self.capability_delegation.iter().filter_map(__filter_ref))
      .chain(self.capability_invocation.iter().filter_map(__filter_ref))
  }

  /// Returns an iterator over all verification relationships.
  ///
  /// This includes embedded and referenced [`VerificationMethods`](VerificationMethod).
  pub fn verification_relationships(&self) -> impl Iterator<Item = &MethodRef<U>> {
    self
      .authentication
      .iter()
      .chain(self.assertion_method.iter())
      .chain(self.key_agreement.iter())
      .chain(self.capability_delegation.iter())
      .chain(self.capability_invocation.iter())
  }

  /// Returns the first [`VerificationMethod`] with an `id` property matching the provided `query`.
  pub fn resolve_method<'query, Q>(&self, query: Q) -> Option<&VerificationMethod<U>>
  where
    Q: Into<MethodQuery<'query>>,
  {
    self.resolve_method_inner(query.into())
  }

  /// Returns the first [`VerificationMethod`] with an `id` property matching the provided `query`.
  ///
  /// # Errors
  ///
  /// Fails if no matching method is found.
  pub fn try_resolve_method<'query, Q>(&self, query: Q) -> Result<&VerificationMethod<U>>
  where
    Q: Into<MethodQuery<'query>>,
  {
    self
      .resolve_method_inner(query.into())
      .ok_or(Error::QueryMethodNotFound)
  }

  /// Returns the first [`VerificationMethod`] with an `id` property matching the provided `query`
  /// and the verification relationship specified by `scope`.
  pub fn resolve_method_with_scope<'query, 's: 'query, Q>(
    &'s self,
    query: Q,
    scope: MethodScope,
  ) -> Option<&VerificationMethod<U>>
  where
    Q: Into<MethodQuery<'query>>,
  {
    let resolve_ref_helper = |method_ref: &'s MethodRef<U>| self.resolve_method_ref(method_ref);

    match scope {
      MethodScope::VerificationMethod => self.verification_method.query(query.into()),
      MethodScope::Authentication => self.authentication.query(query.into()).and_then(resolve_ref_helper),
      MethodScope::AssertionMethod => self.assertion_method.query(query.into()).and_then(resolve_ref_helper),
      MethodScope::KeyAgreement => self.key_agreement.query(query.into()).and_then(resolve_ref_helper),
      MethodScope::CapabilityDelegation => self
        .capability_delegation
        .query(query.into())
        .and_then(resolve_ref_helper),
      MethodScope::CapabilityInvocation => self
        .capability_invocation
        .query(query.into())
        .and_then(resolve_ref_helper),
    }
  }

  /// Returns the first [`VerificationMethod`] with an `id` property matching the provided `query`
  /// and the verification relationship specified by `scope`.
  ///
  /// # Errors
  ///
  /// Fails if no matching [`VerificationMethod`] is found.
  pub fn try_resolve_method_with_scope<'query, 's: 'query, Q>(
    &'s self,
    query: Q,
    scope: MethodScope,
  ) -> Result<&VerificationMethod<U>>
  where
    Q: Into<MethodQuery<'query>>,
  {
    self
      .resolve_method_with_scope(query, scope)
      .ok_or(Error::QueryMethodNotFound)
  }

  /// Returns a mutable reference to the first [`VerificationMethod`] with an `id` property
  /// matching the provided `query`.
  pub fn resolve_method_mut<'query, Q>(&mut self, query: Q) -> Option<&mut VerificationMethod<U>>
  where
    Q: Into<MethodQuery<'query>>,
  {
    self.resolve_method_mut_inner(query.into())
  }

  /// Returns a mutable reference to the first [`VerificationMethod`] with an `id` property
  /// matching the provided `query`.
  ///
  /// # Errors
  ///
  /// Fails if no matching [`VerificationMethod`] is found.
  pub fn try_resolve_method_mut<'query, Q>(&mut self, query: Q) -> Result<&mut VerificationMethod<U>>
  where
    Q: Into<MethodQuery<'query>>,
  {
    self
      .resolve_method_mut_inner(query.into())
      .ok_or(Error::QueryMethodNotFound)
  }

  #[doc(hidden)]
  pub fn resolve_method_ref<'a>(&'a self, method_ref: &'a MethodRef<U>) -> Option<&'a VerificationMethod<U>> {
    match method_ref {
      MethodRef::Embed(method) => Some(method),
      MethodRef::Refer(did) => self.verification_method.query(did),
    }
  }

  fn resolve_method_inner(&self, query: MethodQuery<'_>) -> Option<&VerificationMethod<U>> {
    let mut method: Option<&MethodRef<U>> = None;

    if method.is_none() {
      method = self.authentication.query(query.clone());
    }

    if method.is_none() {
      method = self.assertion_method.query(query.clone());
    }

    if method.is_none() {
      method = self.key_agreement.query(query.clone());
    }

    if method.is_none() {
      method = self.capability_delegation.query(query.clone());
    }

    if method.is_none() {
      method = self.capability_invocation.query(query.clone());
    }

    match method {
      Some(MethodRef::Embed(method)) => Some(method),
      Some(MethodRef::Refer(did)) => self.verification_method.query(&did.to_string()),
      None => self.verification_method.query(query),
    }
  }

  fn resolve_method_mut_inner(&mut self, query: MethodQuery<'_>) -> Option<&mut VerificationMethod<U>> {
    let mut method: Option<&mut MethodRef<U>> = None;

    if method.is_none() {
      method = self.authentication.query_mut(query.clone());
    }

    if method.is_none() {
      method = self.assertion_method.query_mut(query.clone());
    }

    if method.is_none() {
      method = self.key_agreement.query_mut(query.clone());
    }

    if method.is_none() {
      method = self.capability_delegation.query_mut(query.clone());
    }

    if method.is_none() {
      method = self.capability_invocation.query_mut(query.clone());
    }

    match method {
      Some(MethodRef::Embed(method)) => Some(method),
      Some(MethodRef::Refer(did)) => self.verification_method.query_mut(&did.to_string()),
      None => self.verification_method.query_mut(query),
    }
  }
}

impl<T, U, V> Display for CoreDocument<T, U, V>
where
  T: Serialize,
  U: Serialize,
  V: Serialize,
{
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    if f.alternate() {
      f.write_str(&self.to_json_pretty().map_err(|_| FmtError)?)
    } else {
      f.write_str(&self.to_json().map_err(|_| FmtError)?)
    }
  }
}

#[cfg(test)]
mod tests {
  use crate::did::CoreDID;
  use crate::did::DID;
  use crate::document::CoreDocument;
  use crate::verification::MethodData;
  use crate::verification::MethodType;
  use crate::verification::VerificationMethod;

  fn controller() -> CoreDID {
    "did:example:1234".parse().unwrap()
  }

  fn method(controller: &CoreDID, fragment: &str) -> VerificationMethod {
    VerificationMethod::builder(Default::default())
      .id(controller.to_url().join(fragment).unwrap())
      .controller(controller.clone())
      .key_type(MethodType::Ed25519VerificationKey2018)
      .key_data(MethodData::new_multibase(fragment.as_bytes()))
      .build()
      .unwrap()
  }

  fn document() -> CoreDocument {
    let controller: CoreDID = controller();

    CoreDocument::builder(Default::default())
      .id(controller.clone())
      .verification_method(method(&controller, "#key-1"))
      .verification_method(method(&controller, "#key-2"))
      .verification_method(method(&controller, "#key-3"))
      .authentication(method(&controller, "#auth-key"))
      .authentication(controller.to_url().join("#key-3").unwrap())
      .key_agreement(controller.to_url().join("#key-4").unwrap())
      .build()
      .unwrap()
  }

  #[rustfmt::skip]
  #[test]
  fn test_resolve_method() {
    let document: CoreDocument = document();

    // Resolve methods by fragment.
    assert_eq!(document.resolve_method("#key-1").unwrap().id().to_string(), "did:example:1234#key-1");
    assert_eq!(document.resolve_method("#key-2").unwrap().id().to_string(), "did:example:1234#key-2");
    assert_eq!(document.resolve_method("#key-3").unwrap().id().to_string(), "did:example:1234#key-3");

    // Fine to omit the octothorpe.
    assert_eq!(document.resolve_method("key-1").unwrap().id().to_string(), "did:example:1234#key-1");
    assert_eq!(document.resolve_method("key-2").unwrap().id().to_string(), "did:example:1234#key-2");
    assert_eq!(document.resolve_method("key-3").unwrap().id().to_string(), "did:example:1234#key-3");

    // Resolve methods by full DID Url id.
    assert_eq!(document.resolve_method("did:example:1234#key-1").unwrap().id().to_string(), "did:example:1234#key-1");
    assert_eq!(document.resolve_method("did:example:1234#key-2").unwrap().id().to_string(), "did:example:1234#key-2");
    assert_eq!(document.resolve_method("did:example:1234#key-3").unwrap().id().to_string(), "did:example:1234#key-3");
  }

  #[test]
  fn test_resolve_method_fails() {
    let document: CoreDocument = document();

    // Resolving an existing reference to a missing method returns None.
    assert_eq!(document.resolve_method("#key-4"), None);

    // Resolving a plain DID returns None.
    assert_eq!(document.resolve_method("did:example:1234"), None);

    // Resolving an empty string returns None.
    assert_eq!(document.resolve_method(""), None);
  }

  #[rustfmt::skip]
  #[test]
  fn test_methods_index() {
    let document: CoreDocument = document();

    // Access methods by index.
    assert_eq!(document.methods().next().unwrap().id().to_string(), "did:example:1234#key-1");
    assert_eq!(document.methods().nth(2).unwrap().id().to_string(), "did:example:1234#key-3");
  }
}
