// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::error::Error;
use std::fmt::Debug;
use std::str::FromStr;

use identity_did::BaseDIDUrl;
use identity_did::CoreDID;
use identity_did::Error as DIDError;
use identity_did::DID;
use identity_document::document::CoreDocument;
use identity_document::document::DocumentBuilder;

use crate::Error as ResolverError;
use crate::ErrorCause;
use crate::Resolver;

/// A very simple handler
async fn mock_handler(did: CoreDID) -> std::result::Result<CoreDocument, std::io::Error> {
  Ok(core_document(did))
}

/// Create a [`CoreDocument`]
fn core_document(did: CoreDID) -> CoreDocument {
  DocumentBuilder::default().id(did).build().unwrap()
}

/// A custom document type
#[derive(Debug, Clone)]
struct FooDocument(CoreDocument);
impl AsRef<CoreDocument> for FooDocument {
  fn as_ref(&self) -> &CoreDocument {
    &self.0
  }
}
impl From<CoreDocument> for FooDocument {
  fn from(value: CoreDocument) -> Self {
    Self(value)
  }
}

// ===========================================================================
// Missing handler for DID method failure tests
// ===========================================================================
#[tokio::test]
async fn missing_handler_errors() {
  let method_name: String = "foo".to_owned();
  let bad_did: CoreDID = CoreDID::parse(format!("did:{method_name}:1234")).unwrap();
  let other_method: String = "bar".to_owned();
  let good_did: CoreDID = CoreDID::parse(format!("did:{other_method}:1234")).unwrap();

  // configure `resolver` to resolve the "bar" method
  let mut resolver_foo: Resolver<FooDocument> = Resolver::new();
  let mut resolver_core: Resolver<CoreDocument> = Resolver::new();
  resolver_foo.attach_handler(other_method.clone(), mock_handler);
  resolver_core.attach_handler(other_method, mock_handler);

  let err: ResolverError = resolver_foo.resolve(&bad_did).await.unwrap_err();
  let ErrorCause::UnsupportedMethodError { method } = err.into_error_cause() else {
    unreachable!()
  };
  assert_eq!(method_name, method);

  let err: ResolverError = resolver_core.resolve(&bad_did).await.unwrap_err();
  let ErrorCause::UnsupportedMethodError { method } = err.into_error_cause() else {
    unreachable!()
  };
  assert_eq!(method_name, method);

  assert!(resolver_foo.resolve(&good_did).await.is_ok());
  assert!(resolver_core.resolve(&good_did).await.is_ok());

  let both_dids = [good_did, bad_did];
  let err: ResolverError = resolver_foo.resolve_multiple(&both_dids).await.unwrap_err();
  let ErrorCause::UnsupportedMethodError { method } = err.into_error_cause() else {
    unreachable!()
  };
  assert_eq!(method_name, method);

  let err: ResolverError = resolver_core.resolve_multiple(&both_dids).await.unwrap_err();
  let ErrorCause::UnsupportedMethodError { method } = err.into_error_cause() else {
    unreachable!()
  };
  assert_eq!(method_name, method);
}

// ===========================================================================
// DID Parsing failure tests
// ===========================================================================

// Implement the DID trait for a new type
#[derive(Hash, Ord, PartialOrd, Eq, PartialEq, Clone)]
struct FooDID(CoreDID);

impl FooDID {
  const METHOD_ID_LENGTH: usize = 5;

  fn try_from_core(did: CoreDID) -> std::result::Result<Self, DIDError> {
    Some(did)
      .filter(|did| did.method() == "foo" && did.method_id().len() == FooDID::METHOD_ID_LENGTH)
      .map(Self)
      .ok_or(DIDError::InvalidMethodName)
  }
}

impl AsRef<CoreDID> for FooDID {
  fn as_ref(&self) -> &CoreDID {
    &self.0
  }
}

impl From<FooDID> for String {
  fn from(did: FooDID) -> Self {
    String::from(did.0)
  }
}
impl From<FooDID> for CoreDID {
  fn from(value: FooDID) -> Self {
    value.0
  }
}

impl TryFrom<CoreDID> for FooDID {
  type Error = DIDError;
  fn try_from(value: CoreDID) -> Result<Self, Self::Error> {
    Self::try_from_core(value)
  }
}

impl FromStr for FooDID {
  type Err = DIDError;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    CoreDID::from_str(s).and_then(Self::try_from_core)
  }
}

impl TryFrom<BaseDIDUrl> for FooDID {
  type Error = DIDError;
  fn try_from(value: BaseDIDUrl) -> Result<Self, Self::Error> {
    CoreDID::try_from(value).and_then(Self::try_from_core)
  }
}

impl<'a> TryFrom<&'a str> for FooDID {
  type Error = DIDError;
  fn try_from(value: &'a str) -> Result<Self, Self::Error> {
    CoreDID::try_from(value).and_then(Self::try_from_core)
  }
}

#[tokio::test]
async fn resolve_unparsable() {
  let mut resolver_foo: Resolver<FooDocument> = Resolver::new();
  let mut resolver_core: Resolver<CoreDocument> = Resolver::new();

  // register a handler that wants `did` to be of type `FooDID`.
  async fn handler(did: FooDID) -> std::result::Result<CoreDocument, std::io::Error> {
    mock_handler(did.as_ref().clone()).await
  }

  resolver_foo.attach_handler("foo".to_owned(), handler);
  resolver_core.attach_handler("foo".to_owned(), handler);

  let bad_did: CoreDID = CoreDID::parse("did:foo:1234").unwrap();
  // ensure that the DID we created does not satisfy the requirements of the "foo" method
  assert!(bad_did.method_id().len() < FooDID::METHOD_ID_LENGTH);

  let good_did: FooDID = FooDID::try_from("did:foo:12345").unwrap();

  let error_matcher = |err: ErrorCause| {
    assert!(matches!(
      err
        .source()
        .unwrap()
        .downcast_ref::<DIDError>()
        .unwrap_or_else(|| panic!("{:?}", &err)),
      &DIDError::InvalidMethodName
    ));

    match err {
      ErrorCause::DIDParsingError { .. } => {}
      _ => unreachable!(),
    }
  };

  let err_cause: ErrorCause = resolver_foo.resolve(&bad_did).await.unwrap_err().into_error_cause();
  error_matcher(err_cause);

  let err_cause: ErrorCause = resolver_core.resolve(&bad_did).await.unwrap_err().into_error_cause();
  error_matcher(err_cause);

  assert!(resolver_foo.resolve(&good_did).await.is_ok());
  assert!(resolver_core.resolve(&good_did).await.is_ok());
}

// ===========================================================================
// Failing handler tests
// ===========================================================================

#[tokio::test]
async fn handler_failure() {
  #[derive(Debug, thiserror::Error)]
  #[error("resolution failed")]
  struct ResolutionError;
  async fn failing_handler(_did: CoreDID) -> std::result::Result<CoreDocument, ResolutionError> {
    Err(ResolutionError)
  }

  let mut resolver_foo: Resolver<FooDocument> = Resolver::new();
  let mut resolver_core: Resolver<CoreDocument> = Resolver::new();
  resolver_foo.attach_handler("foo".to_owned(), failing_handler);
  resolver_core.attach_handler("foo".to_owned(), failing_handler);

  let bad_did: CoreDID = CoreDID::parse("did:foo:1234").unwrap();
  let good_did: CoreDID = CoreDID::parse("did:bar:1234").unwrap();
  resolver_foo.attach_handler(good_did.method().to_owned(), mock_handler);
  resolver_core.attach_handler(good_did.method().to_owned(), mock_handler);

  // to avoid boiler plate
  let error_matcher = |err: ErrorCause| {
    assert!(err.source().unwrap().downcast_ref::<ResolutionError>().is_some());
    match err {
      ErrorCause::HandlerError { .. } => {}
      _ => unreachable!(),
    }
  };

  let err_cause: ErrorCause = resolver_foo.resolve(&bad_did).await.unwrap_err().into_error_cause();
  error_matcher(err_cause);

  let err_cause: ErrorCause = resolver_core.resolve(&bad_did).await.unwrap_err().into_error_cause();
  error_matcher(err_cause);

  assert!(resolver_foo.resolve(&good_did).await.is_ok());
  assert!(resolver_core.resolve(&good_did).await.is_ok());
}

// ===========================================================================
// Resolve Multiple.
// ===========================================================================

#[tokio::test]
async fn resolve_multiple() {
  let method_name: String = "foo".to_owned();

  let did_1: CoreDID = CoreDID::parse(format!("did:{method_name}:1111")).unwrap();
  let did_2: CoreDID = CoreDID::parse(format!("did:{method_name}:2222")).unwrap();
  let did_3: CoreDID = CoreDID::parse(format!("did:{method_name}:3333")).unwrap();
  let did_1_clone: CoreDID = CoreDID::parse(format!("did:{method_name}:1111")).unwrap();

  let mut resolver: Resolver<CoreDocument> = Resolver::new();
  resolver.attach_handler(method_name, mock_handler);

  // Resolve with duplicate `did_3`.
  let resolved_dids: HashMap<CoreDID, CoreDocument> = resolver
    .resolve_multiple(&[
      did_1.clone(),
      did_2.clone(),
      did_3.clone(),
      did_1_clone.clone(),
      did_3.clone(),
    ])
    .await
    .unwrap();

  assert_eq!(resolved_dids.len(), 3);
  assert_eq!(resolved_dids.get(&did_1).unwrap().id(), &did_1);
  assert_eq!(resolved_dids.get(&did_2).unwrap().id(), &did_2);
  assert_eq!(resolved_dids.get(&did_3).unwrap().id(), &did_3);
  assert_eq!(resolved_dids.get(&did_1_clone).unwrap().id(), &did_1_clone);

  let dids: &[CoreDID] = &[];
  let resolved_dids: HashMap<CoreDID, CoreDocument> = resolver.resolve_multiple(dids).await.unwrap();
  assert_eq!(resolved_dids.len(), 0);

  let resolved_dids: HashMap<CoreDID, CoreDocument> =
    resolver.resolve_multiple(std::slice::from_ref(&did_1)).await.unwrap();
  assert_eq!(resolved_dids.len(), 1);
  assert_eq!(resolved_dids.get(&did_1).unwrap().id(), &did_1);
}
