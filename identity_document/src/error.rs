// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Errors that may occur when working with DID Documents.

#[cfg(target_arch = "wasm32")]
use product_common::impl_wasm_error_from;

/// Alias for a [`Result`][::core::result::Result] with the error type [Error].
pub type Result<T, E = Error> = ::core::result::Result<T, E>;

/// This type represents all possible errors that can occur in the library.
#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
  /// Caused by querying for a method that does not exist.
  #[error("verification method not found")]
  MethodNotFound,
  /// Caused by invalid or missing properties when constructing a [`CoreDocument`](crate::document::CoreDocument).
  #[error("invalid document property: {0}")]
  InvalidDocument(&'static str, #[source] Option<::identity_core::Error>),
  /// Caused by invalid or missing properties when constructing a [`Service`](crate::service::Service).
  #[error("invalid service property: {0}")]
  InvalidService(&'static str),
  /// Caused by an invalid or empty fragment.
  #[error("invalid or empty `id` fragment")]
  MissingIdFragment,
  /// Caused by attempting to add a verification method to a document, where a method or service with the same fragment
  /// already exists.
  #[error("unable to insert method: the id is already in use")]
  MethodInsertionError,
  /// Caused by attempting to attach or detach a relationship on an embedded method.
  #[error("unable to modify relationships on embedded methods, use insert or remove instead")]
  InvalidMethodEmbedded,
  /// Caused by attempting to insert a service whose id overlaps with a verification method or an already existing
  /// service.
  #[error("unable to insert service: the id is already in use")]
  InvalidServiceInsertion,
  /// Caused by an attempt to use a method's key material in an incompatible context.
  #[error("invalid key material")]
  InvalidKeyMaterial(#[source] identity_verification::Error),
  /// Caused by a failure to verify a JSON Web Signature.
  #[error("jws verification failed")]
  JwsVerificationError(#[source] identity_verification::jose::error::Error),
}

#[cfg(target_arch = "wasm32")]
impl_wasm_error_from!(Error);