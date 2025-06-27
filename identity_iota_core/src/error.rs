// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[cfg(target_arch = "wasm32")]
use product_common::impl_wasm_error_from;

/// Alias for a `Result` with the error type [`Error`].
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// This type represents errors that can occur when constructing credentials and presentations or their serializations.
#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
  /// Caused by a failure to serialize or deserialize.
  #[error("serialization error: {0}")]
  SerializationError(&'static str, #[source] Option<identity_core::Error>),
  /// Caused by an invalid DID.
  #[error("invalid did")]
  DIDSyntaxError(#[source] identity_did::Error),
  /// Caused by an invalid DID document.
  #[error("invalid document")]
  InvalidDoc(#[source] identity_document::Error),
  /// Caused by a client failure during resolution.
  #[error("DID resolution failed; {0}")]
  DIDResolutionError(String),
  /// Caused by an invalid network name.
  #[error("\"{0}\" is not a valid network name in the context of the `iota` did method")]
  InvalidNetworkName(String),
  /// Caused by a mismatch of the DID's network and the network the client is connected with.
  #[error("unable to resolve a `{expected}` DID on network `{actual}`")]
  NetworkMismatch {
    /// The network of the DID.
    expected: String,
    /// The network the client is connected with.
    actual: String,
  },
  /// Caused by an attempt to read state metadata that does not adhere to the IOTA DID method specification.
  #[error("invalid state metadata {0}")]
  InvalidStateMetadata(&'static str),
  #[cfg(feature = "revocation-bitmap")]
  /// Caused by a failure during (un)revocation of credentials.
  #[error("credential revocation error")]
  RevocationError(#[source] identity_credential::revocation::RevocationError),
  /// Caused by an error when constructing an output id.
  #[error("conversion to an OutputId failed: {0}")]
  OutputIdConversionError(String),
  #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
  /// Caused by an error in the Wasm bindings.
  #[error("JavaScript function threw an exception: {0}")]
  JsError(String),
  /// Caused by an error during JSON Web Signature verification.
  #[error("jws signature verification failed")]
  JwsVerificationError(#[source] identity_document::Error),
}

#[cfg(target_arch = "wasm32")]
impl_wasm_error_from!(Error);