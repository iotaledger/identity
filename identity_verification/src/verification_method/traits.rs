// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::error::Error;
use crate::error::Result;
use crate::verification_method::VerificationMethod;

/// Represents all possible verification method URI types
///
/// see [W3C DID-core spec](https://www.w3.org/TR/did-core/#relative-did-urls)
pub enum MethodUriType {
  Absolute,
  Relative,
}

/// Used to return absolute or relative method URI.
///
/// This trait is used to determine whether absolute or relative method URIs
/// should be used to sign data.
///
/// [More Info](https://www.w3.org/TR/did-core/#relative-did-urls)
pub trait TryMethod {
  /// Flag that determines whether absolute or relative URI
  const TYPE: MethodUriType;

  /// Returns an absolute or relative method URI, if any, depending on the [`MethodUriType`].
  ///
  /// - [`MethodUriType::Absolute`] => "did:example:1234#method"
  /// - [`MethodUriType::Relative`] => "#method"
  fn method(method: &VerificationMethod) -> Option<String> {
    // Return None if there is no fragment on the method, even in the absolute case.
    let fragment: &str = method.id().fragment()?;

    match Self::TYPE {
      MethodUriType::Absolute => Some(method.id().to_string()),
      MethodUriType::Relative => Some(core::iter::once('#').chain(fragment.chars()).collect()),
    }
  }

  /// Returns String representation of absolute or relative method URI.
  ///
  /// # Errors
  ///
  /// Fails if an unsupported verification method is used.
  fn try_method(method: &VerificationMethod) -> Result<String> {
    Self::method(method).ok_or(Error::MissingIdFragment)
  }
}
