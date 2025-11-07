// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use serde::Deserialize;
use serde::Serialize;

/// Controls validation behaviour when checking whether or not a credential has been revoked by its
/// [`credentialStatus`](https://www.w3.org/TR/vc-data-model/#status).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde_repr::Serialize_repr, serde_repr::Deserialize_repr)]
#[repr(u8)]
#[derive(Default)]
pub enum StatusCheck {
  /// Validate the status if supported, reject any unsupported
  /// [`credentialStatus`](https://www.w3.org/TR/vc-data-model/#status) types.
  ///
  /// Only `RevocationBitmap2022` is currently supported.
  ///
  /// This is the default.
  #[default]
  Strict = 0,
  /// Validate the status if supported, skip any unsupported
  /// [`credentialStatus`](https://www.w3.org/TR/vc-data-model/#status) types.
  SkipUnsupported = 1,
  /// Skip all status checks.
  SkipAll = 2,
}


/// Declares how credential subjects must relate to the presentation holder during validation.
///
/// See also the [Subject-Holder Relationship](https://www.w3.org/TR/vc-data-model/#subject-holder-relationships) section of the specification.
// Need to use serde_repr to make this work with duck typed interfaces in the Wasm bindings.
#[derive(Debug, Clone, Copy, serde_repr::Serialize_repr, serde_repr::Deserialize_repr)]
#[repr(u8)]
#[derive(Default)]
pub enum SubjectHolderRelationship {
  /// The holder must always match the subject on all credentials, regardless of their [`nonTransferable`](https://www.w3.org/TR/vc-data-model/#nontransferable-property) property.
  /// This is the variant returned by [Self::default](Self::default()) and the default used in
  /// [`crate::validator::JwtPresentationValidationOptions`].
  #[default]
  AlwaysSubject = 0,
  /// The holder must match the subject only for credentials where the [`nonTransferable`](https://www.w3.org/TR/vc-data-model/#nontransferable-property) property is `true`.
  SubjectOnNonTransferable = 1,
  /// Declares that the subject is not required to have any kind of relationship to the holder.
  Any = 2,
}


/// Declares when validation should return if an error occurs.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum FailFast {
  /// Return all errors that occur during validation.
  AllErrors,
  /// Return after the first error occurs.
  FirstError,
}
