// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::credential::FailFast;
use identity_iota::credential::StatusCheck;
use identity_iota::credential::SubjectHolderRelationship;
use serde_repr::Deserialize_repr;
use serde_repr::Serialize_repr;
use wasm_bindgen::prelude::*;

/// Controls validation behaviour when checking whether or not a credential has been revoked by its
/// [`credentialStatus`](https://www.w3.org/TR/vc-data-model/#status).
#[wasm_bindgen(js_name = StatusCheck)]
#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum WasmStatusCheck {
  /// Validate the status if supported, reject any unsupported
  /// [`credentialStatus`](https://www.w3.org/TR/vc-data-model/#status) types.
  ///
  /// Only `RevocationBitmap2022` is currently supported.
  ///
  /// This is the default.
  Strict = 0,
  /// Validate the status if supported, skip any unsupported
  /// [`credentialStatus`](https://www.w3.org/TR/vc-data-model/#status) types.
  SkipUnsupported = 1,
  /// Skip all status checks.
  SkipAll = 2,
}

impl From<WasmStatusCheck> for StatusCheck {
  fn from(status_check: WasmStatusCheck) -> Self {
    match status_check {
      WasmStatusCheck::Strict => Self::Strict,
      WasmStatusCheck::SkipUnsupported => Self::SkipUnsupported,
      WasmStatusCheck::SkipAll => Self::SkipAll,
    }
  }
}

/// Declares how credential subjects must relate to the presentation holder.
///
/// See also the [Subject-Holder Relationship](https://www.w3.org/TR/vc-data-model/#subject-holder-relationships) section of the specification.
#[wasm_bindgen(js_name = SubjectHolderRelationship)]
#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum WasmSubjectHolderRelationship {
  /// The holder must always match the subject on all credentials, regardless of their [`nonTransferable`](https://www.w3.org/TR/vc-data-model/#nontransferable-property) property.
  /// This variant is the default.
  AlwaysSubject = 0,
  /// The holder must match the subject only for credentials where the [`nonTransferable`](https://www.w3.org/TR/vc-data-model/#nontransferable-property) property is `true`.
  SubjectOnNonTransferable = 1,
  /// The holder is not required to have any kind of relationship to any credential subject.
  Any = 2,
}

impl From<WasmSubjectHolderRelationship> for SubjectHolderRelationship {
  fn from(subject_holder_relationship: WasmSubjectHolderRelationship) -> Self {
    match subject_holder_relationship {
      WasmSubjectHolderRelationship::AlwaysSubject => Self::AlwaysSubject,
      WasmSubjectHolderRelationship::SubjectOnNonTransferable => Self::SubjectOnNonTransferable,
      WasmSubjectHolderRelationship::Any => Self::Any,
    }
  }
}

/// Declares when validation should return if an error occurs.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[wasm_bindgen(js_name = FailFast)]
pub enum WasmFailFast {
  /// Return all errors that occur during validation.
  AllErrors = 0,
  /// Return after the first error occurs.
  FirstError = 1,
}

impl From<WasmFailFast> for FailFast {
  fn from(fail_fast: WasmFailFast) -> Self {
    match fail_fast {
      WasmFailFast::AllErrors => Self::AllErrors,
      WasmFailFast::FirstError => Self::FirstError,
    }
  }
}
