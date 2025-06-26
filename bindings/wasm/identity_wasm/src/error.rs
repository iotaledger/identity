// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use product_common::bindings::wasm_error::{Result, stringify_js_error};
use identity_iota::storage::key_id_storage::KeyIdStorageError;
use identity_iota::storage::key_id_storage::KeyIdStorageErrorKind;
use identity_iota::storage::key_id_storage::KeyIdStorageResult;
use identity_iota::storage::key_storage::KeyStorageError;
use identity_iota::storage::key_storage::KeyStorageErrorKind;
use identity_iota::storage::key_storage::KeyStorageResult;
use std::result::Result as StdResult;
use wasm_bindgen::JsValue;

/// Convenience struct to convert Result<JsValue, JsValue> to errors in the Rust library.
pub struct JsValueResult(pub(crate) Result<JsValue>);

impl JsValueResult {
  /// Consumes the struct and returns a Result<_, KeyStorageError>, leaving an `Ok` value untouched.
  pub fn to_key_storage_error(self) -> KeyStorageResult<JsValue> {
    self
      .stringify_error()
      .map_err(|err| KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_source(err))
  }

  pub fn to_key_id_storage_error(self) -> KeyIdStorageResult<JsValue> {
    self
      .stringify_error()
      .map_err(|err| KeyIdStorageError::new(KeyIdStorageErrorKind::Unspecified).with_source(err))
  }

  // Consumes the struct and returns a Result<_, String>, leaving an `Ok` value untouched.
  pub(crate) fn stringify_error(self) -> StdResult<JsValue, String> {
    stringify_js_error(self.0)
  }

  /// Consumes the struct and returns a Result<_, identity_iota::iota::Error>, leaving an `Ok` value untouched.
  pub fn to_iota_core_error(self) -> StdResult<JsValue, identity_iota::iota::Error> {
    self.stringify_error().map_err(identity_iota::iota::Error::JsError)
  }

  pub fn to_iota_client_error(self) -> StdResult<JsValue, identity_iota::iota::rebased::Error> {
    self
      .stringify_error()
      .map_err(|e| identity_iota::iota::rebased::Error::FfiError(e.to_string()))
  }
}

impl From<Result<JsValue>> for JsValueResult {
  fn from(result: Result<JsValue>) -> Self {
    JsValueResult(result)
  }
}

impl<T: for<'a> serde::Deserialize<'a>> From<JsValueResult> for KeyStorageResult<T> {
  fn from(result: JsValueResult) -> Self {
    result.to_key_storage_error().and_then(|js_value| {
      js_value
        .into_serde()
        .map_err(|e| KeyStorageError::new(KeyStorageErrorKind::SerializationError).with_source(e))
    })
  }
}

impl<T: for<'a> serde::Deserialize<'a>> From<JsValueResult> for KeyIdStorageResult<T> {
  fn from(result: JsValueResult) -> Self {
    result.to_key_id_storage_error().and_then(|js_value| {
      js_value
        .into_serde()
        .map_err(|e| KeyIdStorageError::new(KeyIdStorageErrorKind::SerializationError).with_source(e))
    })
  }
}

impl<T: for<'a> serde::Deserialize<'a>> From<JsValueResult> for StdResult<T, identity_iota::iota::rebased::Error> {
  fn from(result: JsValueResult) -> Self {
    result.to_iota_client_error().and_then(|js_value| {
      js_value
        .into_serde()
        .map_err(|e| identity_iota::iota::rebased::Error::FfiError(e.to_string()))
    })
  }
}
