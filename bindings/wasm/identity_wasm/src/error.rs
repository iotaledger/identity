// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::credential::CompoundJwtPresentationValidationError;
use identity_iota::resolver;
use identity_iota::storage::key_id_storage::KeyIdStorageError;
use identity_iota::storage::key_id_storage::KeyIdStorageErrorKind;
use identity_iota::storage::key_id_storage::KeyIdStorageResult;
use identity_iota::storage::key_storage::KeyStorageError;
use identity_iota::storage::key_storage::KeyStorageErrorKind;
use identity_iota::storage::key_storage::KeyStorageResult;
use iota_interaction_ts::AdapterError;
use product_common::Error as ProductCommonError;
use std::borrow::Cow;
use std::fmt::Debug;
use std::fmt::Display;
use std::result::Result as StdResult;
use tokio::sync::TryLockError;
use wasm_bindgen::JsValue;

/// Convenience wrapper for `Result<T, JsValue>`.
///
/// All exported errors must be converted to [`JsValue`] when using wasm_bindgen.
/// See: https://rustwasm.github.io/docs/wasm-bindgen/reference/types/result.html
pub type Result<T> = core::result::Result<T, JsValue>;

/// Convert an error into an idiomatic [js_sys::Error].
pub fn wasm_error<'a, E>(error: E) -> JsValue
where
  E: Into<WasmError<'a>>,
{
  let wasm_err: WasmError<'_> = error.into();
  JsValue::from(wasm_err)
}

/// Convenience trait to simplify `result.map_err(wasm_error)` to `result.wasm_result()`
pub trait WasmResult<T> {
  fn wasm_result(self) -> Result<T>;
}

impl<'a, T, E> WasmResult<T> for core::result::Result<T, E>
where
  E: Into<WasmError<'a>>,
{
  fn wasm_result(self) -> Result<T> {
    self.map_err(wasm_error)
  }
}

/// Convenience struct to convert internal errors to [js_sys::Error]. Uses [std::borrow::Cow]
/// internally to avoid unnecessary clones.
///
/// This is a workaround for orphan rules so we can implement [core::convert::From] on errors from
/// dependencies.
#[derive(Debug, Clone)]
pub struct WasmError<'a> {
  pub name: Cow<'a, str>,
  pub message: Cow<'a, str>,
}

impl<'a> WasmError<'a> {
  pub fn new(name: Cow<'a, str>, message: Cow<'a, str>) -> Self {
    Self { name, message }
  }
}

/// Convert [WasmError] into [js_sys::Error] for idiomatic error handling.
impl From<WasmError<'_>> for js_sys::Error {
  fn from(error: WasmError<'_>) -> Self {
    let js_error = js_sys::Error::new(&error.message);
    js_error.set_name(&error.name);
    js_error
  }
}

/// Convert [WasmError] into [wasm_bindgen::JsValue].
impl From<WasmError<'_>> for JsValue {
  fn from(error: WasmError<'_>) -> Self {
    JsValue::from(js_sys::Error::from(error))
  }
}

/// Implement WasmError for each type individually rather than a trait due to Rust's orphan rules.
/// Each type must implement `Into<&'static str> + Display`. The `Into<&'static str>` trait can be
/// derived using `strum::IntoStaticStr`.
#[macro_export]
macro_rules! impl_wasm_error_from {
  ( $($t:ty),* ) => {
  $(impl From<$t> for WasmError<'_> {
    fn from(error: $t) -> Self {
      Self {
        message: Cow::Owned(ErrorMessage(&error).to_string()),
        name: Cow::Borrowed(error.into()),
      }
    }
  })*
  }
}

impl_wasm_error_from!(
  identity_iota::core::Error,
  identity_iota::credential::Error,
  identity_iota::did::Error,
  identity_iota::document::Error,
  identity_iota::iota::Error,
  identity_iota::credential::JwtValidationError,
  identity_iota::credential::RevocationError,
  identity_iota::verification::Error,
  identity_iota::credential::DomainLinkageValidationError,
  identity_iota::sd_jwt_payload::Error,
  identity_iota::credential::KeyBindingJwtError,
  identity_iota::credential::status_list_2021::StatusListError,
  identity_iota::credential::status_list_2021::StatusList2021CredentialError,
  identity_iota::iota::rebased::Error,
  ProductCommonError
);

// Similar to `impl_wasm_error_from`, but uses the types name instead of requiring/calling Into &'static str
#[macro_export]
macro_rules! impl_wasm_error_from_with_struct_name {
  ( $($t:ty),* ) => {
  $(impl From<$t> for WasmError<'_> {
    fn from(error: $t) -> Self {
      Self {
        message: Cow::Owned(error.to_string()),
        name: Cow::Borrowed(stringify!($t)),
      }
    }
  })*
  }
}

impl_wasm_error_from_with_struct_name!(jsonprooftoken::errors::CustomError);

// identity_iota::iota now has some errors where the error message does not include the source error's error message.
// This is in compliance with the Rust error handling project group's recommendation:
// * An error type with a source error should either return that error via source or include that source's error message
//   in its own Display output, but never both. *
// See https://blog.rust-lang.org/inside-rust/2021/07/01/What-the-error-handling-project-group-is-working-towards.html#guidelines-for-implementing-displayfmt-and-errorsource.
//
// However in WasmError we want the display message of the entire error chain. We introduce a workaround here that let's
// us display the entire display chain for new variants that don't include the error message of the source error in its
// own display.

// the following function is inspired by https://www.lpalmieri.com/posts/error-handling-rust/#error-source
fn error_chain_fmt(e: &impl std::error::Error, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
  write!(f, "{e}. ")?;
  let mut current = e.source();
  while let Some(cause) = current {
    write!(f, "Caused by: {cause}. ")?;
    current = cause.source();
  }
  Ok(())
}

struct ErrorMessage<'a, E: std::error::Error>(&'a E);

impl<E: std::error::Error> Display for ErrorMessage<'_, E> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    error_chain_fmt(self.0, f)
  }
}

impl From<resolver::Error> for WasmError<'_> {
  fn from(error: resolver::Error) -> Self {
    Self {
      name: Cow::Owned(format!("ResolverError::{}", <&'static str>::from(error.error_cause()))),
      message: Cow::Owned(ErrorMessage(&error).to_string()),
    }
  }
}

impl From<serde_json::Error> for WasmError<'_> {
  fn from(error: serde_json::Error) -> Self {
    Self {
      name: Cow::Borrowed("serde_json::Error"), // the exact error code is embedded in the message
      message: Cow::Owned(error.to_string()),
    }
  }
}

impl From<anyhow::Error> for WasmError<'_> {
  fn from(value: anyhow::Error) -> Self {
    Self {
      name: Cow::Borrowed("Generic Error"),
      message: Cow::Owned(value.to_string()),
    }
  }
}

impl From<bcs::Error> for WasmError<'_> {
  fn from(value: bcs::Error) -> Self {
    Self {
      name: Cow::Borrowed("BCS Error"),
      message: Cow::Owned(value.to_string()),
    }
  }
}

impl From<iota_sdk::types::block::Error> for WasmError<'_> {
  fn from(error: iota_sdk::types::block::Error) -> Self {
    Self {
      name: Cow::Borrowed("iota_sdk::types::block::Error"),
      message: Cow::Owned(error.to_string()),
    }
  }
}

impl From<identity_iota::credential::CompoundCredentialValidationError> for WasmError<'_> {
  fn from(error: identity_iota::credential::CompoundCredentialValidationError) -> Self {
    Self {
      name: Cow::Borrowed("CompoundCredentialValidationError"),
      message: Cow::Owned(ErrorMessage(&error).to_string()),
    }
  }
}

impl From<identity_iota::core::SingleStructError<KeyStorageErrorKind>> for WasmError<'_> {
  fn from(error: identity_iota::core::SingleStructError<KeyStorageErrorKind>) -> Self {
    Self {
      name: Cow::Borrowed("KeyStorageError"),
      message: Cow::Owned(ErrorMessage(&error).to_string()),
    }
  }
}

impl From<identity_iota::core::SingleStructError<KeyIdStorageErrorKind>> for WasmError<'_> {
  fn from(error: identity_iota::core::SingleStructError<KeyIdStorageErrorKind>) -> Self {
    Self {
      name: Cow::Borrowed("KeyIdStorageError"),
      message: Cow::Owned(ErrorMessage(&error).to_string()),
    }
  }
}

impl From<identity_iota::storage::key_id_storage::MethodDigestConstructionError> for WasmError<'_> {
  fn from(error: identity_iota::storage::key_id_storage::MethodDigestConstructionError) -> Self {
    Self {
      name: Cow::Borrowed("MethodDigestConstructionError"),
      message: Cow::Owned(ErrorMessage(&error).to_string()),
    }
  }
}

impl From<identity_iota::storage::storage::JwkStorageDocumentError> for WasmError<'_> {
  fn from(error: identity_iota::storage::storage::JwkStorageDocumentError) -> Self {
    Self {
      name: Cow::Borrowed("JwkDocumentExtensionError"),
      message: Cow::Owned(ErrorMessage(&error).to_string()),
    }
  }
}

impl From<identity_iota::verification::jws::SignatureVerificationError> for WasmError<'_> {
  fn from(error: identity_iota::verification::jws::SignatureVerificationError) -> Self {
    Self {
      name: Cow::Borrowed("SignatureVerificationError"),
      message: Cow::Owned(ErrorMessage(&error).to_string()),
    }
  }
}

impl From<identity_iota::verification::jose::error::Error> for WasmError<'_> {
  fn from(error: identity_iota::verification::jose::error::Error) -> Self {
    Self {
      name: Cow::Borrowed("JoseError"),
      message: Cow::Owned(ErrorMessage(&error).to_string()),
    }
  }
}

impl From<CompoundJwtPresentationValidationError> for WasmError<'_> {
  fn from(error: CompoundJwtPresentationValidationError) -> Self {
    Self {
      name: Cow::Borrowed("CompoundJwtPresentationValidationError"),
      message: Cow::Owned(ErrorMessage(&error).to_string()),
    }
  }
}

impl From<TryLockError> for WasmError<'_> {
  fn from(error: TryLockError) -> Self {
    Self {
      name: Cow::Borrowed("TryLockError"),
      message: Cow::Owned(ErrorMessage(&error).to_string()),
    }
  }
}

impl From<serde_wasm_bindgen::Error> for WasmError<'_> {
  fn from(error: serde_wasm_bindgen::Error) -> Self {
    Self {
      name: Cow::Borrowed("serde_wasm_bindgen::Error"),
      message: Cow::Owned(ErrorMessage(&error).to_string()),
    }
  }
}

impl From<secret_storage::Error> for WasmError<'_> {
  fn from(error: secret_storage::Error) -> Self {
    Self {
      name: Cow::Borrowed("secret_storage::Error"),
      message: Cow::Owned(ErrorMessage(&error).to_string()),
    }
  }
}

impl From<identity_iota::credential::sd_jwt_vc::Error> for WasmError<'_> {
  fn from(error: identity_iota::credential::sd_jwt_vc::Error) -> Self {
    Self {
      name: Cow::Borrowed("SdJwtVcError"),
      message: Cow::Owned(ErrorMessage(&error).to_string()),
    }
  }
}

impl From<AdapterError> for WasmError<'_> {
  fn from(error: AdapterError) -> Self {
    Self {
      name: Cow::Borrowed("TsSdkError"),
      message: Cow::Owned(ErrorMessage(&error).to_string()),
    }
  }
}

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

/// Consumes the struct and returns a Result<_, String>, leaving an `Ok` value untouched.
pub(crate) fn stringify_js_error<T>(result: Result<T>) -> StdResult<T, String> {
  result.map_err(|js_value| {
    let error_string: String = match wasm_bindgen::JsCast::dyn_into::<js_sys::Error>(js_value) {
      Ok(js_err) => ToString::to_string(&js_err.to_string()),
      Err(js_val) => {
        // Fall back to debug formatting if this is not a proper JS Error instance.
        format!("{js_val:?}")
      }
    };
    error_string
  })
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
