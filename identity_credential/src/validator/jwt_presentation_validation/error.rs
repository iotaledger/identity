// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::fmt::Display;

use crate::validator::jwt_credential_validation::JwtValidationError;

#[cfg(target_arch = "wasm32")]
use product_common::bindings::wasm_error;
#[cfg(target_arch = "wasm32")]
use std::borrow::Cow;

/// Errors caused by a failure to validate a [`Presentation`](crate::presentation::Presentation).
#[derive(Debug)]
pub struct CompoundJwtPresentationValidationError {
  /// Errors that occurred during validation of the presentation.
  pub presentation_validation_errors: Vec<JwtValidationError>,
}

impl CompoundJwtPresentationValidationError {
  pub(crate) fn one_presentation_error(error: JwtValidationError) -> Self {
    Self {
      presentation_validation_errors: vec![error],
    }
  }
}

impl Display for CompoundJwtPresentationValidationError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let error_string_iter = self
      .presentation_validation_errors
      .iter()
      .map(|error| error.to_string());

    let detailed_information: String = itertools::intersperse(error_string_iter, "; ".to_string()).collect();
    write!(f, "[{detailed_information}]")
  }
}

impl Error for CompoundJwtPresentationValidationError {}

#[cfg(target_arch = "wasm32")]
impl From<CompoundJwtPresentationValidationError> for wasm_error::WasmError<'_> {
  fn from(error: CompoundJwtPresentationValidationError) -> Self {
    Self {
      name: Cow::Borrowed("CompoundJwtPresentationValidationError"),
      message: Cow::Owned(wasm_error::ErrorMessage(&error).to_string()),
    }
  }
}