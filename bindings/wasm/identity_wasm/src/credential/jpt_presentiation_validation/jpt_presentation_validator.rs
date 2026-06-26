// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::common::ImportedDocumentLock;
use crate::credential::WasmDecodedJptPresentation;
use crate::credential::WasmFailFast;
use crate::credential::WasmJpt;
use crate::credential::WasmJptPresentationValidationOptions;
use crate::did::IToCoreDocument;
use crate::error::Result;
use crate::error::WasmResult;
use identity_iota::credential::JptPresentationValidator;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = JptPresentationValidator)]
pub struct WasmJptPresentationValidator;

#[wasm_bindgen(js_class = JptPresentationValidator)]
impl WasmJptPresentationValidator {
  /// Decodes and validates a Presented {@link Credential} issued as a JPT (JWP Presented Form). A
  /// {@link DecodedJptPresentation} is returned upon success.
  ///
  /// The following properties are validated according to `options`:
  /// - the holder's proof on the JWP,
  /// - the expiration date,
  /// - the issuance date,
  /// - the semantic structure.
  #[wasm_bindgen]
  pub fn validate(
    presentation_jpt: &WasmJpt,
    issuer: &IToCoreDocument,
    options: &WasmJptPresentationValidationOptions,
    fail_fast: WasmFailFast,
  ) -> Result<WasmDecodedJptPresentation> {
    let issuer_lock = ImportedDocumentLock::from(issuer);
    let issuer_guard = issuer_lock.try_read()?;
    JptPresentationValidator::validate(&presentation_jpt.0, &issuer_guard, &options.0, fail_fast.into())
      .wasm_result()
      .map(WasmDecodedJptPresentation)
  }
}
