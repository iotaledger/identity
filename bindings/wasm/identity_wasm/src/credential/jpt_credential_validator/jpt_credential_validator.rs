// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::common::ImportedDocumentLock;
use crate::credential::WasmDecodedJptCredential;
use crate::credential::WasmFailFast;
use crate::credential::WasmJpt;
use crate::credential::WasmJptCredentialValidationOptions;
use crate::did::IToCoreDocument;
use crate::error::Result;
use crate::error::WasmResult;
use identity_iota::credential::JptCredentialValidator;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = JptCredentialValidator)]
pub struct WasmJptCredentialValidator;

#[wasm_bindgen(js_class = JptCredentialValidator)]
impl WasmJptCredentialValidator {
  #[wasm_bindgen]
  pub fn validate(
    credential_jpt: &WasmJpt,
    issuer: &IToCoreDocument,
    options: &WasmJptCredentialValidationOptions,
    fail_fast: WasmFailFast,
  ) -> Result<WasmDecodedJptCredential> {
    let issuer_lock = ImportedDocumentLock::from(issuer);
    let issuer_guard = issuer_lock.try_read()?;
    JptCredentialValidator::validate(&credential_jpt.0, &issuer_guard, &options.0, fail_fast.into())
      .wasm_result()
      .map(WasmDecodedJptCredential)
  }
}
