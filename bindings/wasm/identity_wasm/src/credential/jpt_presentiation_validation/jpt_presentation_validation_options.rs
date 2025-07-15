// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::credential::JptPresentationValidationOptions;
use wasm_bindgen::prelude::*;

use crate::error::Result;
use crate::error::WasmResult;

/// Options to declare validation criteria for a {@link Jpt} presentation.
#[derive(Debug, Default, Clone)]
#[wasm_bindgen(js_name = "JptPresentationValidationOptions", inspectable)]
pub struct WasmJptPresentationValidationOptions(pub(crate) JptPresentationValidationOptions);

impl_wasm_clone!(WasmJptPresentationValidationOptions, JptPresentationValidationOptions);
impl_wasm_json!(WasmJptPresentationValidationOptions, JptPresentationValidationOptions);

#[wasm_bindgen(js_class = JptPresentationValidationOptions)]
impl WasmJptPresentationValidationOptions {
  #[wasm_bindgen(constructor)]
  pub fn new(opts: Option<IJptPresentationValidationOptions>) -> Result<WasmJptPresentationValidationOptions> {
    if let Some(opts) = opts {
      opts
        .into_serde()
        .wasm_result()
        .map(WasmJptPresentationValidationOptions)
    } else {
      Ok(WasmJptPresentationValidationOptions::default())
    }
  }
}

impl From<JptPresentationValidationOptions> for WasmJptPresentationValidationOptions {
  fn from(value: JptPresentationValidationOptions) -> Self {
    WasmJptPresentationValidationOptions(value)
  }
}

impl From<WasmJptPresentationValidationOptions> for JptPresentationValidationOptions {
  fn from(value: WasmJptPresentationValidationOptions) -> Self {
    value.0
  }
}

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "IJptPresentationValidationOptions")]
  pub type IJptPresentationValidationOptions;
}

#[wasm_bindgen(typescript_custom_section)]
const I_JPT_PRESENTATION_VALIDATION_OPTIONS: &'static str = r#"
/** Holds options to create a new {@link JptPresentationValidationOptions}. */
interface IJptPresentationValidationOptions {
    /**
     * The nonce to be placed in the Presentation Protected Header.
     */
    readonly nonce?: string;

    /**
     * Options which affect the verification of the proof on the credential.
     */
    readonly verificationOptions?: JwpVerificationOptions;
}"#;
