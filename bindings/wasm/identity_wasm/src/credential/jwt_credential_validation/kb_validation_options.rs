// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::error::Result;
use crate::error::WasmResult;
use identity_iota::credential::KeyBindingJwtValidationOptions;
use wasm_bindgen::prelude::*;

/// Options to declare validation criteria when validating credentials.
#[wasm_bindgen(js_name = KeyBindingJwtValidationOptions)]
pub struct WasmKeyBindingJwtValidationOptions(pub(crate) KeyBindingJwtValidationOptions);

#[wasm_bindgen(js_class = KeyBindingJwtValidationOptions)]
impl WasmKeyBindingJwtValidationOptions {
  #[wasm_bindgen(constructor)]
  pub fn new(options: Option<IKeyBindingJwtValidationOptions>) -> Result<WasmKeyBindingJwtValidationOptions> {
    if let Some(opts) = options {
      let options: KeyBindingJwtValidationOptions = opts.into_serde().wasm_result()?;
      Ok(WasmKeyBindingJwtValidationOptions::from(options))
    } else {
      Ok(WasmKeyBindingJwtValidationOptions::from(
        KeyBindingJwtValidationOptions::default(),
      ))
    }
  }
}

impl_wasm_json!(WasmKeyBindingJwtValidationOptions, KeyBindingJwtValidationOptions);
impl_wasm_clone!(WasmKeyBindingJwtValidationOptions, KeyBindingJwtValidationOptions);

impl From<KeyBindingJwtValidationOptions> for WasmKeyBindingJwtValidationOptions {
  fn from(options: KeyBindingJwtValidationOptions) -> Self {
    Self(options)
  }
}

impl From<WasmKeyBindingJwtValidationOptions> for KeyBindingJwtValidationOptions {
  fn from(options: WasmKeyBindingJwtValidationOptions) -> Self {
    options.0
  }
}

// Interface to allow creating `KeyBindingJwtValidationOptions` easily.
#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "IKeyBindingJwtValidationOptions")]
  pub type IKeyBindingJwtValidationOptions;
}

#[wasm_bindgen(typescript_custom_section)]
const I_KEY_BINDING_JWT_VALIDATION_OPTIONS: &'static str = r#"
/** Holds options to create a new `KeyBindingJwtValidationOptions`. */
interface IKeyBindingJwtValidationOptions {
    /**
     * Validates the nonce value of the KB-JWT claims.
     */
    readonly nonce?: string;

    /**
     * Validates the `aud` properties in the KB-JWT claims.
     */
    readonly aud?: string;

    /**
     * Declares that the KB-JWT is considered invalid if the `iat` value in the claims
     * is earlier than this timestamp.
     */
    readonly earliestIssuanceDate?: Timestamp;

    /**
     * Declares that the KB-JWT is considered invalid if the `iat` value in the claims is
     * later than this timestamp.
     *
     * Uses the current timestamp during validation if not set.
     */
    readonly latestIssuanceDate?: Timestamp;

}"#;
