// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::error::Result;
use crate::error::WasmResult;
use identity_iota::credential::KeyBindingJWTValidationOptions;
use wasm_bindgen::prelude::*;

/// Options to declare validation criteria when validating credentials.
#[wasm_bindgen(js_name = KeyBindingJWTValidationOptions)]
pub struct WasmKeyBindingJWTValidationOptions(pub(crate) KeyBindingJWTValidationOptions);

#[wasm_bindgen(js_class = KeyBindingJWTValidationOptions)]
impl WasmKeyBindingJWTValidationOptions {
  #[wasm_bindgen(constructor)]
  pub fn new(options: Option<IKeyBindingJWTValidationOptions>) -> Result<WasmKeyBindingJWTValidationOptions> {
    if let Some(opts) = options {
      let options: KeyBindingJWTValidationOptions = opts.into_serde().wasm_result()?;
      Ok(WasmKeyBindingJWTValidationOptions::from(options))
    } else {
      Ok(WasmKeyBindingJWTValidationOptions::from(
        KeyBindingJWTValidationOptions::default(),
      ))
    }
  }
}

impl_wasm_json!(WasmKeyBindingJWTValidationOptions, KeyBindingJWTValidationOptions);
impl_wasm_clone!(WasmKeyBindingJWTValidationOptions, KeyBindingJWTValidationOptions);

impl From<KeyBindingJWTValidationOptions> for WasmKeyBindingJWTValidationOptions {
  fn from(options: KeyBindingJWTValidationOptions) -> Self {
    Self(options)
  }
}

impl From<WasmKeyBindingJWTValidationOptions> for KeyBindingJWTValidationOptions {
  fn from(options: WasmKeyBindingJWTValidationOptions) -> Self {
    options.0
  }
}

// Interface to allow creating `KeyBindingJWTValidationOptions` easily.
#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "IKeyBindingJWTValidationOptions")]
  pub type IKeyBindingJWTValidationOptions;
}

#[wasm_bindgen(typescript_custom_section)]
const I_KEY_BINDING_JWT_VALIDATION_OPTIONS: &'static str = r#"
/** Holds options to create a new `KeyBindingJWTValidationOptions`. */
interface IKeyBindingJWTValidationOptions {
    /**
     * Validates the nonce value of the KB-JWT claims.
     */
    readonly nonce?: string;

    /**
     * Validates the `aud` properties in the KB-JWT claims.
     */
    readonly aud?: string;

    /**
     * Options which affect the verification of the signature on the KB-JWT.
     */
    readonly jwsOptions: JwsVerificationOptions;

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
