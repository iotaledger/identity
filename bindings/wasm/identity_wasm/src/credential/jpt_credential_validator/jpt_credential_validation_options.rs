// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::credential::JptCredentialValidationOptions;
use wasm_bindgen::prelude::*;

use product_common::bindings::wasm_error::Result;
use product_common::bindings::wasm_error::WasmResult;
use product_common::impl_wasm_clone;
use product_common::impl_wasm_json;

/// Options to declare validation criteria for {@link Jpt}.
#[derive(Debug, Default, Clone)]
#[wasm_bindgen(js_name = "JptCredentialValidationOptions", inspectable)]
pub struct WasmJptCredentialValidationOptions(pub(crate) JptCredentialValidationOptions);

impl_wasm_clone!(WasmJptCredentialValidationOptions, JptCredentialValidationOptions);
impl_wasm_json!(WasmJptCredentialValidationOptions, JptCredentialValidationOptions);

#[wasm_bindgen(js_class = JptCredentialValidationOptions)]
impl WasmJptCredentialValidationOptions {
  /// Creates a new default instance.
  #[wasm_bindgen(constructor)]
  pub fn new(opts: Option<IJptCredentialValidationOptions>) -> Result<WasmJptCredentialValidationOptions> {
    if let Some(opts) = opts {
      opts.into_serde().wasm_result().map(WasmJptCredentialValidationOptions)
    } else {
      Ok(WasmJptCredentialValidationOptions::default())
    }
  }
}

impl From<JptCredentialValidationOptions> for WasmJptCredentialValidationOptions {
  fn from(value: JptCredentialValidationOptions) -> Self {
    WasmJptCredentialValidationOptions(value)
  }
}

impl From<WasmJptCredentialValidationOptions> for JptCredentialValidationOptions {
  fn from(value: WasmJptCredentialValidationOptions) -> Self {
    value.0
  }
}

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "IJptCredentialValidationOptions")]
  pub type IJptCredentialValidationOptions;
}

#[wasm_bindgen(typescript_custom_section)]
const I_JPT_CREDENTIAL_VALIDATION_OPTIONS: &'static str = r#"
/** Holds options to create a new {@link JptCredentialValidationOptions}. */
interface IJptCredentialValidationOptions {
    /**
     * Declare that the credential is **not** considered valid if it expires before this {@link Timestamp}.
     * Uses the current datetime during validation if not set. 
     */
    readonly earliestExpiryDate?: Timestamp;

    /**
     * Declare that the credential is **not** considered valid if it was issued later than this {@link Timestamp}.
     * Uses the current datetime during validation if not set. 
     */
    readonly latestIssuanceDate?: Timestamp;

    /**
     * Validation behaviour for [`credentialStatus`](https://www.w3.org/TR/vc-data-model/#status).
     */
    readonly status?: StatusCheck;

    /** Declares how credential subjects must relate to the presentation holder during validation.
     *
     * <https://www.w3.org/TR/vc-data-model/#subject-holder-relationships>
     */
    readonly subjectHolderRelationship?: [string, SubjectHolderRelationship];

    /**
     * Options which affect the verification of the proof on the credential.
     */
    readonly verificationOptions?: JwpVerificationOptions;
}"#;
