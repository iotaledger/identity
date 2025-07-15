// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::error::Result;
use crate::error::WasmResult;
use wasm_bindgen::prelude::*;

use identity_iota::credential::JwtCredentialValidationOptions;

/// Options to declare validation criteria when validating credentials.
#[wasm_bindgen(js_name = JwtCredentialValidationOptions)]
pub struct WasmJwtCredentialValidationOptions(pub(crate) JwtCredentialValidationOptions);

#[wasm_bindgen(js_class = JwtCredentialValidationOptions)]
impl WasmJwtCredentialValidationOptions {
  #[wasm_bindgen(constructor)]
  pub fn new(options: Option<IJwtCredentialValidationOptions>) -> Result<WasmJwtCredentialValidationOptions> {
    if let Some(opts) = options {
      let options: JwtCredentialValidationOptions = opts.into_serde().wasm_result()?;
      Ok(WasmJwtCredentialValidationOptions::from(options))
    } else {
      Ok(WasmJwtCredentialValidationOptions::from(
        JwtCredentialValidationOptions::default(),
      ))
    }
  }
}

impl_wasm_json!(WasmJwtCredentialValidationOptions, JwtCredentialValidationOptions);
impl_wasm_clone!(WasmJwtCredentialValidationOptions, JwtCredentialValidationOptions);

impl From<JwtCredentialValidationOptions> for WasmJwtCredentialValidationOptions {
  fn from(options: JwtCredentialValidationOptions) -> Self {
    Self(options)
  }
}

impl From<WasmJwtCredentialValidationOptions> for JwtCredentialValidationOptions {
  fn from(options: WasmJwtCredentialValidationOptions) -> Self {
    options.0
  }
}

// Interface to allow creating {@link JwtCredentialValidationOptions} easily.
#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "IJwtCredentialValidationOptions")]
  pub type IJwtCredentialValidationOptions;
}

#[wasm_bindgen(typescript_custom_section)]
const I_JWT_CREDENTIAL_VALIDATION_OPTIONS: &'static str = r#"
/** Holds options to create a new {@link JwtCredentialValidationOptions}. */
interface IJwtCredentialValidationOptions {
    /** Declare that the credential is **not** considered valid if it expires before this {@link Timestamp}.
     * Uses the current datetime during validation if not set. */
    readonly earliestExpiryDate?: Timestamp;

    /** Declare that the credential is **not** considered valid if it was issued later than this {@link Timestamp}.
     * Uses the current datetime during validation if not set. */
    readonly latestIssuanceDate?: Timestamp;

    /** Validation behaviour for `credentialStatus`.
     *
     * Default: `StatusCheck.Strict`. */
    readonly status?: StatusCheck;

    /** Declares how credential subjects must relate to the presentation holder during validation.
    *
    * <https://www.w3.org/TR/vc-data-model/#subject-holder-relationships> */
    readonly subjectHolderRelationship?: [string, SubjectHolderRelationship];

    /** Options which affect the verification of the signature on the credential. */
    readonly verifierOptions?: JwsVerificationOptions;
}"#;
