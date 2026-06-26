// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::error::Result;
use crate::error::WasmResult;
use identity_iota::credential::JwtPresentationValidationOptions;
use wasm_bindgen::prelude::*;

/// Options to declare validation criteria when validating presentation.
#[wasm_bindgen(js_name = JwtPresentationValidationOptions)]
pub struct WasmJwtPresentationValidationOptions(pub(crate) JwtPresentationValidationOptions);

#[wasm_bindgen(js_class = JwtPresentationValidationOptions)]
impl WasmJwtPresentationValidationOptions {
  /// Creates a new {@link JwtPresentationValidationOptions} from the given fields.
  ///
  /// Throws an error if any of the options are invalid.
  #[wasm_bindgen(constructor)]
  pub fn new(options: Option<IJwtPresentationValidationOptions>) -> Result<WasmJwtPresentationValidationOptions> {
    if let Some(opts) = options {
      let options: JwtPresentationValidationOptions = opts.into_serde().wasm_result()?;
      Ok(WasmJwtPresentationValidationOptions::from(options))
    } else {
      Ok(WasmJwtPresentationValidationOptions::from(
        JwtPresentationValidationOptions::default(),
      ))
    }
  }
}

impl_wasm_json!(WasmJwtPresentationValidationOptions, JwtPresentationValidationOptions);
impl_wasm_clone!(WasmJwtPresentationValidationOptions, JwtPresentationValidationOptions);

impl From<JwtPresentationValidationOptions> for WasmJwtPresentationValidationOptions {
  fn from(options: JwtPresentationValidationOptions) -> Self {
    Self(options)
  }
}

impl From<WasmJwtPresentationValidationOptions> for JwtPresentationValidationOptions {
  fn from(options: WasmJwtPresentationValidationOptions) -> Self {
    options.0
  }
}

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "IJwtPresentationValidationOptions")]
  pub type IJwtPresentationValidationOptions;
}

#[wasm_bindgen(typescript_custom_section)]
const I_JWT_PRESENTATION_VALIDATION_OPTIONS: &'static str = r#"
/** Holds options to create a new {@link JwtPresentationValidationOptions}. */
interface IJwtPresentationValidationOptions {
    /** 
     * Options which affect the verification of the signature on the presentation. 
     */
    readonly presentationVerifierOptions?: JwsVerificationOptions;

    /**
     * Declare that the presentation is **not** considered valid if it expires before this {@link Timestamp}.
     * Uses the current datetime during validation if not set. 
     */
    readonly earliestExpiryDate?: Timestamp;

    /**
     * Declare that the presentation is **not** considered valid if it was issued later than this {@link Timestamp}.
     * Uses the current datetime during validation if not set. 
     */
    readonly latestIssuanceDate?: Timestamp;
}"#;
