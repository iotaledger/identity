// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::error::Result;
use crate::error::WasmResult;
use identity_iota::credential::JwtPresentationOptions;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = JwtPresentationOptions)]
pub struct WasmJwtPresentationOptions(pub(crate) JwtPresentationOptions);

#[wasm_bindgen(js_class = JwtPresentationOptions)]
impl WasmJwtPresentationOptions {
  /// Creates a new {@link JwtPresentationOptions} from the given fields.
  ///
  /// Throws an error if any of the options are invalid.
  #[wasm_bindgen(constructor)]
  pub fn new(options: Option<IJwtPresentationOptions>) -> Result<WasmJwtPresentationOptions> {
    if let Some(options) = options {
      let options: JwtPresentationOptions = options.into_serde().wasm_result()?;
      Ok(WasmJwtPresentationOptions::from(options))
    } else {
      Ok(WasmJwtPresentationOptions::from(JwtPresentationOptions::default()))
    }
  }
}

impl_wasm_json!(WasmJwtPresentationOptions, JwtPresentationOptions);
impl_wasm_clone!(WasmJwtPresentationOptions, JwtPresentationOptions);

impl From<JwtPresentationOptions> for WasmJwtPresentationOptions {
  fn from(options: JwtPresentationOptions) -> Self {
    Self(options)
  }
}

impl From<WasmJwtPresentationOptions> for JwtPresentationOptions {
  fn from(options: WasmJwtPresentationOptions) -> Self {
    options.0
  }
}

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "IJwtPresentationOptions")]
  pub type IJwtPresentationOptions;
}

#[wasm_bindgen(typescript_custom_section)]
const I_JWT_PRESENTATION_OPTIONS: &'static str = r#"
/**  Options to be set in the JWT claims of a verifiable presentation. */
interface IJwtPresentationOptions {
    /**
     * Set the presentation's expiration date.
     * Default: `undefined`.
     **/
    readonly expirationDate?: Timestamp;
 
    /**
     * Set the presentation's issuance date.
     * Default: current datetime.
     */
    readonly issuanceDate?: Timestamp;

    /**
     * Sets the audience for presentation (`aud` property in JWT claims).
     * 
     * ## Note:
     * Value must be a valid URL.
     *
     * Default: `undefined`.
     */
    readonly audience?: string;

    /**
     * Custom claims that can be used to set additional claims on the resulting JWT.
     */
    readonly customClaims?: Record<string, any>;
}"#;
