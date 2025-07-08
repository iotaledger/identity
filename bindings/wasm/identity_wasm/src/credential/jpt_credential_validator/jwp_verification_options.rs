// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use product_common::bindings::wasm_error::Result;
use product_common::bindings::wasm_error::WasmResult;
use product_common::impl_wasm_clone;
use product_common::impl_wasm_json;
use identity_iota::document::verifiable::JwpVerificationOptions;
use wasm_bindgen::prelude::*;

/// Holds additional options for verifying a JWP
#[wasm_bindgen(js_name = JwpVerificationOptions, inspectable)]
#[derive(Clone, Debug, Default)]
pub struct WasmJwpVerificationOptions(pub(crate) JwpVerificationOptions);

impl_wasm_clone!(WasmJwpVerificationOptions, JwpVerificationOptions);
impl_wasm_json!(WasmJwpVerificationOptions, JwpVerificationOptions);

#[wasm_bindgen(js_class = JwpVerificationOptions)]
impl WasmJwpVerificationOptions {
  pub fn new(opts: Option<IJwpVerificationOptions>) -> Result<WasmJwpVerificationOptions> {
    if let Some(opts) = opts {
      opts.into_serde().wasm_result().map(WasmJwpVerificationOptions)
    } else {
      Ok(WasmJwpVerificationOptions::default())
    }
  }
}

// Interface to allow creating {@link JwpVerificationOptions} easily.
#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "IJwpVerificationOptions")]
  pub type IJwpVerificationOptions;
}

#[wasm_bindgen(typescript_custom_section)]
const I_JWP_VERIFICATION_OPTIONS: &'static str = r#"
/** Holds options to create a new {@link JwpVerificationOptions}. */
interface IJwpVerificationOptions {
    /**
     * Verify the signing verification method relation matches this.
     */
    readonly methodScope?: MethodScope;

    /**
     * The DID URL of the method, whose JWK should be used to verify the JWP.
     * If unset, the `kid` of the JWP is used as the DID URL.
     */
    readonly methodId?: DIDUrl;
}"#;
