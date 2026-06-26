// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "JptClaims")]
  pub type WasmJptClaims;
}

#[wasm_bindgen(typescript_custom_section)]
const I_JPT_CLAIMS: &'static str = r#"
/** JPT claims */

interface JptClaims {
  /** Who issued the JWP*/
  readonly iss?: string;
  /** Subject of the JPT. */
  readonly sub?: string;
  /** Expiration time. */
  readonly exp?: number;
  /** Issuance date. */
  readonly iat?: number;
  /** Time before which the JPT MUST NOT be accepted */
  readonly nbf?: number;
  /** Unique ID for the JPT. */
  readonly jti?: string;
  /** Custom claims. */
  readonly [properties: string]: any;
}"#;
