// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen(typescript_custom_section)]
const I_SD_JWT_VC_CLAIMS: &str = r#"
interface ISdJwtVcClaims {
  iss?: string;
  vct: string;
  status: SdJwtVcStatus;
  nbf?: string;
  exp?: string;
  iat?: string;
  sub?: string;
}

type SdJwtVcClaims = ISdJwtVcClaims & SdJwtClaims;
"#;

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "SdJwtVcClaims")]
  pub type WasmSdJwtVcClaims;
}
