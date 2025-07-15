// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen(typescript_custom_section)]
const I_SD_JWT_VC_STATUS: &str = r#"
interface SdJwtVcStatusListRef {
  uri: string;
  idx: number;
}

type SdJwtVcStatus = { status_list: SdJwtVcStatusListRef } | unknown;
"#;

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(js_name = "SdJwtVcStatus")]
  pub type WasmStatus;
}
