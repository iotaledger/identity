// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::error::Result;
use crate::error::WasmResult;
use identity_iota::verification::jose::jwu;
use wasm_bindgen::prelude::*;

/// Encode the given bytes in url-safe base64.
#[wasm_bindgen(js_name = encodeB64)]
pub fn encode_b64(data: &[u8]) -> String {
  jwu::encode_b64(data)
}

/// Decode the given url-safe base64-encoded slice into its raw bytes.
#[wasm_bindgen(js_name = decodeB64)]
pub fn decode_b64(data: &[u8]) -> Result<Vec<u8>> {
  jwu::decode_b64(data).wasm_result()
}
