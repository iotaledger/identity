// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::common::ArrayString;
use crate::common::RecordStringAny;
use crate::error::Result;
use crate::error::WasmResult;
use identity_iota::sd_jwt_payload::SdObjectDecoder;
use serde_json::Map;
use serde_json::Value;
use wasm_bindgen::prelude::*;

/// Substitutes digests in an SD-JWT object by their corresponding plaintext values provided by disclosures.
#[wasm_bindgen(js_name = SdObjectDecoder, inspectable)]
pub struct WasmSdObjectDecoder(pub(crate) SdObjectDecoder);

#[wasm_bindgen(js_class = SdObjectDecoder)]
#[allow(clippy::new_without_default)]
impl WasmSdObjectDecoder {
  /// Creates a new `SdObjectDecoder` with `sha-256` hasher.
  #[wasm_bindgen(constructor)]
  pub fn new() -> WasmSdObjectDecoder {
    Self(SdObjectDecoder::new_with_sha256())
  }

  /// Decodes an SD-JWT `object` containing by Substituting the digests with their corresponding
  /// plaintext values provided by `disclosures`.
  ///
  /// ## Notes
  /// * Claims like `exp` or `iat` are not validated in the process of decoding.
  /// * `_sd_alg` property will be removed if present.
  #[wasm_bindgen]
  pub fn decode(&self, object: RecordStringAny, disclosures: ArrayString) -> Result<RecordStringAny> {
    let object: Map<String, Value> = object.into_serde().wasm_result()?;
    let disclosures: Vec<String> = disclosures.into_serde().wasm_result()?;
    let decoded = self.0.decode(&object, &disclosures).wasm_result()?;
    Ok(
      JsValue::from_serde(&decoded)
        .wasm_result()?
        .unchecked_into::<RecordStringAny>(),
    )
  }
}
