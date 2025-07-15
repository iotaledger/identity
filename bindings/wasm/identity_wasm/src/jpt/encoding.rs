// Copyright 2020-2025 IOTA Stiftung, Fondazione LINKS
// SPDX-License-Identifier: Apache-2.0

use jsonprooftoken::encoding::SerializationType;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = SerializationType)]
pub enum WasmSerializationType {
  COMPACT = 0,
  JSON = 1,
  CBOR = 2,
}

impl From<WasmSerializationType> for SerializationType {
  fn from(value: WasmSerializationType) -> Self {
    match value {
      WasmSerializationType::COMPACT => SerializationType::COMPACT,
      WasmSerializationType::JSON => SerializationType::JSON,
      WasmSerializationType::CBOR => SerializationType::CBOR,
    }
  }
}

impl From<SerializationType> for WasmSerializationType {
  fn from(value: SerializationType) -> Self {
    match value {
      SerializationType::COMPACT => WasmSerializationType::COMPACT,
      SerializationType::JSON => WasmSerializationType::JSON,
      SerializationType::CBOR => WasmSerializationType::CBOR,
    }
  }
}
