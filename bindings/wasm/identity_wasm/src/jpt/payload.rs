// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::error::Result;
use crate::error::WasmError;
use crate::error::WasmResult;
use jsonprooftoken::jpt::payloads::PayloadType;
use jsonprooftoken::jpt::payloads::Payloads;
use serde_json::Value;
use std::borrow::Cow;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;

#[wasm_bindgen(js_name = PayloadType)]
#[derive(Clone, Copy, Debug)]
pub enum WasmPayloadType {
  Disclosed = 0,
  Undisclosed = 1,
  ProofMethods = 2,
}

impl From<WasmPayloadType> for PayloadType {
  fn from(value: WasmPayloadType) -> PayloadType {
    match value {
      WasmPayloadType::Disclosed => PayloadType::Disclosed,
      WasmPayloadType::ProofMethods => PayloadType::ProofMethods,
      WasmPayloadType::Undisclosed => PayloadType::Undisclosed,
    }
  }
}

impl From<PayloadType> for WasmPayloadType {
  fn from(value: PayloadType) -> WasmPayloadType {
    match value {
      PayloadType::Disclosed => WasmPayloadType::Disclosed,
      PayloadType::ProofMethods => WasmPayloadType::ProofMethods,
      PayloadType::Undisclosed => WasmPayloadType::Undisclosed,
    }
  }
}

#[wasm_bindgen(js_name = PayloadEntry)]
pub struct WasmPayloadEntry(JsValue, pub WasmPayloadType);

#[wasm_bindgen(js_class = PayloadEntry)]
impl WasmPayloadEntry {
  #[wasm_bindgen(setter)]
  pub fn set_value(&mut self, value: JsValue) {
    self.0 = value;
  }
  #[wasm_bindgen(getter)]
  pub fn value(&self) -> JsValue {
    self.0.clone()
  }
}

#[wasm_bindgen(js_name = Payloads, inspectable)]
pub struct WasmPayloads(pub(crate) Payloads);

impl_wasm_json!(WasmPayloads, Payloads);
impl_wasm_clone!(WasmPayloads, Payloads);

#[wasm_bindgen(js_class = Payloads)]
impl WasmPayloads {
  #[wasm_bindgen(constructor)]
  pub fn new(entries: Vec<WasmPayloadEntry>) -> Result<WasmPayloads> {
    entries
      .into_iter()
      .map(|WasmPayloadEntry(value, type_)| value.into_serde().wasm_result().map(|value| (value, type_.into())))
      .collect::<Result<Vec<(Value, PayloadType)>>>()
      .map(Payloads)
      .map(WasmPayloads)
  }

  #[wasm_bindgen(js_name = newFromValues)]
  pub fn new_from_values(values: Vec<JsValue>) -> Result<WasmPayloads> {
    let values = values
      .into_iter()
      .map(|v| v.into_serde().wasm_result())
      .collect::<Result<Vec<Value>>>()?;

    Ok(Payloads::new_from_values(values).into())
  }

  #[wasm_bindgen(js_name = "getValues")]
  pub fn get_values(&self) -> Result<Vec<JsValue>> {
    self
      .0
      .get_values()
      .into_iter()
      .map(|value| JsValue::from_serde(&value).wasm_result())
      .collect()
  }

  #[wasm_bindgen(js_name = "getUndisclosedIndexes")]
  pub fn get_undisclosed_indexes(&self) -> Vec<usize> {
    self.0.get_undisclosed_indexes()
  }

  #[wasm_bindgen(js_name = "getDisclosedIndexes")]
  pub fn get_disclosed_indexes(&self) -> Vec<usize> {
    self.0.get_disclosed_indexes()
  }

  #[wasm_bindgen(js_name = "getUndisclosedPayloads")]
  pub fn get_undisclosed_payloads(&self) -> Result<Vec<JsValue>> {
    self
      .0
      .get_undisclosed_payloads()
      .into_iter()
      .map(|value| JsValue::from_serde(&value).wasm_result())
      .collect()
  }

  #[wasm_bindgen(js_name = "getDisclosedPayloads")]
  pub fn get_disclosed_payloads(&self) -> WasmPayloads {
    self.0.get_disclosed_payloads().into()
  }

  #[wasm_bindgen(js_name = "setUndisclosed")]
  pub fn set_undisclosed(&mut self, index: usize) {
    self.0.set_undisclosed(index)
  }

  #[wasm_bindgen(js_name = "replacePayloadAtIndex")]
  pub fn replace_payload_at_index(&mut self, index: usize, value: JsValue) -> Result<JsValue> {
    let value = value.into_serde().wasm_result()?;
    self
      .0
      .replace_payload_at_index(index, value)
      .map_err(|_| {
        JsValue::from(WasmError::new(
          Cow::Borrowed("Index out of bounds"),
          Cow::Borrowed("The provided index exceeds the array's bounds"),
        ))
      })
      .and_then(|v| JsValue::from_serde(&v).wasm_result())
  }
}

impl From<Payloads> for WasmPayloads {
  fn from(value: Payloads) -> Self {
    WasmPayloads(value)
  }
}

impl From<WasmPayloads> for Payloads {
  fn from(value: WasmPayloads) -> Self {
    value.0
  }
}
