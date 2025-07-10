// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod borrow;
mod config_change;
mod controller_execution;
mod send;
mod sub_access;
mod update_did;

pub use borrow::*;
pub use config_change::*;
pub use controller_execution::*;
pub use send::*;
pub use sub_access::*;
pub use update_did::*;

use std::collections::HashMap;
use std::collections::HashSet;

use identity_iota::iota_interaction::types::base_types::IotaAddress;
use identity_iota::iota_interaction::types::base_types::ObjectID;
use js_sys::JsString;
use js_sys::Reflect;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsCast as _;
use wasm_bindgen::JsValue;

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "Set<string>")]
  #[derive(Clone)]
  pub type StringSet;

  #[wasm_bindgen(typescript_type = "[string, string]")]
  pub type StringCouple;

  #[wasm_bindgen(typescript_type = "Map<string, number>")]
  #[derive(Clone)]
  pub type MapStringNumber;
}

impl From<StringCouple> for (String, String) {
  fn from(value: StringCouple) -> Self {
    let first = Reflect::get_u32(&value, 0)
      .expect("[string, string] has property 0")
      .unchecked_into::<JsString>()
      .into();
    let second = Reflect::get_u32(&value, 1)
      .expect("[string, string] has property 1")
      .unchecked_into::<JsString>()
      .into();

    (first, second)
  }
}

impl From<(String, String)> for StringCouple {
  fn from(value: (String, String)) -> Self {
    serde_wasm_bindgen::to_value(&value)
      .expect("a string couple can be serialized to JS")
      .unchecked_into()
  }
}

impl TryFrom<MapStringNumber> for HashMap<IotaAddress, u64> {
  type Error = JsValue;
  fn try_from(value: MapStringNumber) -> Result<Self, Self::Error> {
    Ok(serde_wasm_bindgen::from_value(value.into())?)
  }
}

impl TryFrom<&'_ HashMap<IotaAddress, u64>> for MapStringNumber {
  type Error = JsValue;
  fn try_from(value: &'_ HashMap<IotaAddress, u64>) -> Result<Self, Self::Error> {
    let js_value = serde_wasm_bindgen::to_value(value)?;
    js_value.dyn_into()
  }
}

impl TryFrom<MapStringNumber> for HashMap<ObjectID, u64> {
  type Error = JsValue;
  fn try_from(value: MapStringNumber) -> Result<Self, Self::Error> {
    Ok(serde_wasm_bindgen::from_value(value.into())?)
  }
}

impl TryFrom<&'_ HashMap<ObjectID, u64>> for MapStringNumber {
  type Error = JsValue;
  fn try_from(value: &'_ HashMap<ObjectID, u64>) -> Result<Self, Self::Error> {
    let js_value = serde_wasm_bindgen::to_value(value)?;
    js_value.dyn_into()
  }
}

impl TryFrom<StringSet> for HashSet<ObjectID> {
  type Error = JsValue;
  fn try_from(value: StringSet) -> Result<Self, Self::Error> {
    Ok(serde_wasm_bindgen::from_value(value.into())?)
  }
}

impl TryFrom<&'_ HashSet<ObjectID>> for StringSet {
  type Error = JsValue;
  fn try_from(value: &'_ HashSet<ObjectID>) -> Result<Self, Self::Error> {
    let js_value = serde_wasm_bindgen::to_value(value)?;
    js_value.dyn_into::<StringSet>()
  }
}

// TODO: implement the same in product-core and consume it from
// there instead of having the implementation here.
#[wasm_bindgen(module = "@iota/iota-sdk/transactions")]
extern "C" {
  #[wasm_bindgen(typescript_type = TransactionDataBuilder, extends = js_sys::Object)]
  pub(crate) type TransactionDataBuilder;

  #[wasm_bindgen(js_name = fromKindBytes, static_method_of = TransactionDataBuilder, catch)]
  pub(crate) fn from_tx_kind_bcs(bytes: Vec<u8>) -> Result<TransactionDataBuilder, JsValue>;

  #[wasm_bindgen(method)]
  pub(crate) fn build(this: &TransactionDataBuilder, options: Option<&js_sys::Object>) -> Vec<u8>;
}

impl TransactionDataBuilder {
  pub(crate) fn build_tx_kind(&self) -> Vec<u8> {
    let options = js_sys::Object::new();
    let _ = js_sys::Reflect::set(&options, &JsValue::from_str("onlyTransactionKind"), &JsValue::TRUE);
    self.build(Some(&options))
  }
}
