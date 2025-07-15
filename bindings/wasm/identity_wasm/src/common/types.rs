// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::core::Object;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

use crate::error::WasmResult;

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "Promise<void>")]
  pub type PromiseVoid;

  #[wasm_bindgen(typescript_type = "Promise<boolean>")]
  pub type PromiseBool;

  #[wasm_bindgen(typescript_type = "Promise<string>")]
  pub type PromiseString;

  #[wasm_bindgen(typescript_type = "Promise<string | null>")]
  pub type PromiseOptionString;

  #[wasm_bindgen(typescript_type = "Promise<Uint8Array>")]
  pub type PromiseUint8Array;

  #[wasm_bindgen(typescript_type = "Array<string>")]
  pub type ArrayString;

  #[wasm_bindgen(typescript_type = "Map<string, any>")]
  pub type MapStringAny;

  #[wasm_bindgen(typescript_type = "Record<string, any>")]
  pub type RecordStringAny;

  #[wasm_bindgen(typescript_type = "number | number[]")]
  pub type UOneOrManyNumber;

  #[wasm_bindgen(typescript_type = "string | string[] | null")]
  pub type OptionOneOrManyString;

  #[wasm_bindgen(typescript_type = "VerificationMethod[]")]
  pub type ArrayVerificationMethod;

  #[wasm_bindgen(typescript_type = "Array<DIDUrl | VerificationMethod>")]
  pub type ArrayCoreMethodRef;

  #[wasm_bindgen(typescript_type = "DIDUrl | string")]
  pub type UDIDUrlQuery;

  #[wasm_bindgen(typescript_type = "Service[]")]
  pub type ArrayService;
}

impl TryFrom<Object> for MapStringAny {
  type Error = JsValue;

  fn try_from(properties: Object) -> Result<Self, Self::Error> {
    MapStringAny::try_from(&properties)
  }
}

impl TryFrom<&Object> for MapStringAny {
  type Error = JsValue;

  fn try_from(properties: &Object) -> Result<Self, Self::Error> {
    let map: js_sys::Map = js_sys::Map::new();
    for (key, value) in properties.iter() {
      map.set(
        &JsValue::from_str(key.as_str()),
        &JsValue::from_serde(&value).wasm_result()?,
      );
    }
    Ok(map.unchecked_into::<MapStringAny>())
  }
}

impl Default for MapStringAny {
  fn default() -> Self {
    js_sys::Map::new().unchecked_into()
  }
}
