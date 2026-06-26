// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;

use crate::error::Result;
use crate::error::WasmResult;

/// Special-case for deserializing [`js_sys::Map`], which otherwise serializes to JSON as an empty
/// object `{}`. This uses a [`js_sys::Object`] as an intermediate representation to convert
/// to the required struct via JSON.
///
/// Useful for deserializing properties fields which have the TypeScript type:
/// `Map<string, any> | Record<string, any>`
pub(crate) fn deserialize_map_or_any<T>(value: &JsValue) -> Result<T>
where
  T: for<'a> serde::de::Deserialize<'a>,
{
  if let Some(map) = JsCast::dyn_ref::<js_sys::Map>(value) {
    // Map<string, string[]>
    js_sys::Object::from_entries(map).and_then(|object| JsValue::into_serde(&object).wasm_result())
  } else {
    // any
    value.into_serde().wasm_result()
  }
}
