// Copyright 2020-2025 IOTA Stiftung, Fondazione LINKS
// SPDX-License-Identifier: Apache-2.0

use identity_iota::verification::jwk::CompositeAlgId;
use identity_iota::verification::jws::JwsAlgorithm;
use js_sys::JsString;
use std::str::FromStr;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "IJwkParams")]
  pub type IJwkParams;
  #[wasm_bindgen(typescript_type = "JwsAlgorithm")]
  pub type WasmJwsAlgorithm;
  #[wasm_bindgen(typescript_type = "JwkUse")]
  pub type WasmJwkUse;
  #[wasm_bindgen(typescript_type = "JwkType")]
  pub type WasmJwkType;
  #[wasm_bindgen(typescript_type = "Array<JwkOperation>")]
  pub type ArrayJwkOperation;
  #[wasm_bindgen(typescript_type = "JwkParamsEc")]
  pub type WasmJwkParamsEc;
  #[wasm_bindgen(typescript_type = "JwkParamsOkp")]
  pub type WasmJwkParamsOkp;
  #[wasm_bindgen(typescript_type = "JwkParamsRsa")]
  pub type WasmJwkParamsRsa;
  #[wasm_bindgen(typescript_type = "JwkParamsOct")]
  pub type WasmJwkParamsOct;
  #[wasm_bindgen(typescript_type = "JwkParamsAkp")]
  pub type WasmJwkParamsAkp;
  #[wasm_bindgen(typescript_type = "CompositeAlgId")]
  pub type WasmCompositeAlgId;
}

impl TryFrom<WasmJwsAlgorithm> for JwsAlgorithm {
  type Error = JsValue;
  fn try_from(value: WasmJwsAlgorithm) -> Result<Self, Self::Error> {
    if let Ok(js_string) = value.dyn_into::<JsString>() {
      JwsAlgorithm::from_str(String::from(js_string).as_ref())
        .map_err(|err| js_sys::Error::new(&err.to_string()).into())
    } else {
      Err(js_sys::Error::new("invalid JwsAlgorithm").into())
    }
  }
}

impl TryFrom<WasmCompositeAlgId> for CompositeAlgId {
  type Error = JsValue;
  fn try_from(value: WasmCompositeAlgId) -> Result<Self, Self::Error> {
    if let Ok(js_string) = value.dyn_into::<JsString>() {
      CompositeAlgId::from_str(String::from(js_string).as_ref())
        .map_err(|err| js_sys::Error::new(&err.to_string()).into())
    } else {
      Err(js_sys::Error::new("invalid CompositeAlgId").into())
    }
  }
}
