// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use identity_iota::sd_jwt_rework::JsonObject;
use identity_iota::sd_jwt_rework::JwsSigner;
use js_sys::Error as JsError;
use js_sys::Object;
use js_sys::Uint8Array;
use serde::Serialize as _;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsCast;

use crate::error::Result;

#[wasm_bindgen(typescript_custom_section)]
const I_JWS_SIGNER: &str = r#"
interface JwsSigner {
  sign: (header: object, payload: object) => Promise<Uint8Array>;
}
"#;

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "JwsSigner")]
  pub type WasmJwsSigner;

  #[wasm_bindgen(structural, method, catch)]
  pub async fn sign(this: &WasmJwsSigner, header: Object, payload: Object) -> Result<Uint8Array>;
}

#[async_trait(?Send)]
impl JwsSigner for WasmJwsSigner {
  type Error = String;
  async fn sign(&self, header: &JsonObject, payload: &JsonObject) -> std::result::Result<Vec<u8>, Self::Error> {
    assert!(!payload.is_empty());
    let js_serializer = serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true);
    let header = header
      .serialize(&js_serializer)
      .map_err(|e| format!("{e:?}"))?
      .unchecked_into();
    let payload = payload
      .serialize(&js_serializer)
      .map_err(|e| format!("{e:?}"))?
      .unchecked_into();

    self
      .sign(header, payload)
      .await
      .map_err(|e| e.unchecked_into::<JsError>().to_string().into())
      .map(|arr| arr.to_vec())
  }
}
