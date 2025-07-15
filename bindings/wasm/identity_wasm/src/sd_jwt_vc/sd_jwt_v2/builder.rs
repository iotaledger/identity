// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::sd_jwt_rework::SdJwtBuilder;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

use crate::error::Result;
use crate::error::WasmResult;
use crate::sd_jwt_vc::sd_jwt_v2::WasmSdJwt;

use super::WasmHasher;
use super::WasmJwsSigner;
use super::WasmRequiredKeyBinding;

#[wasm_bindgen(js_name = SdJwtBuilder)]
pub struct WasmSdJwtBuilder(pub(crate) SdJwtBuilder<WasmHasher>);

#[wasm_bindgen(js_class = SdJwtBuilder)]
impl WasmSdJwtBuilder {
  /// Creates a new {@link SdJwtVcBuilder} using `object` JSON representation and a given
  /// hasher `hasher`.
  #[wasm_bindgen(constructor)]
  pub fn new(object: js_sys::Object, hasher: WasmHasher, salt_size: Option<usize>) -> Result<Self> {
    let object = serde_wasm_bindgen::from_value::<serde_json::Value>(object.into()).wasm_result()?;
    let salt_size = salt_size.unwrap_or(30);
    SdJwtBuilder::new_with_hasher_and_salt_size(object, hasher, salt_size)
      .map(Self)
      .wasm_result()
  }

  /// Substitutes a value with the digest of its disclosure.
  ///
  /// ## Notes
  /// - `path` indicates the pointer to the value that will be concealed using the syntax of [JSON pointer](https://datatracker.ietf.org/doc/html/rfc6901).
  #[wasm_bindgen(js_name = makeConcealable)]
  pub fn make_concealable(self, path: &str) -> Result<Self> {
    self.0.make_concealable(path).map(Self).wasm_result()
  }

  /// Sets the JWT header.
  /// ## Notes
  /// - if {@link SdJwtVcBuilder.header} is not called, the default header is used: ```json { "typ": "sd-jwt", "alg":
  ///   "<algorithm used in SdJwtBuilder.finish>" } ```
  /// - `alg` is always replaced with the value passed to {@link SdJwtVcBuilder.finish}.
  #[wasm_bindgen]
  pub fn header(self, header: js_sys::Object) -> Self {
    let header = serde_wasm_bindgen::from_value(header.into()).expect("JS object is a valid JSON object");
    Self(self.0.header(header))
  }

  /// Adds a new claim to the underlying object.
  #[wasm_bindgen(js_name = insertClaim)]
  pub fn insert_claim(self, key: String, value: JsValue) -> Result<Self> {
    let value = serde_wasm_bindgen::from_value::<serde_json::Value>(value).wasm_result()?;
    self.0.insert_claim(key, value).map(Self).wasm_result()
  }

  /// Adds a decoy digest to the specified path.
  ///
  /// `path` indicates the pointer to the value that will be concealed using the syntax of
  /// [JSON pointer](https://datatracker.ietf.org/doc/html/rfc6901).
  ///
  /// Use `path` = "" to add decoys to the top level.
  #[wasm_bindgen(js_name = addDecoys)]
  pub fn add_decoys(self, path: &str, number_of_decoys: usize) -> Result<Self> {
    self.0.add_decoys(path, number_of_decoys).map(Self).wasm_result()
  }

  /// Require a proof of possession of a given key from the holder.
  ///
  /// This operation adds a JWT confirmation (`cnf`) claim as specified in
  /// [RFC8300](https://www.rfc-editor.org/rfc/rfc7800.html#section-3).
  #[wasm_bindgen(js_name = requireKeyBinding)]
  pub fn require_key_binding(self, key_bind: WasmRequiredKeyBinding) -> Result<Self> {
    let key_bind = serde_wasm_bindgen::from_value(key_bind.into()).wasm_result()?;
    Ok(Self(self.0.require_key_binding(key_bind)))
  }

  /// Creates an {@link SdJwtVc} with the provided data.
  #[wasm_bindgen]
  pub async fn finish(self, signer: &WasmJwsSigner, alg: &str) -> Result<WasmSdJwt> {
    self.0.finish(signer, alg).await.map(WasmSdJwt).wasm_result()
  }
}
