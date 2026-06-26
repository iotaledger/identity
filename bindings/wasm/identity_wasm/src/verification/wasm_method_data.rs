// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::verification::CustomMethodData;
use identity_iota::verification::MethodData;
use wasm_bindgen::prelude::*;

use crate::error::Result;
use crate::error::WasmError;
use crate::error::WasmResult;
use crate::jose::WasmJwk;
use std::borrow::Cow;

/// Supported verification method data formats.
#[wasm_bindgen(js_name = MethodData, inspectable)]
pub struct WasmMethodData(pub(crate) MethodData);

#[wasm_bindgen(js_class = MethodData)]
impl WasmMethodData {
  /// Creates a new {@link MethodData} variant with Base58-BTC encoded content.
  #[wasm_bindgen(js_name = newBase58)]
  pub fn new_base58(data: Vec<u8>) -> Self {
    Self(MethodData::new_base58(data))
  }

  /// Creates a new {@link MethodData} variant with Multibase-encoded content.
  #[wasm_bindgen(js_name = newMultibase)]
  pub fn new_multibase(data: Vec<u8>) -> Self {
    Self(MethodData::new_multibase(data))
  }

  /// Creates a new {@link MethodData} variant consisting of the given `key`.
  ///
  /// ### Errors
  /// An error is thrown if the given `key` contains any private components.
  #[wasm_bindgen(js_name = newJwk)]
  pub fn new_jwk(key: &WasmJwk) -> Result<WasmMethodData> {
    if !key.0.is_public() {
      return Err(WasmError::new(
        Cow::Borrowed("PrivateKeyMaterialExposed"),
        Cow::Borrowed("jwk with private key components is not permitted"),
      ))
      .wasm_result();
    };

    Ok(Self(MethodData::PublicKeyJwk(key.0.clone())))
  }

  /// Creates a new custom {@link MethodData}.
  #[wasm_bindgen(js_name = newCustom)]
  pub fn new_custom(name: String, data: JsValue) -> Result<WasmMethodData> {
    let data = data.into_serde::<serde_json::Value>().wasm_result()?;
    Ok(Self(MethodData::Custom(CustomMethodData { name, data })))
  }

  /// Returns the wrapped custom method data format is `Custom`.
  #[wasm_bindgen(js_name = tryCustom)]
  pub fn try_custom(&self) -> Result<WasmCustomMethodData> {
    self
      .0
      .custom()
      .map(|custom| custom.clone().into())
      .ok_or(WasmError::new(
        Cow::Borrowed("MethodDataFormatError"),
        Cow::Borrowed("method data format is not Custom"),
      ))
      .wasm_result()
  }

  /// Returns a `Uint8Array` containing the decoded bytes of the {@link MethodData}.
  ///
  /// This is generally a public key identified by a {@link MethodData} value.
  ///
  /// ### Errors
  /// Decoding can fail if {@link MethodData} has invalid content or cannot be
  /// represented as a vector of bytes.
  #[wasm_bindgen(js_name = tryDecode)]
  pub fn try_decode(&self) -> Result<Vec<u8>> {
    self.0.try_decode().wasm_result()
  }

  /// Returns the wrapped {@link Jwk} if the format is `PublicKeyJwk`.
  #[wasm_bindgen(js_name = tryPublicKeyJwk)]
  pub fn try_public_key_jwk(&self) -> Result<WasmJwk> {
    self.0.try_public_key_jwk().cloned().map(WasmJwk::from).wasm_result()
  }
}

impl_wasm_json!(WasmMethodData, MethodData);
impl_wasm_clone!(WasmMethodData, MethodData);

impl From<WasmMethodData> for MethodData {
  fn from(data: WasmMethodData) -> Self {
    data.0
  }
}

impl From<MethodData> for WasmMethodData {
  fn from(data: MethodData) -> Self {
    WasmMethodData(data)
  }
}

/// A custom verification method data format.
#[wasm_bindgen(js_name = CustomMethodData, inspectable)]
pub struct WasmCustomMethodData(pub(crate) CustomMethodData);

#[wasm_bindgen(js_class = CustomMethodData)]
impl WasmCustomMethodData {
  #[wasm_bindgen(constructor)]
  pub fn new(name: String, data: JsValue) -> Result<WasmCustomMethodData> {
    let data = data.into_serde::<serde_json::Value>().wasm_result()?;
    Ok(Self(CustomMethodData { name, data }))
  }
}

impl From<CustomMethodData> for WasmCustomMethodData {
  fn from(value: CustomMethodData) -> Self {
    Self(value)
  }
}

impl From<WasmCustomMethodData> for CustomMethodData {
  fn from(value: WasmCustomMethodData) -> Self {
    value.0
  }
}

impl_wasm_clone!(WasmCustomMethodData, CustomMethodData);
impl_wasm_json!(WasmCustomMethodData, CustomMethodData);
