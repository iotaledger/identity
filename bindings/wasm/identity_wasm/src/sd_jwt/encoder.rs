// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::disclosure::WasmDisclosure;
use crate::common::RecordStringAny;
use crate::error::Result;
use crate::error::WasmResult;
use identity_iota::sd_jwt_payload::SdObjectEncoder;
use identity_iota::sd_jwt_payload::Sha256Hasher;
use serde_json::Value;
use wasm_bindgen::prelude::*;

/// Transforms a JSON object into an SD-JWT object by substituting selected values
/// with their corresponding disclosure digests.
///
/// Note: digests are created using the sha-256 algorithm.
#[wasm_bindgen(js_name = SdObjectEncoder, inspectable)]
pub struct WasmSdObjectEncoder(pub(crate) SdObjectEncoder<Sha256Hasher>);

#[wasm_bindgen(js_class = SdObjectEncoder)]
impl WasmSdObjectEncoder {
  /// Creates a new `SdObjectEncoder` with `sha-256` hash function.
  #[wasm_bindgen(constructor)]
  pub fn new(object: &JsValue) -> Result<WasmSdObjectEncoder> {
    let object: Value = object.into_serde().wasm_result()?;
    Ok(Self(SdObjectEncoder::try_from_serializable(object).wasm_result()?))
  }

  /// Substitutes a value with the digest of its disclosure.
  /// If no salt is provided, the disclosure will be created with a random salt value.
  ///
  /// `path` indicates the pointer to the value that will be concealed using the syntax of
  /// [JSON pointer](https://datatracker.ietf.org/doc/html/rfc6901).
  ///
  /// For the following object:
  ///
  ///  ```
  /// {
  ///   "id": "did:value",
  ///   "claim1": {
  ///      "abc": true
  ///   },
  ///   "claim2": ["val_1", "val_2"]
  /// }
  /// ```
  /// 
  /// Path "/id" conceals `"id": "did:value"`
  /// Path "/claim1/abc" conceals `"abc": true`
  /// Path "/claim2/0" conceals `val_1`
  ///
  /// ## Errors
  /// * `InvalidPath` if pointer is invalid.
  /// * `DataTypeMismatch` if existing SD format is invalid.
  #[wasm_bindgen(js_name = conceal)]
  pub fn conceal(&mut self, path: String, salt: Option<String>) -> Result<WasmDisclosure> {
    let disclosure = self.0.conceal(&path, salt).wasm_result()?;
    Ok(WasmDisclosure(disclosure))
  }

  /// Adds the `_sd_alg` property to the top level of the object, with
  /// its value set to "sha-256".
  #[wasm_bindgen(js_name = addSdAlgProperty)]
  pub fn add_sd_alg_property(&mut self) {
    self.0.add_sd_alg_property();
  }

  /// Returns the modified object as a string.
  #[wasm_bindgen(js_name = encodeToString)]
  pub fn encoded_to_string(&self) -> Result<String> {
    self.0.try_to_string().wasm_result()
  }

  /// Returns the modified object as a string.
  #[wasm_bindgen(js_name = toString)]
  pub fn to_string(&self) -> Result<String> {
    self.0.try_to_string().wasm_result()
  }

  /// Returns the modified object.
  #[wasm_bindgen(js_name = encodeToObject)]
  pub fn encode_to_object(&self) -> Result<RecordStringAny> {
    Ok(
      JsValue::from_serde(&self.0.object().wasm_result()?)
        .wasm_result()?
        .unchecked_into::<RecordStringAny>(),
    )
  }

  /// Returns the modified object.
  #[wasm_bindgen(js_name = toJSON)]
  pub fn to_json(&self) -> Result<JsValue> {
    JsValue::from_serde(&self.0.object().wasm_result()?).wasm_result()
  }

  /// Adds a decoy digest to the specified path.
  /// If path is an empty slice, decoys will be added to the top level.
  #[wasm_bindgen(js_name = addDecoys)]
  pub fn add_decoys(&mut self, path: String, number_of_decoys: usize) -> Result<()> {
    self.0.add_decoys(&path, number_of_decoys).wasm_result()?;
    Ok(())
  }
}
