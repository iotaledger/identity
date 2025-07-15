// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::error::Result;
use crate::error::WasmResult;
use identity_iota::credential::status_list_2021::StatusList2021;
use wasm_bindgen::prelude::*;

/// StatusList2021 data structure as described in [W3C's VC status list 2021](https://www.w3.org/TR/2023/WD-vc-status-list-20230427/).
#[wasm_bindgen(js_name = StatusList2021, inspectable)]
#[derive(Default, Debug)]
pub struct WasmStatusList2021(pub(crate) StatusList2021);

impl_wasm_clone!(WasmStatusList2021, StatusList2021);

#[wasm_bindgen(js_class = StatusList2021)]
impl WasmStatusList2021 {
  /// Creates a new {@link StatusList2021} of `size` entries.
  #[wasm_bindgen(constructor)]
  pub fn new(size: Option<usize>) -> Result<WasmStatusList2021> {
    Ok(Self(match size {
      Some(size) => StatusList2021::new(size).map_err(|e| JsError::new(&e.to_string()))?,
      None => StatusList2021::default(),
    }))
  }

  /// Returns the number of entries in this {@link StatusList2021}.
  #[wasm_bindgen]
  #[allow(clippy::len_without_is_empty)]
  pub fn len(&self) -> usize {
    self.0.len()
  }

  /// Returns whether the entry at `index` is set.
  #[wasm_bindgen]
  pub fn get(&self, index: usize) -> Result<bool> {
    self.0.get(index).wasm_result()
  }

  /// Sets the value of the `index`-th entry.
  #[wasm_bindgen]
  pub fn set(&mut self, index: usize, value: bool) -> Result<()> {
    self.0.set(index, value).wasm_result()
  }

  /// Encodes this {@link StatusList2021} into its compressed
  /// base64 string representation.
  #[wasm_bindgen(js_name = "intoEncodedStr")]
  pub fn into_encoded_str(self) -> String {
    self.0.into_encoded_str()
  }

  #[wasm_bindgen(js_name = "fromEncodedStr")]
  /// Attempts to decode a {@link StatusList2021} from a string.
  pub fn from_encoded_str(s: &str) -> Result<WasmStatusList2021> {
    StatusList2021::try_from_encoded_str(s).map(Self).wasm_result()
  }
}
