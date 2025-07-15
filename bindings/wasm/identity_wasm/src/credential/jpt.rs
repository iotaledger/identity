// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::credential::Jpt;
use wasm_bindgen::prelude::*;

/// A JSON Proof Token (JPT).
#[wasm_bindgen(js_name = Jpt)]
pub struct WasmJpt(pub(crate) Jpt);

#[wasm_bindgen(js_class = Jpt)]
impl WasmJpt {
  /// Creates a new {@link Jpt}.
  #[wasm_bindgen(constructor)]
  pub fn new(jpt_string: String) -> Self {
    WasmJpt(Jpt::new(jpt_string))
  }

  // Returns the string representation for this {@link Jpt}.
  #[allow(clippy::inherent_to_string)]
  #[wasm_bindgen(js_name = "toString")]
  pub fn to_string(&self) -> String {
    self.0.as_str().to_owned()
  }
}

impl_wasm_clone!(WasmJpt, Jpt);

impl From<Jpt> for WasmJpt {
  fn from(value: Jpt) -> Self {
    WasmJpt(value)
  }
}

impl From<WasmJpt> for Jpt {
  fn from(value: WasmJpt) -> Self {
    value.0
  }
}

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "Promise<Jpt>")]
  pub type PromiseJpt;
}
