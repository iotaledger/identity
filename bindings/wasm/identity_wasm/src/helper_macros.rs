// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use wasm_bindgen::prelude::wasm_bindgen;

#[macro_export]
macro_rules! log {
  ($($tt:tt)*) => {
    web_sys::console::log_1(&format!($($tt)*).into());
  }
}

/// Log to console utility without the need for web_sys dependency
#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(js_namespace = console, js_name = log)]
  pub fn console_log(s: &str);
}

/// Logging macro without the need for web_sys dependency
#[macro_export]
macro_rules! console_log {
  ($($tt:tt)*) => {
    $crate::macros::console_log((format!($($tt)*)).as_str())
  }
}

#[macro_export]
macro_rules! impl_wasm_clone {
  ($wasm_class:ident, $js_class:ident) => {
    #[wasm_bindgen(js_class = $js_class)]
    impl $wasm_class {
      /// Deep clones the object.
      #[wasm_bindgen(js_name = clone)]
      pub fn deep_clone(&self) -> $wasm_class {
        return $wasm_class(self.0.clone());
      }
    }
  };
}

#[macro_export]
macro_rules! impl_wasm_json {
  ($wasm_class:ident, $js_class:ident) => {
    #[wasm_bindgen(js_class = $js_class)]
    impl $wasm_class {
      /// Serializes this to a JSON object.
      #[wasm_bindgen(js_name = toJSON)]
      pub fn to_json(&self) -> $crate::error::Result<wasm_bindgen::JsValue> {
        use $crate::error::WasmResult;
        wasm_bindgen::JsValue::from_serde(&self.0).wasm_result()
      }

      /// Deserializes an instance from a JSON object.
      #[wasm_bindgen(js_name = fromJSON)]
      pub fn from_json(json: &wasm_bindgen::JsValue) -> $crate::error::Result<$wasm_class> {
        use $crate::error::WasmResult;
        json.into_serde().map(Self).wasm_result()
      }
    }
  };
}
