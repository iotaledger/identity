#![allow(clippy::inherent_to_string, clippy::new_without_default)]

#[macro_use]
extern crate serde;

use wasm_bindgen::prelude::*;

pub mod did;
pub mod doc;
pub mod iota;
pub mod key;
pub mod pubkey;
pub mod vc;
pub mod vp;

#[wasm_bindgen(start)]
pub fn start() -> Result<(), JsValue> {
    initialize();
    Ok(())
}

/// Initializes the console_error_panic_hook for better error messages
#[wasm_bindgen]
pub fn initialize() -> JsValue {
    console_error_panic_hook::set_once();

    JsValue::TRUE
}

/// Convert errors so they are readable in JS
pub fn js_err<T: ToString>(error: T) -> JsValue {
    error.to_string().into()
}
