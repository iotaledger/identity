// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
use std::rc::Rc;

use identity_iota::storage::storage::Storage;

use super::WasmJwkStorage;
use super::WasmKeyIdStorage;
use wasm_bindgen::prelude::*;

pub(crate) type WasmStorageInner = Storage<WasmJwkStorage, WasmKeyIdStorage>;

/// A type wrapping a `JwkStorage` and `KeyIdStorage` that should always be used together when
/// working with storage backed DID documents.
#[wasm_bindgen(js_name = Storage)]
#[derive(Clone)]
pub struct WasmStorage(pub(crate) Rc<WasmStorageInner>);

#[wasm_bindgen(js_class = Storage)]
impl WasmStorage {
  /// Constructs a new `Storage`.
  #[wasm_bindgen(constructor)]
  #[allow(non_snake_case)]
  pub fn new(jwkStorage: WasmJwkStorage, keyIdStorage: WasmKeyIdStorage) -> WasmStorage {
    WasmStorage(Rc::new(Storage::new(jwkStorage, keyIdStorage)))
  }

  /// Obtain the wrapped `KeyIdStorage`.
  #[wasm_bindgen(js_name = keyIdStorage)]
  pub fn key_id_storage(&self) -> WasmKeyIdStorage {
    JsValue::from(self.0.key_id_storage()).unchecked_into()
  }

  /// Obtain the wrapped `JwkStorage`.
  #[wasm_bindgen(js_name = keyStorage)]
  pub fn key_storage(&self) -> WasmJwkStorage {
    JsValue::from(self.0.key_storage()).unchecked_into()
  }
}
