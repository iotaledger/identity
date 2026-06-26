// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::storage::key_id_storage::MethodDigest;
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

use crate::error::Result;
use crate::error::WasmResult;
use crate::verification::WasmVerificationMethod;

/// Unique identifier of a {@link VerificationMethod}.
///
/// NOTE:
/// This class does not have a JSON representation,
/// use the methods `pack` and `unpack` instead.
#[wasm_bindgen(js_name = MethodDigest, inspectable)]
pub struct WasmMethodDigest(pub(crate) MethodDigest);

#[wasm_bindgen(js_class = MethodDigest)]
impl WasmMethodDigest {
  #[wasm_bindgen(constructor)]
  pub fn new(verification_method: &WasmVerificationMethod) -> Result<WasmMethodDigest> {
    Ok(Self(MethodDigest::new(&verification_method.0).wasm_result()?))
  }

  /// Packs {@link MethodDigest} into bytes.
  #[wasm_bindgen]
  pub fn pack(&self) -> Uint8Array {
    let bytes: &[u8] = &self.0.pack();
    bytes.into()
  }

  /// Unpacks bytes into {@link MethodDigest}.
  #[wasm_bindgen]
  pub fn unpack(bytes: &Uint8Array) -> Result<WasmMethodDigest> {
    let bytes: Vec<u8> = bytes.to_vec();
    Ok(Self(MethodDigest::unpack(bytes).wasm_result()?))
  }
}

impl_wasm_clone!(WasmMethodDigest, MethodDigest);
