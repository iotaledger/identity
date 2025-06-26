// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::core::Url;
use identity_iota::credential::RevocationTimeframeStatus;
use wasm_bindgen::prelude::*;

use crate::common::WasmDuration;
use crate::common::WasmTimestamp;
use product_common::bindings::wasm_error::Result;
use product_common::bindings::wasm_error::WasmResult;
use product_common::impl_wasm_clone;
use product_common::impl_wasm_json;

/// Information used to determine the current status of a {@link Credential}.
#[wasm_bindgen(js_name = RevocationTimeframeStatus, inspectable)]
pub struct WasmRevocationTimeframeStatus(pub(crate) RevocationTimeframeStatus);

impl_wasm_clone!(WasmRevocationTimeframeStatus, RevocationTimeframeStatus);
impl_wasm_json!(WasmRevocationTimeframeStatus, RevocationTimeframeStatus);

#[wasm_bindgen(js_class = RevocationTimeframeStatus)]
impl WasmRevocationTimeframeStatus {
  /// Creates a new `RevocationTimeframeStatus`.
  #[wasm_bindgen(constructor)]
  pub fn new(
    id: String,
    index: u32,
    duration: WasmDuration,
    start_validity: Option<WasmTimestamp>,
  ) -> Result<WasmRevocationTimeframeStatus> {
    RevocationTimeframeStatus::new(
      start_validity.map(|t| t.0),
      duration.0,
      Url::parse(id).wasm_result()?,
      index,
    )
    .wasm_result()
    .map(WasmRevocationTimeframeStatus)
  }

  /// Get startValidityTimeframe value.
  #[wasm_bindgen(js_name = "startValidityTimeframe")]
  pub fn start_validity_timeframe(&self) -> WasmTimestamp {
    self.0.start_validity_timeframe().into()
  }

  /// Get endValidityTimeframe value.
  #[wasm_bindgen(js_name = "endValidityTimeframe")]
  pub fn end_validity_timeframe(&self) -> WasmTimestamp {
    self.0.end_validity_timeframe().into()
  }

  /// Return the URL for the `RevocationBitmapStatus`.
  #[wasm_bindgen]
  pub fn id(&self) -> String {
    self.0.id().to_string()
  }

  /// Return the index of the credential in the issuer's revocation bitmap
  #[wasm_bindgen]
  pub fn index(&self) -> Option<u32> {
    self.0.index()
  }
}

impl From<RevocationTimeframeStatus> for WasmRevocationTimeframeStatus {
  fn from(value: RevocationTimeframeStatus) -> Self {
    WasmRevocationTimeframeStatus(value)
  }
}

impl From<WasmRevocationTimeframeStatus> for RevocationTimeframeStatus {
  fn from(value: WasmRevocationTimeframeStatus) -> Self {
    value.0
  }
}
