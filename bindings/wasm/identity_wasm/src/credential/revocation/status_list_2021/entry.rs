// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::WasmStatusPurpose;
use crate::credential::types::WasmStatus;
use product_common::bindings::wasm_error::Result;
use product_common::bindings::wasm_error::WasmResult;
use product_common::impl_wasm_clone;
use product_common::impl_wasm_json;
use identity_iota::core::Url;
use identity_iota::credential::status_list_2021::StatusList2021Entry;
use identity_iota::credential::Status;
use wasm_bindgen::prelude::*;

/// [StatusList2021Entry](https://www.w3.org/TR/2023/WD-vc-status-list-20230427/#statuslist2021entry) implementation.
#[wasm_bindgen(js_name = StatusList2021Entry, inspectable)]
pub struct WasmStatusList2021Entry(pub(crate) StatusList2021Entry);

#[wasm_bindgen(js_class = StatusList2021Entry)]
impl WasmStatusList2021Entry {
  /// Creates a new {@link StatusList2021Entry}.
  #[wasm_bindgen(constructor)]
  pub fn new(
    status_list: &str,
    purpose: WasmStatusPurpose,
    index: usize,
    id: Option<String>,
  ) -> Result<WasmStatusList2021Entry> {
    let status_list = Url::parse(status_list).map_err(|e| JsError::new(&e.to_string()))?;
    let id = if let Some(id) = id {
      Some(Url::parse(id).map_err(|e| JsError::new(&e.to_string()))?)
    } else {
      None
    };
    Ok(Self(StatusList2021Entry::new(status_list, purpose.into(), index, id)))
  }

  /// Returns this `credentialStatus`'s `id`.
  #[wasm_bindgen]
  pub fn id(&self) -> String {
    self.0.id().to_string()
  }

  /// Returns the purpose of this entry.
  #[wasm_bindgen]
  pub fn purpose(&self) -> WasmStatusPurpose {
    self.0.purpose().into()
  }

  /// Returns the index of this entry.
  #[wasm_bindgen]
  pub fn index(&self) -> usize {
    self.0.index()
  }

  /// Returns the referenced {@link StatusList2021Credential}'s url.
  #[wasm_bindgen(js_name = "statusListCredential")]
  pub fn status_list_credential(&self) -> String {
    self.0.status_list_credential().to_string()
  }

  /// Downcasts {@link StatusList2021Entry} to {@link Status}
  #[wasm_bindgen(js_name = "toStatus")]
  pub fn to_status(self) -> Result<WasmStatus> {
    Ok(
      JsValue::from_serde(&Status::from(self.0))
        .wasm_result()?
        .unchecked_into(),
    )
  }
}

impl_wasm_clone!(WasmStatusList2021Entry, StatusList2021Entry);
impl_wasm_json!(WasmStatusList2021Entry, StatusList2021Entry);
