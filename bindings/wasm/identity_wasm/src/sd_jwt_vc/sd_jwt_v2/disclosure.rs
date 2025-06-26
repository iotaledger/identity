// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::sd_jwt_rework::Disclosure;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

use product_common::bindings::wasm_error::Result;
use product_common::bindings::wasm_error::WasmResult;

/// A disclosable value.
/// Both object properties and array elements disclosures are supported.
///
/// See: https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-07.html#name-disclosures
#[derive(Clone)]
#[wasm_bindgen(js_name = DisclosureV2, inspectable, getter_with_clone)]
pub struct WasmDisclosure {
  pub salt: String,
  #[wasm_bindgen(js_name = claimName)]
  pub claim_name: Option<String>,
  #[wasm_bindgen(js_name = claimValue)]
  pub claim_value: JsValue,
  unparsed: String,
}

#[wasm_bindgen(js_class = DisclosureV2)]
impl WasmDisclosure {
  #[wasm_bindgen]
  pub fn parse(s: &str) -> Result<Self> {
    Disclosure::parse(s).map(Self::from).wasm_result()
  }

  #[allow(clippy::inherent_to_string)]
  #[wasm_bindgen(js_name = toString)]
  pub fn to_string(&self) -> String {
    self.unparsed.clone()
  }
}

impl From<WasmDisclosure> for Disclosure {
  fn from(value: WasmDisclosure) -> Self {
    Disclosure::parse(&value.unparsed).expect("valid WasmDisclosure is a valid disclosure")
  }
}

impl From<Disclosure> for WasmDisclosure {
  fn from(value: Disclosure) -> Self {
    let unparsed = value.to_string();
    let Disclosure {
      salt,
      claim_name,
      claim_value,
      ..
    } = value;
    let claim_value = serde_wasm_bindgen::to_value(&claim_value).expect("serde JSON Value is a valid JS Value");

    Self {
      salt,
      claim_name,
      claim_value,
      unparsed,
    }
  }
}
