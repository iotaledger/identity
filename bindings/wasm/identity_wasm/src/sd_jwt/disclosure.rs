// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::sd_jwt_payload::Disclosure;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

use crate::error::Result;
use crate::error::WasmResult;

/// A disclosable value.
/// Both object properties and array elements disclosures are supported.
///
/// See: [RFC9901 Disclosures](https://www.rfc-editor.org/rfc/rfc9901.html#name-disclosures)
#[derive(Clone)]
#[wasm_bindgen(js_name = Disclosure, inspectable, getter_with_clone)]
pub struct WasmDisclosure {
  pub salt: String,
  #[wasm_bindgen(js_name = claimName)]
  pub claim_name: Option<String>,
  #[wasm_bindgen(js_name = claimValue)]
  pub claim_value: JsValue,
  unparsed: String,
}

#[wasm_bindgen(js_class = Disclosure)]
impl WasmDisclosure {
  /// Attepts to parse a {@link Disclosure} from the given string.
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
