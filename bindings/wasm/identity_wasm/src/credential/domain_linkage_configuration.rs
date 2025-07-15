// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::credential::ArrayCoreDID;
use crate::credential::WasmJwt;
use crate::did::WasmCoreDID;
use crate::error::Result;
use crate::error::WasmResult;

use identity_iota::credential::DomainLinkageConfiguration;
use identity_iota::credential::Jwt;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

use super::ArrayJwt;

/// DID Configuration Resource which contains Domain Linkage Credentials.
/// It can be placed in an origin's `.well-known` directory to prove linkage between the origin and a DID.
/// See: <https://identity.foundation/.well-known/resources/did-configuration/#did-configuration-resource>
///
/// Note:
/// - Only the [JSON Web Token Proof Format](https://identity.foundation/.well-known/resources/did-configuration/#json-web-token-proof-format)
#[wasm_bindgen(js_name = DomainLinkageConfiguration, inspectable)]
pub struct WasmDomainLinkageConfiguration(pub(crate) DomainLinkageConfiguration);

#[wasm_bindgen(js_class = DomainLinkageConfiguration)]
impl WasmDomainLinkageConfiguration {
  /// Constructs a new {@link DomainLinkageConfiguration}.
  #[wasm_bindgen(constructor)]
  #[allow(non_snake_case)]
  pub fn new(linkedDids: &ArrayJwt) -> Result<WasmDomainLinkageConfiguration> {
    let wasm_credentials: Vec<Jwt> = linkedDids.into_serde().wasm_result()?;
    Ok(Self(DomainLinkageConfiguration::new(wasm_credentials)))
  }

  /// List of the Domain Linkage Credentials.
  #[wasm_bindgen(js_name = linkedDids)]
  pub fn linked_dids(&self) -> ArrayJwt {
    self
      .0
      .linked_dids()
      .iter()
      .cloned()
      .map(WasmJwt::from)
      .map(JsValue::from)
      .collect::<js_sys::Array>()
      .unchecked_into::<ArrayJwt>()
  }

  /// List of the issuers of the Domain Linkage Credentials.
  #[wasm_bindgen]
  pub fn issuers(&self) -> Result<ArrayCoreDID> {
    Ok(
      self
        .0
        .issuers()
        .wasm_result()?
        .into_iter()
        .map(WasmCoreDID::from)
        .map(JsValue::from)
        .collect::<js_sys::Array>()
        .unchecked_into::<ArrayCoreDID>(),
    )
  }
}

impl_wasm_json!(WasmDomainLinkageConfiguration, DomainLinkageConfiguration);
impl_wasm_clone!(WasmDomainLinkageConfiguration, DomainLinkageConfiguration);
