// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::credential::sd_jwt_vc::Error;
use identity_iota::sd_jwt_rework::SdJwt;
use identity_iota::sd_jwt_rework::SdJwtPresentationBuilder;
use identity_iota::sd_jwt_rework::Sha256Hasher;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;

use crate::error::Result;
use crate::error::WasmResult;

use super::WasmDisclosure;
use super::WasmHasher;
use super::WasmKeyBindingJwt;
use super::WasmRequiredKeyBinding;

#[wasm_bindgen(typescript_custom_section)]
const I_SD_JWT_CLAIMS: &str = r#"
interface SdJwtClaims {
  _sd: string[];
  _sd_alg?: string;
  cnf?: RequiredKeyBinding;
  [properties: string]: unknown;
}
"#;

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "SdJwtClaims")]
  pub type WasmSdJwtClaims;
}

#[derive(Clone)]
#[wasm_bindgen(js_name = SdJwtV2)]
pub struct WasmSdJwt(pub(crate) SdJwt);

#[wasm_bindgen(js_class = SdJwtV2)]
impl WasmSdJwt {
  #[wasm_bindgen]
  pub fn parse(s: &str) -> Result<WasmSdJwt> {
    SdJwt::parse(s).map(Self).map_err(Error::from).wasm_result()
  }

  #[wasm_bindgen]
  pub fn header(&self) -> JsValue {
    serde_wasm_bindgen::to_value(self.0.header()).unwrap()
  }

  #[wasm_bindgen]
  pub fn claims(&self) -> Result<WasmSdJwtClaims> {
    serde_wasm_bindgen::to_value(self.0.claims())
      .wasm_result()
      .map(JsCast::unchecked_into)
  }

  #[wasm_bindgen]
  pub fn disclosures(&self) -> Vec<String> {
    self.0.disclosures().iter().map(ToString::to_string).collect()
  }

  #[wasm_bindgen(js_name = "requiredKeyBind")]
  pub fn required_key_bind(&self) -> Option<WasmRequiredKeyBinding> {
    self.0.required_key_bind().map(|required_kb| {
      serde_wasm_bindgen::to_value(required_kb)
        .expect("RequiredKeyBinding can be turned into a JS value")
        .unchecked_into()
    })
  }

  /// Returns the JSON object obtained by replacing all disclosures into their
  /// corresponding JWT concealable claims.
  #[wasm_bindgen(js_name = "intoDisclosedObject")]
  pub fn into_disclosed_object(self) -> Result<JsValue> {
    self
      .0
      .into_disclosed_object(&Sha256Hasher)
      .map_err(Error::from)
      .map(|obj| serde_wasm_bindgen::to_value(&obj).expect("obj can be turned into a JS value"))
      .wasm_result()
  }

  /// Serializes the components into the final SD-JWT.
  #[wasm_bindgen]
  pub fn presentation(&self) -> String {
    self.0.presentation()
  }

  #[wasm_bindgen(js_name = "toJSON")]
  pub fn to_json(&self) -> JsValue {
    JsValue::from_str(&self.presentation())
  }

  #[allow(clippy::inherent_to_string)]
  #[wasm_bindgen(js_name = "toString")]
  pub fn to_string(&self) -> JsValue {
    JsValue::from_str(&self.presentation())
  }
}

#[wasm_bindgen(js_name = SdJwtPresentationBuilder)]
pub struct WasmSdJwtPresentationBuilder(pub(crate) SdJwtPresentationBuilder);

#[wasm_bindgen(js_class = SdJwtPresentationBuilder)]
impl WasmSdJwtPresentationBuilder {
  #[wasm_bindgen(constructor)]
  pub fn new(sd_jwt: WasmSdJwt, hasher: &WasmHasher) -> Result<Self> {
    SdJwtPresentationBuilder::new(sd_jwt.0, hasher).map(Self).wasm_result()
  }

  /// Removes the disclosure for the property at `path`, concealing it.
  ///
  /// ## Notes
  /// - When concealing a claim more than one disclosure may be removed: the disclosure for the claim itself and the
  ///   disclosures for any concealable sub-claim.
  #[wasm_bindgen]
  pub fn conceal(self, path: &str) -> Result<Self> {
    self.0.conceal(path).map(Self).wasm_result()
  }

  /// Adds a {@link KeyBindingJwt} to this {@link SdJwt}'s presentation.
  #[wasm_bindgen(js_name = attachKeyBindingJwt)]
  pub fn attach_key_binding_jwt(self, kb_jwt: WasmKeyBindingJwt) -> Self {
    Self(self.0.attach_key_binding_jwt(kb_jwt.0))
  }

  /// Returns the resulting {@link SdJwt} together with all removed disclosures.
  /// ## Errors
  /// - Fails with `Error::MissingKeyBindingJwt` if this {@link SdJwt} requires a key binding but none was provided.
  #[wasm_bindgen]
  pub fn finish(self) -> Result<SdJwtPresentationResult> {
    self
      .0
      .finish()
      .map(|(sd_jwt, disclosures)| SdJwtPresentationResult {
        sd_jwt: WasmSdJwt(sd_jwt),
        disclosures: disclosures.into_iter().map(WasmDisclosure::from).collect(),
      })
      .wasm_result()
  }
}

#[wasm_bindgen(inspectable, getter_with_clone)]
pub struct SdJwtPresentationResult {
  #[wasm_bindgen(js_name = sdJwt)]
  pub sd_jwt: WasmSdJwt,
  pub disclosures: Vec<WasmDisclosure>,
}
