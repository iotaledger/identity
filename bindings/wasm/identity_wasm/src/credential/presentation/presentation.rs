// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::core::Context;
use identity_iota::core::Object;
use identity_iota::credential::Presentation;
use identity_iota::credential::PresentationBuilder;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

use crate::common::ArrayString;
use crate::common::MapStringAny;
use crate::credential::ArrayContext;
use crate::credential::ArrayPolicy;
use crate::credential::ArrayRefreshService;
use crate::credential::ArrayUnknownCredential;
use crate::credential::IPresentation;
use crate::credential::UnknownCredential;
use crate::credential::WasmProof;
use crate::credential::WasmUnknownCredentialContainer;
use crate::error::Result;
use crate::error::WasmResult;

/// Represents a bundle of one or more {@link Credential}s.
#[wasm_bindgen(js_name = Presentation, inspectable)]
pub struct WasmPresentation(pub(crate) Presentation<UnknownCredential>);

#[wasm_bindgen(js_class = Presentation)]
impl WasmPresentation {
  /// Returns the base JSON-LD context.
  #[wasm_bindgen(js_name = "BaseContext")]
  pub fn base_context() -> Result<String> {
    match Presentation::<Object>::base_context() {
      Context::Url(url) => Ok(url.to_string()),
      Context::Obj(_) => Err(JsError::new("Presentation.BaseContext should be a single URL").into()),
    }
  }

  /// Returns the base type.
  #[wasm_bindgen(js_name = "BaseType")]
  pub fn base_type() -> String {
    Presentation::<Object>::base_type().to_owned()
  }

  /// Constructs a new presentation.
  #[wasm_bindgen(constructor)]
  pub fn new(values: IPresentation) -> Result<WasmPresentation> {
    let builder: PresentationBuilder<UnknownCredential, Object> =
      PresentationBuilder::<UnknownCredential, Object>::try_from(values)?;
    builder.build().map(Self).wasm_result()
  }

  /// Constructs a new presentation in the Verifiable Credentials Data Model 2.0 format.
  #[wasm_bindgen(js_name = "newV2")]
  pub fn new_v2(values: IPresentation) -> Result<WasmPresentation> {
    let builder: PresentationBuilder<UnknownCredential, Object> =
      PresentationBuilder::<UnknownCredential, Object>::try_from(values)?;
    builder.build_v2().map(Self).wasm_result()
  }

  /// Returns a copy of the JSON-LD context(s) applicable to the presentation.
  #[wasm_bindgen]
  pub fn context(&self) -> Result<ArrayContext> {
    self
      .0
      .context
      .iter()
      .map(JsValue::from_serde)
      .collect::<std::result::Result<js_sys::Array, _>>()
      .wasm_result()
      .map(|value| value.unchecked_into::<ArrayContext>())
  }

  /// Returns a copy of the unique `URI` identifying the presentation.
  #[wasm_bindgen]
  pub fn id(&self) -> Option<String> {
    self.0.id.as_ref().map(|url| url.to_string())
  }

  /// Returns a copy of the URIs defining the type of the presentation.
  #[wasm_bindgen(js_name = "type")]
  pub fn types(&self) -> ArrayString {
    self
      .0
      .types
      .iter()
      .map(|s| s.as_str())
      .map(JsValue::from_str)
      .collect::<js_sys::Array>()
      .unchecked_into::<ArrayString>()
  }

  /// Returns the JWT credentials expressing the claims of the presentation.
  #[wasm_bindgen(js_name = verifiableCredential)]
  pub fn verifiable_credential(&self) -> ArrayUnknownCredential {
    self
      .0
      .verifiable_credential
      .iter()
      .cloned()
      .map(WasmUnknownCredentialContainer::new)
      .map(JsValue::from)
      .collect::<js_sys::Array>()
      .unchecked_into::<ArrayUnknownCredential>()
  }

  /// Returns a copy of the URI of the entity that generated the presentation.
  #[wasm_bindgen]
  pub fn holder(&self) -> String {
    self.0.holder.as_ref().to_string()
  }

  /// Returns a copy of the service(s) used to refresh an expired {@link Credential} in the presentation.
  #[wasm_bindgen(js_name = "refreshService")]
  pub fn refresh_service(&self) -> Result<ArrayRefreshService> {
    self
      .0
      .refresh_service
      .iter()
      .map(JsValue::from_serde)
      .collect::<std::result::Result<js_sys::Array, _>>()
      .wasm_result()
      .map(|value| value.unchecked_into::<ArrayRefreshService>())
  }

  /// Returns a copy of the terms-of-use specified by the presentation holder
  #[wasm_bindgen(js_name = "termsOfUse")]
  pub fn terms_of_use(&self) -> Result<ArrayPolicy> {
    self
      .0
      .terms_of_use
      .iter()
      .map(JsValue::from_serde)
      .collect::<std::result::Result<js_sys::Array, _>>()
      .wasm_result()
      .map(|value| value.unchecked_into::<ArrayPolicy>())
  }

  /// Optional cryptographic proof, unrelated to JWT.
  #[wasm_bindgen]
  pub fn proof(&self) -> Option<WasmProof> {
    self.0.proof.clone().map(WasmProof)
  }

  /// Sets the proof property of the {@link Presentation}.
  ///
  /// Note that this proof is not related to JWT.
  #[wasm_bindgen(js_name = "setProof")]
  pub fn set_proof(&mut self, proof: Option<WasmProof>) {
    self.0.set_proof(proof.map(|wasm_proof| wasm_proof.0))
  }

  /// Returns a copy of the miscellaneous properties on the presentation.
  #[wasm_bindgen]
  pub fn properties(&self) -> Result<MapStringAny> {
    MapStringAny::try_from(&self.0.properties)
  }
}

impl_wasm_json!(WasmPresentation, Presentation);
impl_wasm_clone!(WasmPresentation, Presentation);

impl From<Presentation<UnknownCredential>> for WasmPresentation {
  fn from(presentation: Presentation<UnknownCredential>) -> WasmPresentation {
    Self(presentation)
  }
}
