// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::WasmMethodData;
use super::WasmMethodType;
use crate::common::MapStringAny;
use crate::did::WasmCoreDID;
use crate::did::WasmDIDUrl;
use crate::error::Result;
use crate::error::WasmResult;
use identity_iota::core::Object;
use identity_iota::did::CoreDID;
use identity_iota::verification::VerificationMethod;
use wasm_bindgen::prelude::*;

use crate::did::IToCoreDID;
use crate::jose::WasmJwk;

/// A DID Document Verification Method.
#[wasm_bindgen(js_name = VerificationMethod, inspectable)]
pub struct WasmVerificationMethod(pub(crate) VerificationMethod);

#[wasm_bindgen(js_class = VerificationMethod)]
impl WasmVerificationMethod {
  /// Creates a new {@link VerificationMethod} from the given `did` and {@link Jwk}. If `fragment` is not given
  /// the `kid` value of the given `key` will be used, if present, otherwise an error is returned.
  ///
  /// ### Recommendations
  /// The following recommendations are essentially taken from the `publicKeyJwk` description from the [DID specification](https://www.w3.org/TR/did-core/#dfn-publickeyjwk):
  /// - It is recommended that verification methods that use `Jwks` to represent their public keys use the value of
  ///   `kid` as their fragment identifier. This is
  /// done automatically if `None` is passed in as the fragment.
  /// - It is recommended that {@link Jwk} kid values are set to the public key fingerprint.
  #[wasm_bindgen(js_name = newFromJwk)]
  pub fn new_from_jwk(did: &IToCoreDID, key: &WasmJwk, fragment: Option<String>) -> Result<WasmVerificationMethod> {
    VerificationMethod::new_from_jwk(CoreDID::from(did), key.0.clone(), fragment.as_deref())
      .map(Self)
      .wasm_result()
  }

  /// Create a custom {@link VerificationMethod}.
  #[wasm_bindgen(constructor)]
  pub fn new(
    id: &WasmDIDUrl,
    controller: &WasmCoreDID,
    type_: &WasmMethodType,
    data: &WasmMethodData,
  ) -> Result<WasmVerificationMethod> {
    VerificationMethod::builder(Object::new())
      .type_(type_.0.clone())
      .data(data.0.clone())
      .controller(controller.0.clone())
      .id(id.0.clone())
      .build()
      .map(Self)
      .wasm_result()
  }

  /// Returns a copy of the {@link DIDUrl} of the {@link VerificationMethod}'s `id`.
  #[wasm_bindgen]
  pub fn id(&self) -> WasmDIDUrl {
    WasmDIDUrl::from(self.0.id().clone())
  }

  /// Sets the id of the {@link VerificationMethod}.
  #[wasm_bindgen(js_name = setId)]
  pub fn set_id(&mut self, id: &WasmDIDUrl) -> Result<()> {
    self.0.set_id(id.0.clone()).wasm_result()?;
    Ok(())
  }

  /// Returns a copy of the `controller` `DID` of the {@link VerificationMethod}.
  #[wasm_bindgen]
  pub fn controller(&self) -> WasmCoreDID {
    WasmCoreDID::from(self.0.controller().clone())
  }

  /// Sets the `controller` `DID` of the {@link VerificationMethod} object.
  #[wasm_bindgen(js_name = setController)]
  pub fn set_controller(&mut self, did: &WasmCoreDID) {
    *self.0.controller_mut() = did.0.clone();
  }

  /// Returns a copy of the {@link VerificationMethod} type.
  #[wasm_bindgen(js_name = type)]
  pub fn type_(&self) -> WasmMethodType {
    WasmMethodType::from(self.0.type_().clone())
  }

  /// Sets the {@link VerificationMethod} type.
  #[wasm_bindgen(js_name = setType)]
  pub fn set_type(&mut self, type_: &WasmMethodType) {
    *self.0.type_mut() = type_.0.clone();
  }

  /// Returns a copy of the {@link VerificationMethod} public key data.
  #[wasm_bindgen]
  pub fn data(&self) -> WasmMethodData {
    WasmMethodData::from(self.0.data().clone())
  }

  /// Sets {@link VerificationMethod} public key data.
  #[wasm_bindgen(js_name = setData)]
  pub fn set_data(&mut self, data: &WasmMethodData) {
    *self.0.data_mut() = data.0.clone();
  }

  /// Get custom properties of the Verification Method.
  #[wasm_bindgen]
  pub fn properties(&self) -> Result<MapStringAny> {
    MapStringAny::try_from(self.0.properties())
  }

  /// Adds a custom property to the Verification Method.
  /// If the value is set to `null`, the custom property will be removed.
  ///
  /// ### WARNING
  /// This method can overwrite existing properties like `id` and result
  /// in an invalid Verification Method.
  #[wasm_bindgen(js_name = setPropertyUnchecked)]
  pub fn set_property_unchecked(&mut self, key: String, value: &JsValue) -> Result<()> {
    let value: Option<serde_json::Value> = value.into_serde().wasm_result()?;
    match value {
      Some(value) => {
        self.0.properties_mut().insert(key, value);
      }
      None => {
        self.0.properties_mut().remove(&key);
      }
    }
    Ok(())
  }
}

impl_wasm_json!(WasmVerificationMethod, VerificationMethod);
impl_wasm_clone!(WasmVerificationMethod, VerificationMethod);

impl From<VerificationMethod> for WasmVerificationMethod {
  fn from(method: VerificationMethod) -> Self {
    Self(method)
  }
}
