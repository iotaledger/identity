// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::common::ArrayString;
use crate::did::WasmService;
use crate::error::Result;
use crate::error::WasmResult;
use identity_iota::core::Object;
use identity_iota::core::OneOrSet;
use identity_iota::core::Url;
use identity_iota::credential::LinkedVerifiablePresentationService;
use identity_iota::did::DIDUrl;
use identity_iota::document::Service;
use proc_typescript::typescript;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

/// A service wrapper for a [Linked Verifiable Presentation Service Endpoint](https://identity.foundation/linked-vp/#linked-verifiable-presentation-service-endpoint).
#[wasm_bindgen(js_name = LinkedVerifiablePresentationService, inspectable)]
pub struct WasmLinkedVerifiablePresentationService(LinkedVerifiablePresentationService);

/// A service wrapper for a [Linked Verifiable Presentation Service Endpoint](https://identity.foundation/linked-vp/#linked-verifiable-presentation-service-endpoint).
#[wasm_bindgen(js_class = LinkedVerifiablePresentationService)]
impl WasmLinkedVerifiablePresentationService {
  /// Constructs a new {@link LinkedVerifiablePresentationService} that wraps a spec compliant [Linked Verifiable Presentation Service Endpoint](https://identity.foundation/linked-vp/#linked-verifiable-presentation-service-endpoint).
  #[wasm_bindgen(constructor)]
  pub fn new(options: ILinkedVerifiablePresentationService) -> Result<WasmLinkedVerifiablePresentationService> {
    let ILinkedVerifiablePresentationServiceHelper {
      id,
      linked_vp,
      properties,
    } = options
      .into_serde::<ILinkedVerifiablePresentationServiceHelper>()
      .wasm_result()?;
    Ok(Self(
      LinkedVerifiablePresentationService::new(id, linked_vp.into_vec(), properties).wasm_result()?,
    ))
  }

  /// Returns the domains contained in the Linked Verifiable Presentation Service.
  #[wasm_bindgen(js_name = verifiablePresentationUrls)]
  pub fn vp_urls(&self) -> ArrayString {
    self
      .0
      .verifiable_presentation_urls()
      .iter()
      .map(|url| url.to_string())
      .map(JsValue::from)
      .collect::<js_sys::Array>()
      .unchecked_into::<ArrayString>()
  }

  /// Returns the inner service which can be added to a DID Document.
  #[wasm_bindgen(js_name = toService)]
  pub fn to_service(&self) -> WasmService {
    let service: Service = self.0.clone().into();
    WasmService(service)
  }

  /// Creates a new {@link LinkedVerifiablePresentationService} from a {@link Service}.
  ///
  /// # Error
  ///
  /// Errors if `service` is not a valid Linked Verifiable Presentation Service.
  #[wasm_bindgen(js_name = fromService)]
  pub fn from_service(service: &WasmService) -> Result<WasmLinkedVerifiablePresentationService> {
    Ok(Self(
      LinkedVerifiablePresentationService::try_from(service.0.clone()).wasm_result()?,
    ))
  }

  /// Returns `true` if a {@link Service} is a valid Linked Verifiable Presentation Service.
  #[wasm_bindgen(js_name = isValid)]
  pub fn is_valid(service: &WasmService) -> bool {
    LinkedVerifiablePresentationService::check_structure(&service.0).is_ok()
  }
}

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "ILinkedVerifiablePresentationService")]
  pub type ILinkedVerifiablePresentationService;
}

/// Fields for constructing a new {@link LinkedVerifiablePresentationService}.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[typescript(name = "ILinkedVerifiablePresentationService", readonly, optional)]
struct ILinkedVerifiablePresentationServiceHelper {
  /// Service id.
  #[typescript(optional = false, type = "DIDUrl")]
  id: DIDUrl,
  /// A unique URI that may be used to identify the {@link Credential}.
  #[typescript(optional = false, type = "string | string[]")]
  linked_vp: OneOrSet<Url>,
  /// Miscellaneous properties.
  #[serde(flatten)]
  #[typescript(optional = false, name = "[properties: string]", type = "unknown")]
  properties: Object,
}

impl_wasm_clone!(
  WasmLinkedVerifiablePresentationService,
  LinkedVerifiablePresentationService
);
impl_wasm_json!(
  WasmLinkedVerifiablePresentationService,
  LinkedVerifiablePresentationService
);
