// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::core::OneOrMany;
use identity_iota::did::DIDUrl;
use identity_iota::document::Service;
use identity_iota::document::ServiceEndpoint;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

use crate::common::deserialize_map_or_any;
use crate::common::ArrayString;
use crate::common::MapStringAny;
use crate::did::WasmDIDUrl;
use crate::error::Result;
use crate::error::WasmResult;

/// A DID Document Service used to enable trusted interactions associated with a DID subject.
#[wasm_bindgen(js_name = Service, inspectable)]
pub struct WasmService(pub(crate) Service);

#[wasm_bindgen(js_class = Service)]
impl WasmService {
  #[wasm_bindgen(constructor)]
  pub fn new(service: IService) -> Result<WasmService> {
    let id: DIDUrl = service.id().into_serde().wasm_result()?;

    let base_service: &IService = service.as_ref();
    let types: OneOrMany<String> = service.type_().into_serde().wasm_result()?;
    let service_endpoint: ServiceEndpoint = deserialize_map_or_any(&base_service.service_endpoint())?;
    let properties: Option<identity_iota::core::Object> = deserialize_map_or_any(&base_service.properties())?;

    Service::builder(properties.unwrap_or_default())
      .id(id)
      .types(types)
      .service_endpoint(service_endpoint)
      .build()
      .map(WasmService)
      .wasm_result()
  }

  /// Returns a copy of the {@link Service} id.
  #[wasm_bindgen]
  pub fn id(&self) -> WasmDIDUrl {
    WasmDIDUrl::from(self.0.id().clone())
  }

  /// Returns a copy of the {@link Service} type.
  #[wasm_bindgen(js_name = type)]
  pub fn type_(&self) -> ArrayString {
    self
      .0
      .type_()
      .iter()
      .cloned()
      .map(JsValue::from)
      .collect::<js_sys::Array>()
      .unchecked_into::<ArrayString>()
  }

  /// Returns a copy of the {@link Service} endpoint.
  #[wasm_bindgen(js_name = serviceEndpoint)]
  pub fn service_endpoint(&self) -> UServiceEndpoint {
    UServiceEndpoint::from(self.0.service_endpoint())
  }

  /// Returns a copy of the custom properties on the {@link Service}.
  #[wasm_bindgen]
  pub fn properties(&self) -> Result<MapStringAny> {
    MapStringAny::try_from(self.0.properties())
  }
}

impl_wasm_json!(WasmService, Service);
impl_wasm_clone!(WasmService, Service);

impl From<Service> for WasmService {
  fn from(service: Service) -> Self {
    Self(service)
  }
}

impl From<ServiceEndpoint> for UServiceEndpoint {
  fn from(endpoint: ServiceEndpoint) -> Self {
    UServiceEndpoint::from(&endpoint)
  }
}

impl From<&ServiceEndpoint> for UServiceEndpoint {
  fn from(endpoint: &ServiceEndpoint) -> Self {
    match endpoint {
      // string
      ServiceEndpoint::One(url) => JsValue::from_str(url.as_str()).unchecked_into::<UServiceEndpoint>(),
      // string[]
      ServiceEndpoint::Set(set) => set
        .iter()
        .map(|url| JsValue::from_str(url.as_str()))
        .collect::<js_sys::Array>()
        .unchecked_into::<UServiceEndpoint>(),
      // Map<string, string[]>
      ServiceEndpoint::Map(map) => {
        let js_map: js_sys::Map = js_sys::Map::new();
        for (key, urls) in map.into_iter() {
          js_map.set(
            &JsValue::from_str(key.as_str()),
            &urls
              .iter()
              .map(|url| JsValue::from_str(url.as_str()))
              .collect::<js_sys::Array>(),
          );
        }
        js_map.unchecked_into::<UServiceEndpoint>()
      }
    }
  }
}

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "string | string[] | Map<string, string[]>")]
  pub type UServiceEndpoint;
}

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "IService")]
  pub type IService;

  #[wasm_bindgen(method, getter)]
  pub fn id(this: &IService) -> JsValue;

  #[wasm_bindgen(method, getter, js_name = type)]
  pub fn type_(this: &IService) -> JsValue;

  #[wasm_bindgen(method, getter, js_name = serviceEndpoint)]
  pub fn service_endpoint(this: &IService) -> JsValue;

  #[wasm_bindgen(method, getter)]
  pub fn properties(this: &IService) -> JsValue;
}

#[wasm_bindgen(typescript_custom_section)]
const I_SERVICE: &'static str = r#"
/**
 * Base {@link Service} properties.
 */
interface IService {
  /**
   * Identifier of the service.
   *
   * Must be a valid DIDUrl with a fragment.
   */
    readonly id: DIDUrl | string;

    /**
     * Type of service.
     *
     * E.g. "LinkedDomains".
     */
    readonly type: string | string[];

    /**
     * A URL, set of URLs, or map of URL sets.
     *
     * NOTE: throws an error if any entry is not a valid URL string. List entries must be unique.
     */
    readonly serviceEndpoint: string | string[] | Map<string, string[]> | Record<string, string[]>;

    /**
     * Additional custom properties to embed in the service.
     *
     * WARNING: entries may overwrite existing fields and result in invalid documents.
     */
    readonly properties?: Map<string, any> | Record<string, any>;
}"#;
