// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::common::ArrayString;
use crate::did::WasmService;
use crate::error::Result;
use crate::error::WasmResult;
use identity_iota::core::Object;
use identity_iota::core::OrderedSet;
use identity_iota::core::Url;
use identity_iota::credential::LinkedDomainService;
use identity_iota::did::DIDUrl;
use identity_iota::document::Service;
use proc_typescript::typescript;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

/// A service wrapper for a
/// [Linked Domain Service Endpoint](https://identity.foundation/.well-known/resources/did-configuration/#linked-domain-service-endpoint).
#[wasm_bindgen(js_name = LinkedDomainService, inspectable)]
pub struct WasmLinkedDomainService(LinkedDomainService);

#[wasm_bindgen(js_class = LinkedDomainService)]
impl WasmLinkedDomainService {
  /// Constructs a new {@link LinkedDomainService} that wraps a spec compliant [Linked Domain Service Endpoint](https://identity.foundation/.well-known/resources/did-configuration/#linked-domain-service-endpoint).
  ///
  /// Domain URLs must include the `https` scheme in order to pass the domain linkage validation.
  #[wasm_bindgen(constructor)]
  pub fn new(options: ILinkedDomainService) -> Result<WasmLinkedDomainService> {
    let ILinkedDomainServiceHelper {
      id,
      domains,
      properties,
    } = options.into_serde::<ILinkedDomainServiceHelper>().wasm_result()?;
    Ok(Self(LinkedDomainService::new(id, domains, properties).wasm_result()?))
  }

  /// Returns the domains contained in the Linked Domain Service.
  #[wasm_bindgen]
  pub fn domains(&self) -> ArrayString {
    self
      .0
      .domains()
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

  /// Creates a new {@link LinkedDomainService} from a {@link Service}.
  ///
  /// # Error
  ///
  /// Errors if `service` is not a valid Linked Domain Service.
  #[wasm_bindgen(js_name = fromService)]
  pub fn from_service(service: &WasmService) -> Result<WasmLinkedDomainService> {
    Ok(Self(LinkedDomainService::try_from(service.0.clone()).wasm_result()?))
  }

  /// Returns `true` if a {@link Service} is a valid Linked Domain Service.
  #[wasm_bindgen(js_name = isValid)]
  pub fn is_valid(service: &WasmService) -> bool {
    LinkedDomainService::check_structure(&service.0).is_ok()
  }
}

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "ILinkedDomainService")]
  pub type ILinkedDomainService;
}

/// Fields for constructing a new {@link LinkedDomainService}.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[typescript(name = "ILinkedDomainService", readonly, optional)]
struct ILinkedDomainServiceHelper {
  /// Service id.
  #[typescript(optional = false, type = "DIDUrl")]
  id: DIDUrl,
  /// A unique URI that may be used to identify the {@link Credential}.
  #[typescript(optional = false, type = "string[]")]
  domains: OrderedSet<Url>,
  /// Miscellaneous properties.
  #[serde(flatten)]
  #[typescript(optional = false, name = "[properties: string]", type = "unknown")]
  properties: Object,
}

impl_wasm_clone!(WasmLinkedDomainService, LinkedDomainService);
