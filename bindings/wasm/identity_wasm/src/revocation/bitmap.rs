// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;

use identity_iota::credential::RevocationBitmap;
use wasm_bindgen::prelude::*;

use crate::did::WasmDIDUrl;
use crate::did::WasmService;
use crate::error::Result;
use crate::error::WasmError;
use crate::error::WasmResult;

/// A compressed bitmap for managing credential revocation.
#[wasm_bindgen(js_name = RevocationBitmap, inspectable)]
pub struct WasmRevocationBitmap(pub(crate) RevocationBitmap);

#[allow(clippy::new_without_default)]
#[wasm_bindgen(js_class = RevocationBitmap)]
impl WasmRevocationBitmap {
  /// Creates a new {@link RevocationBitmap} instance.
  #[wasm_bindgen(constructor)]
  pub fn new() -> Self {
    WasmRevocationBitmap(RevocationBitmap::new())
  }

  /// The name of the service type.
  #[wasm_bindgen(js_name = type)]
  pub fn type_() -> String {
    RevocationBitmap::TYPE.to_owned()
  }

  /// Returns `true` if the credential at the given `index` is revoked.
  #[wasm_bindgen(js_name = isRevoked)]
  pub fn is_revoked(&self, index: u32) -> bool {
    self.0.is_revoked(index)
  }

  /// Mark the given index as revoked.
  ///
  /// Returns true if the index was absent from the set.
  #[wasm_bindgen]
  pub fn revoke(&mut self, index: u32) -> bool {
    self.0.revoke(index)
  }

  /// Mark the index as not revoked.
  ///
  /// Returns true if the index was present in the set.
  #[wasm_bindgen]
  pub fn unrevoke(&mut self, index: u32) -> bool {
    self.0.unrevoke(index)
  }

  /// Returns the number of revoked credentials.
  #[wasm_bindgen]
  #[allow(clippy::len_without_is_empty)]
  pub fn len(&self) -> Result<u32> {
    u32::try_from(self.0.len())
      .map_err(|err| WasmError::new(Cow::Borrowed("TryFromIntError"), Cow::Owned(err.to_string())).into())
  }

  /// Return a `Service` with:
  /// - the service's id set to `serviceId`,
  /// - of type `RevocationBitmap2022`,
  /// - and with the bitmap embedded in a data url in the service's endpoint.
  #[wasm_bindgen(js_name = toService)]
  #[allow(non_snake_case)]
  pub fn to_service(&self, serviceId: &WasmDIDUrl) -> Result<WasmService> {
    self
      .0
      .to_service(serviceId.0.clone())
      .map(WasmService::from)
      .wasm_result()
  }

  /// Try to construct a {@link RevocationBitmap} from a service
  /// if it is a valid Revocation Bitmap Service.
  #[wasm_bindgen(js_name = fromEndpoint)]
  pub fn from_service(service: &WasmService) -> Result<WasmRevocationBitmap> {
    RevocationBitmap::try_from(&service.0).map(Self).wasm_result()
  }
}

impl From<RevocationBitmap> for WasmRevocationBitmap {
  fn from(revocation_list: RevocationBitmap) -> Self {
    WasmRevocationBitmap(revocation_list)
  }
}

impl From<WasmRevocationBitmap> for RevocationBitmap {
  fn from(revocation_list: WasmRevocationBitmap) -> Self {
    revocation_list.0
  }
}
