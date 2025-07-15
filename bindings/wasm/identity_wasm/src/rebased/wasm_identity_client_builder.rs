// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use wasm_bindgen::prelude::*;

use identity_iota::iota_interaction::types::base_types::IotaAddress;
use iota_interaction_ts::bindings::WasmIotaClient;
use iota_interaction_ts::iota_client_ts_sdk::IotaClientTsSdk;

use super::client_dummy::IdentityClientBuilder;

use crate::error::wasm_error;
use crate::error::Result;

use super::types::WasmObjectID;
use super::WasmIotaAddress;
use super::WasmIdentityClient;

#[derive(Default)]
#[wasm_bindgen(js_name = IdentityClientBuilder)]
pub struct WasmIdentityClientBuilder(pub(crate) IdentityClientBuilder<IotaClientTsSdk>);

#[wasm_bindgen(js_class = IdentityClientBuilder)]
impl WasmIdentityClientBuilder {
  #[wasm_bindgen(js_name = identityIotaPackageId)]
  pub fn identity_iota_package_id(self, value: WasmObjectID) -> Self {
    Self(
      self.0.identity_iota_package_id(
        value
          .parse()
          .expect("failed to parse identity_iota_package_id value into ObjectID"),
      ),
    )
  }

  #[wasm_bindgen(js_name = senderPublicKey)]
  pub fn sender_public_key(self, value: &[u8]) -> Self {
    Self(self.0.sender_public_key(value))
  }

  #[wasm_bindgen(js_name = senderAddress)]
  pub fn sender_address(self, value: WasmIotaAddress) -> Self {
    Self(
      self
        .0
        .sender_address(&IotaAddress::from_str(&value).expect("failed to parse sender_address value into IotaAddress")),
    )
  }

  #[wasm_bindgen(js_name = iotaClient)]
  pub fn iota_client(self, value: WasmIotaClient) -> Self {
    Self(
      self
        .0
        .iota_client(IotaClientTsSdk::new(value).expect("IotaClientTsSdk could not be initialized")),
    )
  }

  #[wasm_bindgen(js_name = networkName)]
  pub fn network_name(self, value: &str) -> Self {
    Self(self.0.network_name(value))
  }

  pub fn build(self) -> Result<WasmIdentityClient> {
    Ok(WasmIdentityClient(self.0.build().map_err(wasm_error)?))
  }
}
