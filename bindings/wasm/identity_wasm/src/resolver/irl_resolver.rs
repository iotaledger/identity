// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_caip::iota::resolver::Resolver;
use iota_caip::iota::IotaNetwork;
use js_sys::Object;
use wasm_bindgen::prelude::*;

/// A resolver for IOTA Resource Locators (IRLs).
#[wasm_bindgen(js_name = IrlResolver)]
pub struct WasmIrlResolver(Resolver);

#[wasm_bindgen(js_class = IrlResolver)]
impl WasmIrlResolver {
  // Creates a new {@link IrlResolver} instance.
  #[wasm_bindgen(constructor)]
  pub fn new(params: Option<IIrlResolverParams>) -> Result<Self, JsError> {
    let params: IrlResolverParams = serde_wasm_bindgen::from_value(params.unwrap_or_default().into())?;
    let custom_networks = params
      .custom_networks
      .into_iter()
      .map(|CustomNetworkParams { chain_id, endpoint }| {
        let network = IotaNetwork::from_genesis_digest(&chain_id)
          .ok_or_else(|| JsError::new(&format!("Invalid chain ID: {chain_id}")))?;
        Ok((network, endpoint))
      })
      .collect::<Result<Vec<(IotaNetwork, String)>, JsError>>()?;

    Ok(Self(Resolver::new_with_custom_networks(custom_networks)))
  }

  /// Resolves an IOTA Resource Locator (IRL) to its corresponding resource.
  pub async fn resolve(&self, irl: &str) -> Result<JsValue, JsError> {
    let res = self
      .0
      .resolve(irl)
      .await
      .map_err(|e| JsError::new(&format!("{:#}", anyhow::Error::from(e))))?;
    Ok(serde_wasm_bindgen::to_value(&res).expect("a JSON Value can be turned into a JsValue"))
  }
}

#[derive(serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct IrlResolverParams {
  #[serde(default)]
  custom_networks: Vec<CustomNetworkParams>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct CustomNetworkParams {
  chain_id: String,
  endpoint: String,
}

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "IrlResolverParams", extends = Object)]
  #[derive(Default)]
  pub type IIrlResolverParams;
}

#[wasm_bindgen(typescript_custom_section)]
const IRL_PARAMS: &str = r#"
/** Parameters for creating a new {@link IrlResolver} instance. */
export interface IrlResolverParams {
  /** Custom networks to use for resolving IOTA Resource Locators. */
  customNetworks?: CustomNetworkParams[];
}

/** Parameters for defining a custom IOTA network. */
export interface CustomNetworkParams {
  /** An IOTA chain ID. e.g. `mainnet`, `32b2fcb4`.*/
  chainId: string;
  /** The node JSON-RPC endpoint to connect to. */
  endpoint: string;
}
"#;
