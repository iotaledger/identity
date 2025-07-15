// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use wasm_bindgen::prelude::*;

use super::WasmDidResolutionHandler;

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "ResolutionHandlers")]
  pub(crate) type MapResolutionHandler;

  #[wasm_bindgen(typescript_type = "ResolverConfig")]
  pub type ResolverConfig;

  #[wasm_bindgen(method, getter)]
  pub(crate) fn client(this: &ResolverConfig) -> Option<WasmDidResolutionHandler>;

  #[wasm_bindgen(method, getter)]
  pub(crate) fn handlers(this: &ResolverConfig) -> Option<MapResolutionHandler>;
}

// Workaround because JSDocs does not support arrows (=>) while TS does not support the "function" word in type
// definitions (which would be accepted by JSDocs).
#[wasm_bindgen(typescript_custom_section)]
const HANDLERS: &'static str =
  "export type ResolutionHandlers = Map<string, (did: string) => Promise<CoreDocument | IToCoreDocument>>;";

#[wasm_bindgen(typescript_custom_section)]
const TS_RESOLVER_CONFIG: &'static str = r#"
/**
 * Configurations for the {@link Resolver}.
 */
export type ResolverConfig = {
    /**
     * Client for resolving DIDs of the iota method, usually an {@link IdentityClient} or an {@link IdentityClientReadOnly}
     */
    client?: WasmDidResolutionHandler,

    /**
     * Handlers for resolving DIDs from arbitrary DID methods. 
     * 
     * The keys to the map are expected to match the method name and the values are asynchronous functions returning DID documents. 
     * 
     * Note that if a `client` is given the key "iota" may NOT be present in this map. 
     */
    handlers?: Map<string, (did: string) => Promise<CoreDocument | IToCoreDocument>>
};
"#;
