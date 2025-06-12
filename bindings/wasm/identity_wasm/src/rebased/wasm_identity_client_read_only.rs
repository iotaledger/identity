// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::rc::Rc;
use std::str::FromStr;

use identity_iota::iota::rebased::client::IdentityClientReadOnly;
use identity_iota::iota::rebased::migration::Identity;
use identity_iota::iota_interaction::types::base_types::ObjectID;
use iota_interaction_ts::bindings::WasmIotaClient;
use product_common::core_client::CoreClientReadOnly as _;
use wasm_bindgen::prelude::*;

use super::WasmObjectID;
use super::WasmOnChainIdentity;
use crate::iota::IotaDocumentLock;
use crate::iota::WasmIotaDID;
use crate::iota::WasmIotaDocument;

#[wasm_bindgen(js_name = Identity)]
pub struct IdentityContainer(pub(crate) Identity);
#[wasm_bindgen(js_class = Identity)]
impl IdentityContainer {
  /// TODO: check if we can actually do this like this w/o consuming the container on the 1st try
  /// TODO: add support for unmigrated aliases
  #[wasm_bindgen(js_name = toFullFledged)]
  pub fn to_full_fledged(&self) -> Option<WasmOnChainIdentity> {
    match self.0.clone() {
      Identity::FullFledged(v) => Some(WasmOnChainIdentity::new(v)),
      _ => None,
    }
  }

  // #[wasm_bindgen(js_name = toLegacy)]
  // pub fn to_legacy(self) -> Option<UnmigratedAlias> {
  //   match self.0 {
  //     Identity::Legacy (v) => Some(v),
  //     _ => None,
  //   }
  // }
}

/// A client to interact with identities on the IOTA chain.
///
/// Used for read operations, so does not need an account and signing capabilities.
/// If you want to write to the chain, use {@link IdentityClient}.
#[derive(Clone)]
#[wasm_bindgen(js_name = IdentityClientReadOnly)]
pub struct WasmIdentityClientReadOnly(pub(crate) IdentityClientReadOnly);

// builder related functions
#[wasm_bindgen(js_class = IdentityClientReadOnly)]
impl WasmIdentityClientReadOnly {
  #[wasm_bindgen(constructor, skip_typescript)]  
  pub fn _new() -> JsError {
    JsError::new("cannot build an instance of `IdentityClientReadOnly` through its default sync constructor. Use `IdentityClientReadOnly.create` instead.")
  }

  #[wasm_bindgen(js_name = create)]
  pub async fn new(iota_client: WasmIotaClient) -> Result<WasmIdentityClientReadOnly, JsError> {
    let inner_client = IdentityClientReadOnly::new(iota_client).await?;
    Ok(WasmIdentityClientReadOnly(inner_client))
  }

  #[wasm_bindgen(js_name = createWithPkgId)]
  pub async fn new_new_with_pkg_id(
    iota_client: WasmIotaClient,
    iota_identity_pkg_id: String,
  ) -> Result<WasmIdentityClientReadOnly, JsError> {
    let inner_client =
      IdentityClientReadOnly::new_with_pkg_id(iota_client, ObjectID::from_str(&iota_identity_pkg_id)?).await?;
    Ok(WasmIdentityClientReadOnly(inner_client))
  }

  #[wasm_bindgen(js_name = packageId)]
  pub fn package_id(&self) -> String {
    self.0.package_id().to_string()
  }

  #[wasm_bindgen(js_name = packageHistory)]
  pub fn package_history(&self) -> Vec<String> {
    self
      .0
      .package_history()
      .into_iter()
      .map(|pkg_id| pkg_id.to_string())
      .collect()
  }

  #[wasm_bindgen(js_name = iotaClient)]
  pub fn iota_client(&self) -> WasmIotaClient {
    (*self.0).clone().into_inner()
  }

  #[wasm_bindgen]
  pub fn network(&self) -> String {
    self.0.network().to_string()
  }

  #[wasm_bindgen(js_name = resolveDid)]
  pub async fn resolve_did(&self, did: &WasmIotaDID) -> Result<WasmIotaDocument, JsError> {
    let document = self.0.resolve_did(&did.0).await.map_err(JsError::from)?;
    Ok(WasmIotaDocument(Rc::new(IotaDocumentLock::new(document))))
  }

  #[wasm_bindgen(js_name = getIdentity)]
  pub async fn get_identity(&self, object_id: WasmObjectID) -> Result<IdentityContainer, JsError> {
    let inner_value = self
      .0
      .get_identity(object_id.parse()?)
      .await
      .map_err(|err| JsError::new(&format!("failed to resolve identity by object id; {err:?}")))?;
    Ok(IdentityContainer(inner_value))
  }
}
