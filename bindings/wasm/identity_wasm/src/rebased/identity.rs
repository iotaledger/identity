// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::rc::Rc;

use identity_iota::iota::rebased::migration::get_identity;
use identity_iota::iota::rebased::migration::CreateIdentity;
use identity_iota::iota::rebased::migration::IdentityBuilder;
use identity_iota::iota::rebased::migration::OnChainIdentity;
use identity_iota::iota::rebased::Error as RebasedError;
use identity_iota::iota::IotaDocument;
use iota_interaction::types::base_types::IotaAddress;
use iota_interaction::types::base_types::ObjectID;
use iota_interaction_ts::bindings::WasmIotaTransactionBlockEffects;
use iota_interaction_ts::core_client::WasmCoreClientReadOnly;
use js_sys::Object;
use product_common::bindings::wasm_error::wasm_error;
use product_common::bindings::wasm_error::Result;
use product_common::bindings::wasm_error::WasmResult;
use product_common::bindings::core_client::WasmManagedCoreClientReadOnly;
use product_common::bindings::transaction::WasmTransactionBuilder;
use product_common::transaction::transaction_builder::Transaction;
use tokio::sync::RwLock;
use wasm_bindgen::prelude::*;

use crate::iota::WasmIotaDocument;
use crate::rebased::proposals::WasmCreateConfigChangeProposal;
use crate::rebased::proposals::WasmCreateUpdateDidProposal;
use crate::rebased::WasmDeleteDelegationToken;

use super::proposals::StringCouple;
use super::proposals::WasmConfigChange;
use super::proposals::WasmCreateSendProposal;
use super::WasmControllerCap;
use super::WasmControllerToken;
use super::WasmDelegationToken;
use super::WasmDelegationTokenRevocation;
use super::WasmIdentityClient;
use super::WasmIotaAddress;

// Helper type for `WasmIdentityBuilder::controllers`.
// Has getters to support `Clone` for serialization
#[derive(Debug)]
#[wasm_bindgen(getter_with_clone)]
pub struct ControllerAndVotingPower(pub WasmIotaAddress, pub u64, pub bool);

#[wasm_bindgen(js_class = ControllerAndVotingPower)]
impl ControllerAndVotingPower {
  #[wasm_bindgen(constructor)]
  pub fn new(address: WasmIotaAddress, voting_power: u64, can_delegate: bool) -> Self {
    Self(address, voting_power, can_delegate)
  }
}

#[wasm_bindgen(js_name = OnChainIdentity)]
#[derive(Clone)]
pub struct WasmOnChainIdentity(pub(crate) Rc<RwLock<OnChainIdentity>>);

#[wasm_bindgen(js_class = OnChainIdentity)]
impl WasmOnChainIdentity {
  #[wasm_bindgen(js_name = getById)]
  pub async fn get_by_id(id: String, client: &WasmCoreClientReadOnly) -> Result<Self> {
    let client = WasmManagedCoreClientReadOnly::from_wasm(client)?;
    let id = id.parse::<ObjectID>().map_err(|e| JsError::new(&e.to_string()))?;

    get_identity(&client, id)
      .await
      .wasm_result()?
      .ok_or_else(|| RebasedError::ObjectLookup(format!("an OnChainIdentity with ID {id} wouldn't be found")))
      .wasm_result()
      .map(WasmOnChainIdentity::new)
  }

  pub(crate) fn new(identity: OnChainIdentity) -> Self {
    Self(Rc::new(RwLock::new(identity)))
  }

  #[wasm_bindgen]
  pub fn id(&self) -> Result<String> {
    Ok(self.0.try_read().wasm_result()?.id().to_string())
  }

  #[wasm_bindgen(js_name = didDocument)]
  pub fn did_document(&self) -> Result<WasmIotaDocument> {
    let inner_doc = self.0.try_read().wasm_result()?.did_document().clone();
    Ok(WasmIotaDocument::from(inner_doc))
  }

  /// Returns whether the {@link IotaDocument} contained in this {@link OnChainIdentity} has been deleted.
  /// Once a DID Document is deleted, it cannot be reactivated.
  ///
  /// When calling {@link OnChainIdentity.did_document} on an Identity whose DID Document
  /// had been deleted, an *empty* and *deactivated* {@link IotaDocument} will be returned.
  #[wasm_bindgen(js_name = hasDeletedDid)]
  pub fn has_deleted_did(&self) -> Result<bool> {
    self
      .0
      .try_read()
      .wasm_result()
      .map(|identity| identity.has_deleted_did())
  }

  #[wasm_bindgen(js_name = isShared)]
  pub fn is_shared(&self) -> Result<bool> {
    Ok(self.0.try_read().wasm_result()?.is_shared())
  }

  #[wasm_bindgen(js_name = getControllerToken)]
  pub async fn get_controller_token(&self, client: &WasmIdentityClient) -> Result<Option<WasmControllerToken>> {
    let maybe_controller_token = self
      .0
      .read()
      .await
      .get_controller_token(&client.0)
      .await
      .wasm_result()?
      .map(WasmControllerToken);
    Ok(maybe_controller_token)
  }

  #[wasm_bindgen(js_name = getControllerTokenForAddress)]
  pub async fn get_controller_token_for_address(
    &self,
    address: &str,
    client: &WasmIdentityClient,
  ) -> Result<Option<WasmControllerToken>> {
    let address = address
      .parse::<IotaAddress>()
      .map_err(|e| JsError::new(&e.to_string()))?;
    let maybe_controller_token = self
      .0
      .read()
      .await
      .get_controller_token_for_address(address, &client.0)
      .await
      .wasm_result()?
      .map(WasmControllerToken);
    Ok(maybe_controller_token)
  }

  #[wasm_bindgen(skip_typescript)] // ts type in custom section below
  pub fn proposals(&self) -> Result<JsValue> {
    let lock = self.0.try_read().wasm_result()?;
    let proposals = lock.proposals();
    serde_wasm_bindgen::to_value(proposals).map_err(wasm_error)
  }

  #[wasm_bindgen(
    js_name = updateDidDocument,
    unchecked_return_type = "TransactionBuilder<CreateProposal<UpdateDid>>",
  )]
  pub fn update_did_document(
    &self,
    updated_doc: &WasmIotaDocument,
    controller_token: &WasmControllerToken,
    expiration_epoch: Option<u64>,
  ) -> WasmTransactionBuilder {
    let create_proposal_tx =
      WasmCreateUpdateDidProposal::new(self, updated_doc.clone(), controller_token.clone(), expiration_epoch);
    WasmTransactionBuilder::new(JsValue::from(create_proposal_tx).unchecked_into())
  }

  #[wasm_bindgen(
    js_name = deactivateDid,
    unchecked_return_type = "TransactionBuilder<CreateProposal<UpdateDid>>",
  )]
  pub fn deactivate_did(
    &self,
    controller_token: &WasmControllerToken,
    expiration_epoch: Option<u64>,
  ) -> WasmTransactionBuilder {
    let create_proposal_tx = WasmCreateUpdateDidProposal::deactivate(self, controller_token.clone(), expiration_epoch);
    WasmTransactionBuilder::new(JsValue::from(create_proposal_tx).unchecked_into())
  }

  #[wasm_bindgen(
    js_name = deleteDid,
    unchecked_return_type = "TransactionBuilder<CreateProposal<UpdateDid>>",
  )]
  pub fn delete_did(
    &self,
    controller_token: &WasmControllerToken,
    expiration_epoch: Option<u64>,
  ) -> WasmTransactionBuilder {
    let tx = WasmCreateUpdateDidProposal::delete(self, controller_token, expiration_epoch);
    WasmTransactionBuilder::new(JsValue::from(tx).unchecked_into())
  }

  #[wasm_bindgen(
    js_name = updateConfig,
    unchecked_return_type = "TransactionBuilder<CreateProposal<ConfigChange>>",
  )]
  pub fn update_config(
    &self,
    controller_token: &WasmControllerToken,
    config: WasmConfigChange,
    expiration_epoch: Option<u64>,
  ) -> WasmTransactionBuilder {
    let tx = JsValue::from(WasmCreateConfigChangeProposal::new(
      self,
      controller_token,
      config,
      expiration_epoch,
    ));
    WasmTransactionBuilder::new(tx.unchecked_into())
  }

  #[wasm_bindgen(
    js_name = sendAssets,
    unchecked_return_type = "TransactionBuilder<CreateProposal<SendAction>>",
  )]
  pub fn send_assets(
    &self,
    controller_token: &WasmControllerToken,
    transfer_map: Vec<StringCouple>,
    expiration_epoch: Option<u64>,
  ) -> Result<WasmTransactionBuilder> {
    let tx = WasmCreateSendProposal::new(self, controller_token, transfer_map, expiration_epoch).wasm_result()?;
    Ok(WasmTransactionBuilder::new(JsValue::from(tx).unchecked_into()))
  }

  #[wasm_bindgen(
    js_name = revokeDelegationToken,
    unchecked_return_type = "TransactionBuilder<DelegationTokenRevocation>",
  )]
  pub fn revoke_delegation_token(
    &self,
    controller_cap: &WasmControllerCap,
    delegation_token: &WasmDelegationToken,
  ) -> Result<WasmDelegationTokenRevocation> {
    WasmDelegationTokenRevocation::new(self, controller_cap, delegation_token, Some(true))
  }

  #[wasm_bindgen(
    js_name = unrevokeDelegationToken,
    unchecked_return_type = "TransactionBuilder<DelegationTokenRevocation>",
  )]
  pub fn unrevoke_delegation_token(
    &self,
    controller_cap: &WasmControllerCap,
    delegation_token: &WasmDelegationToken,
  ) -> Result<WasmDelegationTokenRevocation> {
    WasmDelegationTokenRevocation::new(self, controller_cap, delegation_token, Some(false))
  }

  #[wasm_bindgen(
    js_name = deleteDelegationToken,
    unchecked_return_type = "TransactionBuilder<DeleteDelegationToken>",
  )]
  pub fn delete_delegation_token(&self, delegation_token: WasmDelegationToken) -> Result<WasmDeleteDelegationToken> {
    WasmDeleteDelegationToken::new(self, delegation_token)
  }
}

#[wasm_bindgen(js_name = IdentityBuilder)]
pub struct WasmIdentityBuilder(pub(crate) IdentityBuilder);

#[wasm_bindgen(js_class = IdentityBuilder)]
impl WasmIdentityBuilder {
  #[wasm_bindgen(constructor)]
  pub fn new(did_doc: &WasmIotaDocument) -> Result<WasmIdentityBuilder> {
    let document: IotaDocument = did_doc.0.try_read().unwrap().clone();
    Ok(WasmIdentityBuilder(IdentityBuilder::new(document)))
  }

  pub fn controller(self, address: WasmIotaAddress, voting_power: u64, can_delegate: Option<bool>) -> Result<Self> {
    let can_delegate = can_delegate.unwrap_or(false);
    let address = address.parse().map_err(wasm_error)?;

    let inner_builder = if can_delegate {
      self.0.controller_with_delegation(address, voting_power)
    } else {
      self.0.controller(address, voting_power)
    };

    Ok(Self(inner_builder))
  }

  pub fn threshold(self, threshold: u64) -> Self {
    Self(self.0.threshold(threshold))
  }

  pub fn controllers(self, controllers: Vec<ControllerAndVotingPower>) -> Result<Self> {
    let inner_builder = self.0.controllers_with_delegation(
      controllers
        .into_iter()
        .map(|ControllerAndVotingPower(addr, vp, can_delegate)| {
          Ok((addr.parse().map_err(wasm_error)?, vp, can_delegate))
        })
        .collect::<Result<Vec<_>>>()?,
    );
    Ok(Self(inner_builder))
  }

  #[wasm_bindgen(unchecked_return_type = "TransactionBuilder<CreateIdentity>")]
  pub fn finish(self) -> WasmTransactionBuilder {
    WasmTransactionBuilder::new(JsValue::from(WasmCreateIdentity::new(self)).unchecked_into())
  }
}

#[wasm_bindgen(js_name = CreateIdentity)]
pub struct WasmCreateIdentity(pub(crate) CreateIdentity);

#[wasm_bindgen(js_class = CreateIdentity)]
impl WasmCreateIdentity {
  #[wasm_bindgen(constructor)]
  pub fn new(builder: WasmIdentityBuilder) -> Self {
    Self(CreateIdentity::new(builder.0))
  }

  #[wasm_bindgen(js_name = buildProgrammableTransaction)]
  pub async fn build_programmable_transaction(&self, client: &WasmCoreClientReadOnly) -> Result<Vec<u8>> {
    let managed_client = WasmManagedCoreClientReadOnly::from_wasm(client)?;
    let pt = self
      .0
      .build_programmable_transaction(&managed_client)
      .await
      .wasm_result()?;
    product_common::bindings::wasm_error::WasmResult::wasm_result(bcs::to_bytes(&pt))
  }

  #[wasm_bindgen]
  pub async fn apply(
    self,
    wasm_effects: &WasmIotaTransactionBlockEffects,
    client: &WasmCoreClientReadOnly,
  ) -> Result<WasmOnChainIdentity> {
    let managed_client = WasmManagedCoreClientReadOnly::from_wasm(client)?;
    let mut effects = wasm_effects.clone().into();
    let apply_result = self.0.apply(&mut effects, &managed_client).await;
    let rem_wasm_effects = WasmIotaTransactionBlockEffects::from(&effects);
    Object::assign(wasm_effects, &rem_wasm_effects);

    apply_result.wasm_result().map(WasmOnChainIdentity::new)
  }
}
