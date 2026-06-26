// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::collections::HashSet;
use std::rc::Rc;

use identity_iota::iota::rebased::migration::Proposal;
use identity_iota::iota::rebased::proposals::ConfigChange;
use identity_iota::iota::rebased::proposals::ProposalResult;
use identity_iota::iota::rebased::proposals::ProposalT;
use iota_interaction_ts::bindings::WasmIotaTransactionBlockEffects;
use iota_interaction_ts::core_client::WasmCoreClientReadOnly;
use js_sys::Object;
use product_common::bindings::core_client::WasmManagedCoreClientReadOnly;
use product_common::transaction::transaction_builder::Transaction;
use tokio::sync::RwLock;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::prelude::JsCast;
use wasm_bindgen::JsValue;

use super::MapStringNumber;
use super::StringSet;
use crate::error::Result;
use crate::error::WasmResult;
use crate::rebased::WasmControllerToken;
use crate::rebased::WasmOnChainIdentity;
use product_common::bindings::transaction::WasmTransactionBuilder;

#[wasm_bindgen(js_name = ConfigChange, inspectable, getter_with_clone)]
pub struct WasmConfigChange {
  pub threshold: Option<u64>,
  #[wasm_bindgen(js_name = controllersToAdd)]
  pub controllers_to_add: Option<MapStringNumber>,
  #[wasm_bindgen(js_name = controllersToRemove)]
  pub controllers_to_remove: Option<StringSet>,
  #[wasm_bindgen(js_name = controllersToUpdate)]
  pub controllers_to_update: Option<MapStringNumber>,
}

impl TryFrom<ConfigChange> for WasmConfigChange {
  type Error = JsValue;
  fn try_from(value: ConfigChange) -> std::result::Result<Self, Self::Error> {
    let threshold = value.threshold();
    let controllers_to_add = if value.controllers_to_add().is_empty() {
      None
    } else {
      Some(value.controllers_to_add().try_into()?)
    };
    let controllers_to_remove = if value.controllers_to_remove().is_empty() {
      None
    } else {
      Some(value.controllers_to_remove().try_into()?)
    };
    let controllers_to_update = if value.controllers_to_update().is_empty() {
      None
    } else {
      Some(value.controllers_to_update().try_into()?)
    };

    Ok(Self {
      threshold,
      controllers_to_add,
      controllers_to_remove,
      controllers_to_update,
    })
  }
}

#[wasm_bindgen(js_name = ConfigChangeProposal)]
#[derive(Clone)]
pub struct WasmConfigChangeProposal(pub(crate) Rc<RwLock<Proposal<ConfigChange>>>);

#[wasm_bindgen(js_class = ConfigChangeProposal)]
impl WasmConfigChangeProposal {
  fn new(proposal: Proposal<ConfigChange>) -> Self {
    Self(Rc::new(RwLock::new(proposal)))
  }

  #[wasm_bindgen(getter)]
  pub fn id(&self) -> Result<String> {
    self
      .0
      .try_read()
      .wasm_result()
      .map(|proposal| proposal.id().to_string())
  }

  #[wasm_bindgen(getter)]
  pub fn action(&self) -> Result<WasmConfigChange> {
    self
      .0
      .try_read()
      .wasm_result()
      .and_then(|proposal| proposal.action().clone().try_into())
  }

  #[wasm_bindgen(getter)]
  pub fn expiration_epoch(&self) -> Result<Option<u64>> {
    self
      .0
      .try_read()
      .wasm_result()
      .map(|proposal| proposal.expiration_epoch())
  }

  #[wasm_bindgen(getter)]
  pub fn votes(&self) -> Result<u64> {
    self.0.try_read().wasm_result().map(|proposal| proposal.votes())
  }

  #[wasm_bindgen(getter)]
  pub fn voters(&self) -> Result<StringSet> {
    let js_set = self
      .0
      .try_read()
      .wasm_result()?
      .voters()
      .iter()
      .map(ToString::to_string)
      .map(js_sys::JsString::from)
      .fold(js_sys::Set::default(), |set, value| {
        set.add(&value);
        set
      })
      .unchecked_into();

    Ok(js_set)
  }

  #[wasm_bindgen(unchecked_return_type = "TransactionBuilder<ApproveProposal>")]
  pub fn approve(
    &self,
    identity: &WasmOnChainIdentity,
    controller_token: &WasmControllerToken,
  ) -> WasmTransactionBuilder {
    let tx = JsValue::from(WasmApproveConfigChangeProposal::new(self, identity, controller_token));
    WasmTransactionBuilder::new(tx.unchecked_into())
  }

  #[wasm_bindgen(
    js_name = intoTx,
    unchecked_return_type = "TransactionBuilder<ExecuteProposal<ConfigChange>>",
  )]
  pub fn into_tx(
    self,
    identity: &WasmOnChainIdentity,
    controller_token: &WasmControllerToken,
  ) -> WasmTransactionBuilder {
    let tx = JsValue::from(WasmExecuteConfigChangeProposal::new(self, identity, controller_token));
    WasmTransactionBuilder::new(tx.unchecked_into())
  }
}

#[wasm_bindgen(js_name = ApproveConfigChangeProposal)]
pub struct WasmApproveConfigChangeProposal {
  proposal: WasmConfigChangeProposal,
  identity: WasmOnChainIdentity,
  controller_token: WasmControllerToken,
}

#[wasm_bindgen(js_class = ApproveConfigChangeProposal)]
impl WasmApproveConfigChangeProposal {
  fn new(
    proposal: &WasmConfigChangeProposal,
    identity: &WasmOnChainIdentity,
    controller_token: &WasmControllerToken,
  ) -> Self {
    Self {
      proposal: proposal.clone(),
      identity: identity.clone(),
      controller_token: controller_token.clone(),
    }
  }

  #[wasm_bindgen(js_name = buildProgrammableTransaction)]
  pub async fn build_programmable_transaction(&self, client: &WasmCoreClientReadOnly) -> Result<Vec<u8>> {
    let managed_client = WasmManagedCoreClientReadOnly::from_wasm(client)?;
    let mut proposal = self.proposal.0.write().await;
    let identity = self.identity.0.read().await;

    let tx = proposal
      .approve(&identity, &self.controller_token.0)
      .wasm_result()?
      .into_inner();
    let ptb = tx.build_programmable_transaction(&managed_client).await.wasm_result()?;
    bcs::to_bytes(&ptb).wasm_result()
  }

  #[wasm_bindgen]
  pub async fn apply(
    &self,
    wasm_effects: &WasmIotaTransactionBlockEffects,
    client: &WasmCoreClientReadOnly,
  ) -> Result<()> {
    let managed_client = WasmManagedCoreClientReadOnly::from_wasm(client)?;
    let mut proposal = self.proposal.0.write().await;
    let identity = self.identity.0.read().await;
    let tx = proposal
      .approve(&identity, &self.controller_token.0)
      .wasm_result()?
      .into_inner();
    let mut effects = wasm_effects.clone().into();
    let apply_result = tx.apply(&mut effects, &managed_client).await;
    let wasm_rem_effects = WasmIotaTransactionBlockEffects::from(&effects);
    Object::assign(wasm_effects, &wasm_rem_effects);

    apply_result.wasm_result()
  }
}

#[wasm_bindgen(js_name = ExecuteConfigChangeProposal)]
pub struct WasmExecuteConfigChangeProposal {
  proposal: WasmConfigChangeProposal,
  identity: WasmOnChainIdentity,
  controller_token: WasmControllerToken,
}

#[wasm_bindgen(js_class = ExecuteConfigChangeProposal)]
impl WasmExecuteConfigChangeProposal {
  fn new(
    proposal: WasmConfigChangeProposal,
    identity: &WasmOnChainIdentity,
    controller_token: &WasmControllerToken,
  ) -> Self {
    Self {
      proposal,
      identity: identity.clone(),
      controller_token: controller_token.clone(),
    }
  }

  #[wasm_bindgen(js_name = buildProgrammableTransaction)]
  pub async fn build_programmable_transaction(&self, client: &WasmCoreClientReadOnly) -> Result<Vec<u8>> {
    let managed_client = WasmManagedCoreClientReadOnly::from_wasm(client)?;
    let proposal = self.proposal.0.read().await.clone();
    let mut identity = self.identity.0.write().await;

    let tx = proposal
      .into_tx(&mut identity, &self.controller_token.0, &managed_client)
      .await
      .wasm_result()?
      .into_inner();
    let ptb = tx.build_programmable_transaction(&managed_client).await.wasm_result()?;
    bcs::to_bytes(&ptb).wasm_result()
  }

  #[wasm_bindgen]
  pub async fn apply(
    &self,
    wasm_effects: &WasmIotaTransactionBlockEffects,
    client: &WasmCoreClientReadOnly,
  ) -> Result<()> {
    let managed_client = WasmManagedCoreClientReadOnly::from_wasm(client)?;
    let proposal = self.proposal.0.read().await.clone();
    let mut identity = self.identity.0.write().await;
    let tx = proposal
      .into_tx(&mut identity, &self.controller_token.0, &managed_client)
      .await
      .wasm_result()?
      .into_inner();
    let mut effects = wasm_effects.clone().into();
    let apply_result = tx.apply(&mut effects, &managed_client).await;
    let wasm_rem_effects = WasmIotaTransactionBlockEffects::from(&effects);
    Object::assign(wasm_effects, &wasm_rem_effects);

    apply_result.wasm_result()
  }
}

#[wasm_bindgen(js_name = CreateConfigChangeProposal)]
pub struct WasmCreateConfigChangeProposal {
  identity: WasmOnChainIdentity,
  controller_token: WasmControllerToken,
  threshold: Option<u64>,
  controllers_to_add: Option<MapStringNumber>,
  controllers_to_remove: Option<StringSet>,
  controllers_to_update: Option<MapStringNumber>,
  expiration_epoch: Option<u64>,
}

#[wasm_bindgen(js_class = CreateConfigChangeProposal)]
impl WasmCreateConfigChangeProposal {
  pub(crate) fn new(
    identity: &WasmOnChainIdentity,
    controller_token: &WasmControllerToken,
    config: WasmConfigChange,
    expiration_epoch: Option<u64>,
  ) -> Self {
    let WasmConfigChange {
      controllers_to_add,
      controllers_to_remove,
      controllers_to_update,
      threshold,
    } = config;
    Self {
      identity: identity.clone(),
      threshold,
      controllers_to_add,
      controllers_to_remove,
      controllers_to_update,
      expiration_epoch,
      controller_token: controller_token.clone(),
    }
  }

  #[wasm_bindgen(js_name = buildProgrammableTransaction)]
  pub async fn build_programmable_transaction(&self, client: &WasmCoreClientReadOnly) -> Result<Vec<u8>> {
    let managed_client = WasmManagedCoreClientReadOnly::from_wasm(client)?;
    let mut identity_ref = self.identity.0.write().await;
    let controllers_to_add = self
      .controllers_to_add
      .clone()
      .map(HashMap::try_from)
      .transpose()?
      .unwrap_or_default();
    let controllers_to_remove = self
      .controllers_to_remove
      .clone()
      .map(HashSet::try_from)
      .transpose()?
      .unwrap_or_default();
    let controllers_to_update = self
      .controllers_to_update
      .clone()
      .map(HashMap::try_from)
      .transpose()?
      .unwrap_or_default();
    let builder = identity_ref
      .update_config(&self.controller_token.0)
      .add_multiple_controllers(controllers_to_add)
      .remove_multiple_controllers(controllers_to_remove)
      .update_multiple_controllers(controllers_to_update);

    let builder = if let Some(exp) = self.expiration_epoch {
      builder.expiration_epoch(exp)
    } else {
      builder
    };
    let builder = if let Some(threshold) = self.threshold {
      builder.threshold(threshold)
    } else {
      builder
    };

    let tx = builder.finish(&managed_client).await.wasm_result()?.into_inner();

    let pt = tx.build_programmable_transaction(&managed_client).await.wasm_result()?;
    bcs::to_bytes(&pt).wasm_result()
  }

  #[wasm_bindgen(unchecked_return_type = "ProposalResult<ConfigChange>")]
  pub async fn apply(
    self,
    wasm_effects: &WasmIotaTransactionBlockEffects,
    client: &WasmCoreClientReadOnly,
  ) -> Result<Option<WasmConfigChangeProposal>> {
    let managed_client = WasmManagedCoreClientReadOnly::from_wasm(client)?;
    let mut identity_ref = self.identity.0.write().await;
    let controllers_to_add = self
      .controllers_to_add
      .clone()
      .map(HashMap::try_from)
      .transpose()?
      .unwrap_or_default();
    let controllers_to_remove = self
      .controllers_to_remove
      .clone()
      .map(HashSet::try_from)
      .transpose()?
      .unwrap_or_default();
    let controllers_to_update = self
      .controllers_to_update
      .clone()
      .map(HashMap::try_from)
      .transpose()?
      .unwrap_or_default();
    let builder = identity_ref
      .update_config(&self.controller_token.0)
      .add_multiple_controllers(controllers_to_add)
      .remove_multiple_controllers(controllers_to_remove)
      .update_multiple_controllers(controllers_to_update);

    let builder = if let Some(exp) = self.expiration_epoch {
      builder.expiration_epoch(exp)
    } else {
      builder
    };
    let builder = if let Some(threshold) = self.threshold {
      builder.threshold(threshold)
    } else {
      builder
    };

    let tx = builder.finish(&managed_client).await.wasm_result()?.into_inner();

    let mut effects = wasm_effects.clone().into();
    let apply_result = tx.apply(&mut effects, &managed_client).await;
    let rem_wasm_effects = WasmIotaTransactionBlockEffects::from(&effects);
    Object::assign(wasm_effects, &rem_wasm_effects);

    match apply_result.wasm_result()? {
      ProposalResult::Executed(_) => Ok(None),
      ProposalResult::Pending(proposal) => Ok(Some(WasmConfigChangeProposal::new(proposal))),
    }
  }
}
