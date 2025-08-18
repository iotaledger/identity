// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::ops::Deref;
use std::ops::DerefMut;
use std::rc::Rc;
use std::result::Result as StdResult;

use identity_iota::iota::rebased::migration::Proposal;
use identity_iota::iota::rebased::proposals::ControllerExecution;
use identity_iota::iota::rebased::proposals::ControllerIntentFnT;
use identity_iota::iota::rebased::proposals::ProposalResult;
use identity_iota::iota::rebased::proposals::ProposalT as _;
use iota_interaction::types::base_types::IotaAddress;
use iota_interaction::types::base_types::ObjectID;
use iota_interaction::types::programmable_transaction_builder::ProgrammableTransactionBuilder;
use iota_interaction::types::transaction::Argument;
use iota_interaction::types::transaction::ProgrammableTransaction;
use iota_interaction::types::transaction::TransactionKind;
use iota_interaction_ts::bindings::WasmIotaTransactionBlockEffects;
use iota_interaction_ts::core_client::WasmCoreClientReadOnly;
use product_common::bindings::core_client::WasmManagedCoreClientReadOnly;
use product_common::bindings::transaction::WasmTransactionBuilder;
use product_common::core_client::CoreClientReadOnly;
use product_common::transaction::transaction_builder::Transaction as _;
use product_common::transaction::ProtoTransaction;
use tokio::sync::RwLock;
use wasm_bindgen::prelude::*;

use crate::error::Result;
use crate::error::WasmResult as _;
use crate::rebased::WasmControllerToken;
use crate::rebased::WasmOnChainIdentity;

use super::StringSet;
use super::TransactionDataBuilder;

#[wasm_bindgen(typescript_custom_section)]
const _TYPE_DEFS: &str = r#"
import { TransactionDataBuilder, Argument } from "@iota/iota-sdk/transactions";
import { IotaObjectData } from "@iota/iota-sdk/client";

/**
 * Closure that allows users to define what to do with the Identity's controller capability.
 */
export type ControllerExecutionFn = (tx: TransactionDataBuilder, capability: Argument) => void;
"#;

#[wasm_bindgen]
extern "C" {
  #[derive(Clone)]
  #[wasm_bindgen(typescript_type = ControllerExecutionFn, extends = js_sys::Function)]
  pub type WasmControllerExecutionFn;
}

impl WasmControllerExecutionFn {
  /// The resulting closure may panic if anything goes wrong.
  /// Make sure to catch_unwind when it's called.
  pub(crate) fn into_intent_fn(self) -> impl ControllerIntentFnT {
    type Ptb = ProgrammableTransactionBuilder;

    move |ptb: &mut Ptb, cap: &Argument| {
      // Convert the PTB into a TS Transaction (the builder).
      let pt = std::mem::take(ptb).finish();
      let tx_kind = TransactionKind::ProgrammableTransaction(pt);
      let tx_kind_bytes = bcs::to_bytes(&tx_kind).unwrap();
      let ts_tx_builder = TransactionDataBuilder::from_tx_kind_bcs(tx_kind_bytes).unwrap();
      let ts_argument = serde_wasm_bindgen::to_value(cap).unwrap();

      // Call the provided JS closure `exec_fn`.
      self
        .call2(
          // No `this`.
          &JsValue::NULL,
          &ts_tx_builder,
          &ts_argument,
        )
        .unwrap();
      // Call the provided JS closure `exec_fn`.

      // `exec_fn` has changed the internals of transaction builder.
      // Convert it back into a PTB and set `ptb`.
      // Build the programmable transaction.
      // Dev note: since we already know which transaction kind (PT) we are dealing with
      // we can strip away the tag (the first byte) and directly deserialize a PT.
      let pt: ProgrammableTransaction = bcs::from_bytes(&ts_tx_builder.build_tx_kind()[1..]).unwrap();
      for input in pt.inputs {
        ptb.input(input).unwrap();
      }
      for cmd in pt.commands {
        ptb.command(cmd);
      }
    }
  }
}

#[derive(Clone)]
#[wasm_bindgen(js_name = ControllerExecution, inspectable, getter_with_clone)]
pub struct WasmControllerExecution {
  controller_cap: ObjectID,
  identity: IotaAddress,
  pub controller_exec_fn: Option<WasmControllerExecutionFn>,
}

impl From<WasmControllerExecution> for ControllerExecution {
  fn from(value: WasmControllerExecution) -> Self {
    let action = Self::new_from_identity_address(value.controller_cap, value.identity);
    if let Some(exec_fn) = value.controller_exec_fn {
      action.with_intent(Box::new(exec_fn.into_intent_fn()))
    } else {
      action
    }
  }
}

#[wasm_bindgen(js_class = ControllerExecution)]
impl WasmControllerExecution {
  #[wasm_bindgen(constructor)]
  pub fn new(
    controller_cap: String,
    identity: &WasmOnChainIdentity,
    exec_fn: Option<WasmControllerExecutionFn>,
  ) -> StdResult<Self, JsError> {
    let controller_cap = controller_cap.parse()?;
    let identity = identity.0.try_read()?.id().into();

    Ok(Self {
      controller_cap,
      identity,
      controller_exec_fn: exec_fn,
    })
  }

  #[wasm_bindgen(getter, js_name = controllerCap)]
  pub fn controller_cap(&self) -> String {
    self.controller_cap.to_string()
  }

  #[wasm_bindgen(getter, js_name = identityAddress)]
  pub fn identity_address(&self) -> String {
    self.identity.to_string()
  }
}

struct Internal {
  proposal: Proposal<ControllerExecution>,
  exec_fn: Option<WasmControllerExecutionFn>,
}

impl Deref for Internal {
  type Target = Proposal<ControllerExecution>;
  fn deref(&self) -> &Self::Target {
    &self.proposal
  }
}

impl DerefMut for Internal {
  fn deref_mut(&mut self) -> &mut Self::Target {
    &mut self.proposal
  }
}

#[derive(Clone)]
#[wasm_bindgen(js_name = ControllerExecutionProposal)]
pub struct WasmProposalControllerExecution(Rc<RwLock<Internal>>);

#[wasm_bindgen(js_class = ControllerExecutionProposal)]
impl WasmProposalControllerExecution {
  fn new(proposal: Proposal<ControllerExecution>) -> Self {
    Self(Rc::new(RwLock::new(Internal {
      proposal,
      exec_fn: None,
    })))
  }

  #[wasm_bindgen(getter)]
  pub fn id(&self) -> Result<String> {
    self
      .0
      .try_read()
      .wasm_result()
      .map(|guard| guard.proposal.id().to_string())
  }

  #[wasm_bindgen(getter)]
  pub fn action(&self) -> Result<WasmControllerExecution> {
    self.0.try_read().wasm_result().map(|guard| WasmControllerExecution {
      controller_cap: guard.action().controller_cap(),
      identity: guard.action().identity_address(),
      controller_exec_fn: None,
    })
  }

  #[wasm_bindgen(getter)]
  pub fn expiration_epoch(&self) -> Result<Option<u64>> {
    self
      .0
      .try_read()
      .wasm_result()
      .map(|guard| guard.proposal.expiration_epoch())
  }

  #[wasm_bindgen(getter)]
  pub fn votes(&self) -> Result<u64> {
    self.0.try_read().wasm_result().map(|guard| guard.proposal.votes())
  }

  #[wasm_bindgen(getter)]
  pub fn voters(&self) -> Result<StringSet> {
    let js_set = self
      .0
      .try_read()
      .wasm_result()?
      .proposal
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

  #[wasm_bindgen(js_name = execFn, setter)]
  pub fn set_intent_fn(&self, exec_fn: WasmControllerExecutionFn) -> Result<()> {
    self.0.try_write().wasm_result()?.exec_fn = Some(exec_fn);
    Ok(())
  }

  #[wasm_bindgen(unchecked_return_type = "TransactionBuilder<ApproveProposal>")]
  pub fn approve(
    &self,
    identity: &WasmOnChainIdentity,
    controller_token: &WasmControllerToken,
  ) -> Result<WasmTransactionBuilder> {
    let js_tx = JsValue::from(WasmApproveControllerExecutionProposal::new(
      self,
      identity,
      controller_token,
    ));
    Ok(WasmTransactionBuilder::new(js_tx.unchecked_into()))
  }

  #[wasm_bindgen(
    js_name = intoTx,
    unchecked_return_type = "TransactionBuilder<ExecuteProposal<ControllerExecution>>"
  )]
  pub fn into_tx(
    self,
    identity: &WasmOnChainIdentity,
    controller_token: &WasmControllerToken,
  ) -> WasmTransactionBuilder {
    let js_tx = JsValue::from(WasmExecuteControllerExecutionProposal::new(
      self,
      identity,
      controller_token,
    ));
    WasmTransactionBuilder::new(js_tx.unchecked_into())
  }
}

#[wasm_bindgen(js_name = ApproveControllerExecutionProposal)]
pub struct WasmApproveControllerExecutionProposal {
  proposal: WasmProposalControllerExecution,
  identity: WasmOnChainIdentity,
  controller_token: WasmControllerToken,
}

#[wasm_bindgen(js_class = ApproveControllerExecutionProposal)]
impl WasmApproveControllerExecutionProposal {
  fn new(
    proposal: &WasmProposalControllerExecution,
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
    let pt = tx.build_programmable_transaction(&managed_client).await.wasm_result()?;
    bcs::to_bytes(&pt).wasm_result()
  }

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
    js_sys::Object::assign(wasm_effects, &wasm_rem_effects);

    apply_result.wasm_result()
  }
}

#[wasm_bindgen(js_name = ExecuteControllerExecutionProposal)]
pub struct WasmExecuteControllerExecutionProposal {
  proposal: WasmProposalControllerExecution,
  identity: WasmOnChainIdentity,
  controller_token: WasmControllerToken,
}

#[wasm_bindgen(js_class = ExecuteControllerExecutionProposal)]
impl WasmExecuteControllerExecutionProposal {
  pub fn new(
    proposal: WasmProposalControllerExecution,
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
    let proposal_id = self.proposal.0.read().await.id();
    let mut proposal = managed_client.get_object_by_id(proposal_id).await.wasm_result()?;
    let exec_fn = {
      let mut guard = self.proposal.0.write().await;
      std::mem::swap(&mut guard.proposal, &mut proposal);
      guard.exec_fn.clone()
    };
    let Some(exec_fn) = exec_fn else {
      return Err(JsError::new("cannot execute this controller execution proposal without an `execFn`").into());
    };
    let mut identity = self.identity.0.write().await;
    let tx = proposal
      .into_tx(&mut identity, &self.controller_token.0, &managed_client)
      .await
      .wasm_result()?
      .with(Box::new(exec_fn.into_intent_fn()))
      .into_inner()
      .build_programmable_transaction(&managed_client)
      .await
      .wasm_result()?;
    bcs::to_bytes(&tx).wasm_result()
  }

  pub async fn apply(
    self,
    wasm_effects: &WasmIotaTransactionBlockEffects,
    client: &WasmCoreClientReadOnly,
  ) -> Result<()> {
    let managed_client = WasmManagedCoreClientReadOnly::from_wasm(client)?;
    let proposal_id = self.proposal.0.read().await.id();
    let proposal = managed_client
      .get_object_by_id::<Proposal<ControllerExecution>>(proposal_id)
      .await
      .wasm_result()?;
    let mut identity = self.identity.0.write().await;
    let tx = proposal
      .into_tx(&mut identity, &self.controller_token.0, &managed_client)
      .await
      .wasm_result()?
      // Dummy exec fn as it won't be needed for apply.
      .with(Box::new(move |_, _| ()))
      .into_inner();
    let mut effects = wasm_effects.clone().into();
    let apply_result = tx.apply(&mut effects, &managed_client).await;
    let wasm_rem_effects = WasmIotaTransactionBlockEffects::from(&effects);
    js_sys::Object::assign(wasm_effects, &wasm_rem_effects);

    apply_result.wasm_result()
  }
}

#[wasm_bindgen(js_name = CreateControllerExecutionProposal)]
pub struct WasmCreateControllerExecutionProposal {
  identity: WasmOnChainIdentity,
  controller_token: WasmControllerToken,
  expiration_epoch: Option<u64>,
  exec_fn: Option<WasmControllerExecutionFn>,
  controller_cap: ObjectID,
}

#[wasm_bindgen(js_class = CreateControllerExecutionProposal)]
impl WasmCreateControllerExecutionProposal {
  pub(crate) fn new(
    identity: &WasmOnChainIdentity,
    controller_token: &WasmControllerToken,
    controller_cap: ObjectID,
    exec_fn: Option<WasmControllerExecutionFn>,
    expiration_epoch: Option<u64>,
  ) -> Self {
    Self {
      identity: identity.clone(),
      controller_token: controller_token.clone(),
      controller_cap,
      expiration_epoch,
      exec_fn,
    }
  }

  #[wasm_bindgen(js_name = buildProgrammableTransaction)]
  pub async fn build_programmable_transaction(&self, client: &WasmCoreClientReadOnly) -> Result<Vec<u8>> {
    let managed_client = WasmManagedCoreClientReadOnly::from_wasm(client)?;
    let mut identity_lock = self.identity.0.write().await;
    let mut builder = identity_lock.controller_execution(self.controller_cap, &self.controller_token.0);

    if let Some(exec_fn) = self.exec_fn.clone() {
      builder = builder.with_intent(Box::new(exec_fn.into_intent_fn()))
    }

    if let Some(expiration) = self.expiration_epoch {
      builder = builder.expiration_epoch(expiration);
    }

    let tx = builder.finish(&managed_client).await.wasm_result()?.into_inner();
    bcs::to_bytes(tx.ptb()).wasm_result()
  }

  #[wasm_bindgen(unchecked_return_type = "ProposalResult<ControllerExecution>")]
  pub async fn apply(
    self,
    wasm_effects: &WasmIotaTransactionBlockEffects,
    client: &WasmCoreClientReadOnly,
  ) -> Result<Option<WasmProposalControllerExecution>> {
    let managed_client = WasmManagedCoreClientReadOnly::from_wasm(client)?;
    let mut identity_lock = self.identity.0.write().await;
    let mut builder = identity_lock.controller_execution(self.controller_cap, &self.controller_token.0);

    if let Some(exec_fn) = self.exec_fn.clone() {
      builder = builder.with_intent(Box::new(exec_fn.into_intent_fn()))
    }

    if let Some(expiration) = self.expiration_epoch {
      builder = builder.expiration_epoch(expiration);
    }

    let tx = builder.finish(&managed_client).await.wasm_result()?.into_inner();

    let mut effects = wasm_effects.clone().into();
    let apply_result = tx.apply(&mut effects, &managed_client).await;
    let wasm_rem_effects = WasmIotaTransactionBlockEffects::from(&effects);
    js_sys::Object::assign(wasm_effects, &wasm_rem_effects);

    let ProposalResult::Pending(proposal) = apply_result.wasm_result()? else {
      return Ok(None);
    };

    Ok(Some(WasmProposalControllerExecution::new(proposal)))
  }
}
