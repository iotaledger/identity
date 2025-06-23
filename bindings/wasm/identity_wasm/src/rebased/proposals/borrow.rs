// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::ops::Deref;
use std::ops::DerefMut;
use std::rc::Rc;
use std::result::Result as StdResult;

use identity_iota::iota::rebased::migration::Proposal;
use identity_iota::iota::rebased::proposals::BorrowAction;
use identity_iota::iota::rebased::proposals::BorrowIntentFnT;
use identity_iota::iota::rebased::proposals::ProposalResult;
use identity_iota::iota::rebased::proposals::ProposalT as _;
use iota_interaction::rpc_types::IotaObjectData;
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

#[wasm_bindgen(typescript_custom_section)]
const _TYPE_DEFS: &str = r#"
import { Transaction as SdkTransaction, Argument } from "@iota/iota-sdk/transactions";
import { IotaObjectData } from "@iota/iota-sdk/client";

/**
 * User defined function to define what should be done with the borrowed objects.
 */
export type BorrowFn = (tx: SdkTransaction, objects: Map<string, [Argument, IotaObjectData]>) => void;
"#;

#[wasm_bindgen]
extern "C" {
  #[derive(Clone)]
  #[wasm_bindgen(typescript_type = BorrowFn, extends = js_sys::Function)]
  pub type WasmBorrowFn;
}

// TODO: implement the same in product-core and consume it from
// there instead of having the implementation here.
#[wasm_bindgen(module = "@iota/iota-sdk/transactions")]
extern "C" {
  #[wasm_bindgen(typescript_type = TransactionDataBuilder, extends = js_sys::Object)]
  type _TransactionDataBuilder;

  #[wasm_bindgen(js_name = fromKindBytes, static_method_of = _TransactionDataBuilder)]
  fn from_tx_kind_bcs(bytes: &[u8]) -> _TransactionDataBuilder;

  #[wasm_bindgen(method)]
  fn build(this: &_TransactionDataBuilder, options: Option<&js_sys::Object>) -> Vec<u8>;
}

impl _TransactionDataBuilder {
  fn build_tx_kind(&self) -> Vec<u8> {
    let options = js_sys::Object::new();
    let _ = js_sys::Reflect::set(&options, &JsValue::from_str("onlyTransactionKind"), &JsValue::TRUE);
    self.build(Some(&options))
  }
}

impl WasmBorrowFn {
  /// The resulting closure may panic if anything goes wrong.
  /// Make sure to catch_unwind when it's called.
  pub(crate) fn into_intent_fn(self) -> impl BorrowIntentFnT {
    use serde::Serialize as _;
    type Ptb = ProgrammableTransactionBuilder;

    move |ptb: &mut Ptb, objects: &HashMap<ObjectID, (Argument, IotaObjectData)>| {
      // Convert the PTB into a TS Transaction (the builder).
      let tx_kind = TransactionKind::ProgrammableTransaction(std::mem::take(ptb).finish());
      let tx_kind_bytes = bcs::to_bytes(&tx_kind).unwrap();
      let ts_tx_builder = _TransactionDataBuilder::from_tx_kind_bcs(&tx_kind_bytes);
      // Convert objects into a JS Map of the same types.
      let ts_map = objects
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .unwrap();

      // Call the provided JS closure `borrow_fn`.
      self
        .call2(
          // No `this`.
          &JsValue::NULL,
          &ts_tx_builder,
          &ts_map,
        )
        .unwrap();

      // `borrow_fn` has changed the internals of transaction builder.
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
#[wasm_bindgen(js_name = Borrow, inspectable, getter_with_clone)]
pub struct WasmBorrow {
  objects: Vec<ObjectID>,
  pub borrow_fn: Option<WasmBorrowFn>,
}

impl From<WasmBorrow> for BorrowAction {
  fn from(value: WasmBorrow) -> Self {
    if let Some(borrow_fn) = value.borrow_fn {
      let intent_fn = borrow_fn.into_intent_fn();
      Self::new_with_intent(value.objects, Box::new(intent_fn))
    } else {
      Self::new(value.objects)
    }
  }
}

#[wasm_bindgen(js_class = Borrow)]
impl WasmBorrow {
  #[wasm_bindgen(constructor)]
  pub fn new(objects: Vec<String>, borrow_fn: Option<WasmBorrowFn>) -> StdResult<Self, JsError> {
    let objects = objects
      .iter()
      .map(|s| s.parse::<ObjectID>())
      .collect::<StdResult<Vec<_>, _>>()?;

    Ok(Self { borrow_fn, objects })
  }

  #[wasm_bindgen(getter)]
  pub fn objects(&self) -> Vec<String> {
    self.objects.iter().map(ToString::to_string).collect()
  }
}

struct Internal {
  proposal: Proposal<BorrowAction>,
  borrow_fn: Option<WasmBorrowFn>,
}

impl Deref for Internal {
  type Target = Proposal<BorrowAction>;
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
#[wasm_bindgen(js_name = BorrowProposal)]
pub struct WasmProposalBorrow(Rc<RwLock<Internal>>);

#[wasm_bindgen(js_class = BorrowProposal)]
impl WasmProposalBorrow {
  fn new(proposal: Proposal<BorrowAction>) -> Self {
    Self(Rc::new(RwLock::new(Internal {
      proposal,
      borrow_fn: None,
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
  pub fn action(&self) -> Result<WasmBorrow> {
    self.0.try_read().wasm_result().map(|guard| WasmBorrow {
      objects: guard.proposal.action().objects().to_vec(),
      borrow_fn: None,
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

  #[wasm_bindgen(js_name = borrowFn, setter)]
  pub fn set_intent_fn(&self, borrow_fn: WasmBorrowFn) -> Result<()> {
    self.0.try_write().wasm_result()?.borrow_fn = Some(borrow_fn);
    Ok(())
  }

  #[wasm_bindgen(unchecked_return_type = "TransactionBuilder<ApproveProposal>")]
  pub fn approve(
    &self,
    identity: &WasmOnChainIdentity,
    controller_token: &WasmControllerToken,
  ) -> Result<WasmTransactionBuilder> {
    let js_tx = JsValue::from(WasmApproveBorrowProposal::new(self, identity, controller_token));
    Ok(WasmTransactionBuilder::new(js_tx.unchecked_into()))
  }

  #[wasm_bindgen(
    js_name = intoTx,
    unchecked_return_type = "TransactionBuilder<ExecuteProposal<Borrow>>"
  )]
  pub fn into_tx(
    self,
    identity: &WasmOnChainIdentity,
    controller_token: &WasmControllerToken,
  ) -> WasmTransactionBuilder {
    let js_tx = JsValue::from(WasmExecuteBorrowProposal::new(self, identity, controller_token));
    WasmTransactionBuilder::new(js_tx.unchecked_into())
  }
}

#[wasm_bindgen(js_name = ApproveBorrowProposal)]
pub struct WasmApproveBorrowProposal {
  proposal: WasmProposalBorrow,
  identity: WasmOnChainIdentity,
  controller_token: WasmControllerToken,
}

#[wasm_bindgen(js_class = ApproveBorrowProposal)]
impl WasmApproveBorrowProposal {
  fn new(
    proposal: &WasmProposalBorrow,
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

#[wasm_bindgen(js_name = ExecuteBorrowProposal)]
pub struct WasmExecuteBorrowProposal {
  proposal: WasmProposalBorrow,
  identity: WasmOnChainIdentity,
  controller_token: WasmControllerToken,
}

#[wasm_bindgen(js_class = ExecuteBorrowProposal)]
impl WasmExecuteBorrowProposal {
  pub fn new(
    proposal: WasmProposalBorrow,
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
    let borrow_fn = {
      let mut guard = self.proposal.0.write().await;
      std::mem::swap(&mut guard.proposal, &mut proposal);
      guard.borrow_fn.clone()
    };
    let Some(borrow_fn) = borrow_fn else {
      return Err(JsError::new("cannot execute this borrow proposal without a `borrowFn`").into());
    };
    let mut identity = self.identity.0.write().await;
    let tx = proposal
      .into_tx(&mut identity, &self.controller_token.0, &managed_client)
      .await
      .wasm_result()?
      .with(Box::new(borrow_fn.into_intent_fn()))
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
      .get_object_by_id::<Proposal<BorrowAction>>(proposal_id)
      .await
      .wasm_result()?;
    let mut identity = self.identity.0.write().await;
    let tx = proposal
      .into_tx(&mut identity, &self.controller_token.0, &managed_client)
      .await
      .wasm_result()?
      // Dummy borrow fn as it won't be needed for apply.
      .with(Box::new(move |_, _| ()))
      .into_inner();
    let mut effects = wasm_effects.clone().into();
    let apply_result = tx.apply(&mut effects, &managed_client).await;
    let wasm_rem_effects = WasmIotaTransactionBlockEffects::from(&effects);
    js_sys::Object::assign(wasm_effects, &wasm_rem_effects);

    apply_result.wasm_result()
  }
}

#[wasm_bindgen(js_name = CreateBorrowProposal)]
pub struct WasmCreateBorrowProposal {
  identity: WasmOnChainIdentity,
  controller_token: WasmControllerToken,
  expiration_epoch: Option<u64>,
  borrow_fn: Option<WasmBorrowFn>,
  objects: Vec<ObjectID>,
}

#[wasm_bindgen(js_class = CreateBorrowProsal)]
impl WasmCreateBorrowProposal {
  pub(crate) fn new(
    identity: &WasmOnChainIdentity,
    controller_token: &WasmControllerToken,
    objects: Vec<ObjectID>,
    borrow_fn: Option<WasmBorrowFn>,
    expiration_epoch: Option<u64>,
  ) -> Self {
    Self {
      identity: identity.clone(),
      controller_token: controller_token.clone(),
      objects,
      expiration_epoch,
      borrow_fn,
    }
  }

  #[wasm_bindgen(js_name = buildProgrammableTransaction)]
  pub async fn build_programmable_transaction(&self, client: &WasmCoreClientReadOnly) -> Result<Vec<u8>> {
    let managed_client = WasmManagedCoreClientReadOnly::from_wasm(client)?;
    let mut identity_lock = self.identity.0.write().await;
    let mut builder = identity_lock
      .borrow_assets(&self.controller_token.0)
      .borrow_objects(self.objects.iter().copied());

    if let Some(borrow_fn) = self.borrow_fn.clone() {
      builder = builder.with_intent(Box::new(borrow_fn.into_intent_fn()))
    }

    if let Some(expiration) = self.expiration_epoch {
      builder = builder.expiration_epoch(expiration);
    }

    let tx = builder.finish(&managed_client).await.wasm_result()?.into_inner();
    bcs::to_bytes(tx.ptb()).wasm_result()
  }

  #[wasm_bindgen(unchecked_return_type = "ProposalResult<Borrow>")]
  pub async fn apply(
    self,
    wasm_effects: &WasmIotaTransactionBlockEffects,
    client: &WasmCoreClientReadOnly,
  ) -> Result<Option<WasmProposalBorrow>> {
    let managed_client = WasmManagedCoreClientReadOnly::from_wasm(client)?;
    let mut identity_lock = self.identity.0.write().await;
    let mut builder = identity_lock
      .borrow_assets(&self.controller_token.0)
      .borrow_objects(self.objects.iter().copied());

    if let Some(borrow_fn) = self.borrow_fn.clone() {
      builder = builder.with_intent(Box::new(borrow_fn.into_intent_fn()))
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

    Ok(Some(WasmProposalBorrow::new(proposal)))
  }
}
