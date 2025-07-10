// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::rc::Rc;

use identity_iota::iota::rebased::migration::ControllerToken;
use identity_iota::iota::rebased::migration::OnChainIdentity;
use identity_iota::iota::rebased::migration::Proposal;
use identity_iota::iota::rebased::proposals::AccessSubIdentity;
use identity_iota::iota::rebased::proposals::AccessSubIdentityBuilder;
use identity_iota::iota::rebased::proposals::ProposedTxResult;
use identity_iota::iota::rebased::proposals::SubAccessFnT;
use iota_interaction_ts::bindings::WasmIotaTransactionBlockEffects;
use iota_interaction_ts::core_client::WasmCoreClientReadOnly;
use js_sys::Object;
use js_sys::Promise;
use js_sys::Reflect;
use product_common::bindings::core_client::WasmManagedCoreClientReadOnly;
use product_common::bindings::transaction::WasmTransaction;
use product_common::bindings::transaction::WasmTransactionBuilder;
use product_common::transaction::Transaction;
use tokio::sync::RwLock;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsCast as _;
use wasm_bindgen::JsError;
use wasm_bindgen::JsValue;

use crate::error::WasmResult as _;
use crate::rebased::WasmControllerToken;
use crate::rebased::WasmOnChainIdentity;

use super::StringSet;

type Result<T, E = JsValue> = std::result::Result<T, E>;

/// Action to access an Identity controlled by another Identity.
#[wasm_bindgen(js_name = AccessSubIdentity, inspectable, getter_with_clone)]
pub struct WasmAccessSubIdentity {
  /// Object ID of the Identity whose token will be used.
  pub identity: String,
  /// Object ID of the sub-Identity that will be accessed.
  pub sub_identity: String,
}

#[wasm_bindgen(js_class = AccessSubIdentity)]
impl WasmAccessSubIdentity {
  #[wasm_bindgen(constructor)]  
  pub fn new(identity: String, sub_identity: String) -> Self {
    Self { identity, sub_identity }
  }

  #[wasm_bindgen(js_name = toJSON)]
  pub fn to_json(&self) -> Result<JsValue, JsValue> {
    let js_object = js_sys::Object::new();
    Reflect::set(
      &js_object,
      &JsValue::from_str("identity"),
      &JsValue::from_str(&self.identity),
    )?;
    Reflect::set(
      &js_object,
      &JsValue::from_str("sub_identity"),
      &JsValue::from_str(&self.sub_identity),
    )?;

    Ok(js_object.into())
  }
}

impl From<AccessSubIdentity> for WasmAccessSubIdentity {
  fn from(
    AccessSubIdentity {
      sub_identity, identity, ..
    }: AccessSubIdentity,
  ) -> Self {
    Self {
      sub_identity: sub_identity.to_string(),
      identity: identity.to_string(),
    }
  }
}

#[derive(Clone)]
#[wasm_bindgen(js_name = AccessSubIdentityProposal)]
pub struct WasmAccessSubIdentityProposal(pub(crate) Rc<RwLock<Proposal<AccessSubIdentity>>>);

#[wasm_bindgen(js_class = AccessSubIdentityProposal)]
impl WasmAccessSubIdentityProposal {
  fn new(proposal: Proposal<AccessSubIdentity>) -> Self {
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
  pub fn action(&self) -> Result<WasmAccessSubIdentity> {
    self
      .0
      .try_read()
      .wasm_result()
      .map(|proposal| proposal.action().clone().into())
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
    let tx = WasmApproveAccessSubIdentityProposal::new(self, identity, controller_token);
    WasmTransactionBuilder::new(JsValue::from(tx).unchecked_into())
  }

  #[wasm_bindgen(js_name = intoTx, skip_typescript)]
  pub fn into_tx(
    self,
    identity: &WasmOnChainIdentity,
    controller_token: &WasmControllerToken,
    sub_identity: &WasmOnChainIdentity,
    sub_access_fn: WasmSubAccessFn,
  ) -> WasmTransactionBuilder {
    let wasm_tx: JsValue =
      WasmAccessSubIdentityTx::execute(identity, sub_identity, controller_token, sub_access_fn, Some(self)).into();
    WasmTransactionBuilder::new(wasm_tx.unchecked_into())
  }
}

#[wasm_bindgen(skip_typescript)]
pub struct WasmApproveAccessSubIdentityProposal {
  proposal: WasmAccessSubIdentityProposal,
  identity: WasmOnChainIdentity,
  controller_token: WasmControllerToken,
}

#[wasm_bindgen]
impl WasmApproveAccessSubIdentityProposal {
  fn new(
    proposal: &WasmAccessSubIdentityProposal,
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
    let identity_ref = self.identity.0.read().await;
    let mut proposal_ref = self.proposal.0.write().await;
    let tx = proposal_ref
      .approve(&identity_ref, &self.controller_token.0)
      .wasm_result()?
      .into_inner();

    let pt = tx.build_programmable_transaction(&managed_client).await.wasm_result()?;
    bcs::to_bytes(&pt).wasm_result()
  }

  #[wasm_bindgen]
  pub async fn apply(
    self,
    wasm_effects: &WasmIotaTransactionBlockEffects,
    client: &WasmCoreClientReadOnly,
  ) -> Result<()> {
    let managed_client = WasmManagedCoreClientReadOnly::from_wasm(client)?;
    let identity_ref = self.identity.0.read().await;
    let mut proposal_ref = self.proposal.0.write().await;
    let tx = proposal_ref
      .approve(&identity_ref, &self.controller_token.0)
      .wasm_result()?
      .into_inner();

    let mut effects = wasm_effects.clone().into();
    let apply_result = tx.apply(&mut effects, &managed_client).await;
    let wasm_rem_effects = WasmIotaTransactionBlockEffects::from(&effects);
    Object::assign(wasm_effects, &wasm_rem_effects);

    apply_result.wasm_result()
  }
}

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "SubAccessFn<unknown>", extends = js_sys::Function)]
  #[derive(Clone)]
  pub type WasmSubAccessFn;
}

enum TxKind {
  Create {
    expiration: Option<u64>,
  },
  Execute {
    proposal: Option<WasmAccessSubIdentityProposal>,
    sub_fn: WasmSubAccessFn,
  },
}

#[wasm_bindgen(skip_typescript)]
pub struct WasmAccessSubIdentityTx {
  identity: WasmOnChainIdentity,
  sub_identity: WasmOnChainIdentity,
  identity_token: WasmControllerToken,
  tx_kind: TxKind,
}

#[wasm_bindgen]
impl WasmAccessSubIdentityTx {
  pub(crate) fn create(
    identity: &WasmOnChainIdentity,
    sub_identity: &WasmOnChainIdentity,
    identity_token: &WasmControllerToken,
    expiration: Option<u64>,
  ) -> Self {
    Self {
      identity: identity.clone(),
      sub_identity: sub_identity.clone(),
      identity_token: identity_token.clone(),
      tx_kind: TxKind::Create { expiration },
    }
  }

  pub(crate) fn execute(
    identity: &WasmOnChainIdentity,
    sub_identity: &WasmOnChainIdentity,
    identity_token: &WasmControllerToken,
    sub_fn: WasmSubAccessFn,
    proposal: Option<WasmAccessSubIdentityProposal>,
  ) -> Self {
    let tx_kind = TxKind::Execute { proposal, sub_fn };

    Self {
      identity: identity.clone(),
      sub_identity: sub_identity.clone(),
      identity_token: identity_token.clone(),
      tx_kind,
    }
  }

  #[wasm_bindgen(js_name = buildProgrammableTransaction)]
  pub async fn build_programmable_transaction(&self, client: &WasmCoreClientReadOnly) -> Result<Vec<u8>, JsError> {
    let managed_client = WasmManagedCoreClientReadOnly::from_wasm(client)
      .map_err(|_| JsError::new("failed to create a managed client from CoreClientReadOnly"))?;
    let mut identity_mut = self.identity.0.write().await;
    let mut sub_identity_mut = self.sub_identity.0.write().await;
    let identity_token = &self.identity_token.0;

    let pt = match &self.tx_kind {
      TxKind::Create { expiration } => {
        let builder =
          AccessSubIdentityBuilder::<'_, '_, ()>::new(&mut identity_mut, &mut sub_identity_mut, identity_token);
        if let Some(exp) = expiration {
          builder.with_expiration(*exp)
        } else {
          builder
        }
        .finish(&managed_client)
        .await?
        .into_inner()
        .build_programmable_transaction(&managed_client)
        .await?
      }
      TxKind::Execute { proposal, sub_fn } => {
        let sub_access_fn = sub_fn.to_sub_access_fn();
        if let Some(proposal) = proposal {
          proposal
            .0
            .read()
            .await
            .clone()
            .into_tx(
              &mut identity_mut,
              &mut sub_identity_mut,
              identity_token,
              sub_access_fn,
              &managed_client,
            )
            .await?
        } else {
          AccessSubIdentityBuilder::<'_, '_, ()>::new(&mut identity_mut, &mut sub_identity_mut, identity_token)
            .to_perform(sub_access_fn)
            .finish(&managed_client)
            .await?
        }
        .into_inner()
        .build_programmable_transaction(&managed_client)
        .await?
      }
    };

    Ok(bcs::to_bytes(&pt)?)
  }

  #[wasm_bindgen]
  pub async fn apply(
    self,
    wasm_effects: &WasmIotaTransactionBlockEffects,
    client: &WasmCoreClientReadOnly,
  ) -> Result<JsValue, JsError> {
    let managed_client = WasmManagedCoreClientReadOnly::from_wasm(client)
      .map_err(|_| JsError::new("failed to create a managed client from CoreClientReadOnly"))?;
    let mut identity_mut = self.identity.0.write().await;
    let mut sub_identity_mut = self.sub_identity.0.write().await;
    let identity_token = &self.identity_token.0;
    let mut effects = wasm_effects.clone().into();

    let value = match &self.tx_kind {
      TxKind::Create { expiration } => {
        let tx = {
          let builder =
            AccessSubIdentityBuilder::<'_, '_, ()>::new(&mut identity_mut, &mut sub_identity_mut, identity_token);
          if let Some(exp) = expiration {
            builder.with_expiration(*exp)
          } else {
            builder
          }
          .finish(&managed_client)
          .await?
          .into_inner()
        };

        let ProposedTxResult::Pending(pending_proposal) =
          tx.apply(&mut effects, &managed_client).await.expect("infallible")
        else {
          unreachable!("TxKind::Create always return a pending proposal result");
        };
        let wasm_rem_effects = WasmIotaTransactionBlockEffects::from(&effects);
        Object::assign(wasm_effects, &wasm_rem_effects);

        JsValue::from(WasmAccessSubIdentityProposal::new(pending_proposal))
      }
      TxKind::Execute { proposal, sub_fn } => {
        let sub_access_fn = sub_fn.to_sub_access_fn();

        let ProposedTxResult::Executed(application_result) = if let Some(proposal) = proposal {
          proposal
            .0
            .read()
            .await
            .clone()
            .into_tx(
              &mut identity_mut,
              &mut sub_identity_mut,
              identity_token,
              sub_access_fn,
              &managed_client,
            )
            .await?
        } else {
          AccessSubIdentityBuilder::<'_, '_, ()>::new(&mut identity_mut, &mut sub_identity_mut, identity_token)
            .to_perform(sub_access_fn)
            .finish(&managed_client)
            .await?
        }
        .into_inner()
        .apply(&mut effects, &managed_client)
        .await?
        else {
          unreachable!("TxKind::Execute always return its sub_tx application result")
        };

        let wasm_rem_effects = WasmIotaTransactionBlockEffects::from(&effects);
        Object::assign(wasm_effects, &wasm_rem_effects);
        application_result
      }
    };

    Ok(value)
  }
}

impl WasmSubAccessFn {
  fn to_sub_access_fn<'sub>(
    &self,
  ) -> impl SubAccessFnT<'sub, Error = Box<dyn std::error::Error + Send + Sync>, Tx = WasmTransaction> {
    let wasm_sub_fn = self.clone();
    move |sub_identity: &'sub mut OnChainIdentity, sub_identity_token: ControllerToken| async move {
      let wasm_sub_identity = WasmOnChainIdentity::new(sub_identity.clone());
      let wasm_sub_identity_token = WasmControllerToken(sub_identity_token);

      let promise = wasm_sub_fn
        .call2(
          &JsValue::NULL,
          &wasm_sub_identity.into(),
          &wasm_sub_identity_token.into(),
        )
        .map_err(|e| {
          e.as_string()
            .unwrap_or_else(|| "calling user-defined SubAccessFn failed".to_owned())
        })?
        .dyn_into::<Promise>()
        .map_err(|js_value| {
          format!(
            "expected `Promise<Tx extends Transaction>` but found `{}`",
            js_value.js_typeof().as_string().as_deref().unwrap_or("unknown"),
          )
        })?;

      let wasm_transaction = wasm_bindgen_futures::JsFuture::from(promise)
        .await
        .map_err(|js_value| {
          js_value
            .dyn_into::<js_sys::Error>()
            .ok()
            .map(|js_err| String::from(js_err.message()))
            .unwrap_or_else(|| "failed to resolve promise returned by user-defined JS SubAccessFn".to_owned())
        })?
        .unchecked_into::<WasmTransaction>();

      Ok(wasm_transaction)
    }
  }
}
