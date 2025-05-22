// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::iota::rebased::migration::ControllerCap;
use identity_iota::iota::rebased::migration::DelegatePermissions;
use identity_iota::iota::rebased::migration::DelegateToken;
use identity_iota::iota::rebased::migration::DelegationToken;
use identity_iota::iota::rebased::migration::DelegationTokenRevocation;
use identity_iota::iota::rebased::migration::DeleteDelegationToken;
use iota_interaction_ts::bindings::WasmIotaTransactionBlockEffects;
use js_sys::Object;
use product_common::transaction::transaction_builder::Transaction as _;
use product_common::transaction::transaction_builder::TransactionBuilder;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsCast as _;
use wasm_bindgen::JsError;
use wasm_bindgen::JsValue;

use crate::error::wasm_error;
use crate::error::Result;
use crate::error::WasmResult;

use super::WasmIdentityClientReadOnly;
use super::WasmOnChainIdentity;
use super::WasmTransactionBuilder;

#[wasm_bindgen(typescript_custom_section)]
pub const _CONTROLLER_TOKEN_DEF: &str = r#"
export type ControllerToken = ControllerCap | DelegationToken;
"#;

/// A token that authenticates its bearer as a controller of a specific shared object.
#[wasm_bindgen(js_name = ControllerCap)]
pub struct WasmControllerCap(pub(crate) ControllerCap);

#[wasm_bindgen(js_class = ControllerCap)]
impl WasmControllerCap {
  /// Returns the ID of this {@link ControllerCap}.
  #[wasm_bindgen(getter)]
  pub fn id(&self) -> String {
    self.0.id().to_string()
  }

  /// Returns the ID of the object this token controls.
  #[wasm_bindgen(getter, js_name = controllerOf)]
  pub fn controller_of(&self) -> String {
    self.0.controller_of().to_string()
  }

  /// Returns whether this controller is allowed to delegate
  /// its access to the controlled object.
  #[wasm_bindgen(getter, js_name = canDelegate)]
  pub fn can_delegate(&self) -> bool {
    self.0.can_delegate()
  }

  /// If this token can be delegated, this function will return
  /// a {@link DelegationToken} Transaction that will mint a new {@link DelegationToken}
  /// and send it to `recipient`.
  #[wasm_bindgen]
  pub fn delegate(
    &self,
    recipient: &str,
    #[wasm_bindgen(unchecked_param_type = "DelegatePermissions | undefined | null")] permissions: Option<u32>,
  ) -> Result<WasmTransactionBuilder> {
    let recipient = recipient.parse().wasm_result()?;
    let permissions = permissions.map(DelegatePermissions::from);

    let js_tx = self
      .0
      .delegate(recipient, permissions)
      .map(TransactionBuilder::into_inner)
      .map(WasmDelegateToken)
      .map(JsValue::from)
      .ok_or_else(|| JsError::new("this controller cannot delegate its authority"))?;

    Ok(WasmTransactionBuilder::new(js_tx.unchecked_into()))
  }
}

/// A token minted by a controller that allows another entity to act in
/// its stead - with full or reduced permissions.
#[wasm_bindgen(js_name = DelegationToken)]
pub struct WasmDelegationToken(pub(crate) DelegationToken);

#[wasm_bindgen(js_class = DelegationToken)]
impl WasmDelegationToken {
  /// Returns the ID of this {@link DelegationToken}.
  #[wasm_bindgen(getter)]
  pub fn id(&self) -> String {
    self.0.id().to_string()
  }

  /// Returns the ID of the {@link ControllerCap} that minted
  /// this {@link DelegationToken}.
  #[wasm_bindgen(getter)]
  pub fn controller(&self) -> String {
    self.0.controller().to_string()
  }

  /// Returns the ID of the object this token controls.
  #[wasm_bindgen(getter, js_name = controllerOf)]
  pub fn controller_of(&self) -> String {
    self.0.controller_of().to_string()
  }

  /// Returns the permissions of this token.
  #[wasm_bindgen(getter, unchecked_return_type = "DelegatePermissions")]
  pub fn permissions(&self) -> u32 {
    self.0.permissions().into()
  }
}

#[wasm_bindgen(js_name = DelegateToken)]
pub struct WasmDelegateToken(pub(crate) DelegateToken);

#[wasm_bindgen(js_class = DelegateToken)]
impl WasmDelegateToken {
  #[wasm_bindgen(constructor)]
  pub fn new(
    controller_cap: &WasmControllerCap,
    recipient: &str,
    #[wasm_bindgen(unchecked_param_type = "DelegatePermissions | undefined | null")] permissions: Option<u32>,
  ) -> Result<Self> {
    let recipient = recipient.parse().map_err(wasm_error)?;
    let token = if let Some(permissions) = permissions {
      DelegateToken::new_with_permissions(&controller_cap.0, recipient, permissions.into())
    } else {
      DelegateToken::new(&controller_cap.0, recipient)
    };
    Ok(Self(token))
  }

  #[wasm_bindgen(js_name = buildProgrammableTransaction)]
  pub async fn build_programmable_transaction(&self, client: &WasmIdentityClientReadOnly) -> Result<Vec<u8>> {
    let pt = self.0.build_programmable_transaction(&client.0).await.wasm_result()?;
    bcs::to_bytes(&pt).wasm_result()
  }

  #[wasm_bindgen]
  pub async fn apply(
    self,
    wasm_effects: &WasmIotaTransactionBlockEffects,
    client: &WasmIdentityClientReadOnly,
  ) -> Result<WasmDelegationToken> {
    let mut effects = wasm_effects.clone().into();
    let apply_result = self.0.apply(&mut effects, &client.0).await;
    let rem_wasm_effects = WasmIotaTransactionBlockEffects::from(&effects);
    Object::assign(wasm_effects, &rem_wasm_effects);

    apply_result.wasm_result().map(WasmDelegationToken)
  }
}

/// Transaction for revoking / unrevoking a {@link DelegationToken}.
/// If no `revoke` parameter is passed, or `true` is passed, this transaction
/// will *revoke* the passed token - *unrevoke* otherwise.
#[wasm_bindgen(js_name = DelegationTokenRevocation)]
pub struct WasmDelegationTokenRevocation(pub(crate) DelegationTokenRevocation);

#[wasm_bindgen(js_class = DelegationTokenRevocation)]
impl WasmDelegationTokenRevocation {
  #[wasm_bindgen(constructor)]
  pub fn new(
    identity: &WasmOnChainIdentity,
    controller_cap: &WasmControllerCap,
    delegation_token: &WasmDelegationToken,
    revoke: Option<bool>,
  ) -> Result<Self> {
    let revoke = revoke.unwrap_or(true);
    let identity = identity.0.try_read().wasm_result()?;

    let inner = if revoke {
      DelegationTokenRevocation::revoke(&identity, &controller_cap.0, &delegation_token.0).wasm_result()?
    } else {
      DelegationTokenRevocation::unrevoke(&identity, &controller_cap.0, &delegation_token.0).wasm_result()?
    };

    Ok(Self(inner))
  }

  /// Returns whether this transaction will revoke the given token.
  #[wasm_bindgen(js_name = isRevocation)]
  pub fn is_revocation(&self) -> bool {
    self.0.is_revocation()
  }

  /// Returns the ID of the token handled by this transaction.
  #[wasm_bindgen(js_name = tokenId)]
  pub fn token_id(&self) -> String {
    self.0.token_id().to_string()
  }

  #[wasm_bindgen(js_name = buildProgrammableTransaction)]
  pub async fn build_programmable_transaction(&self, client: &WasmIdentityClientReadOnly) -> Result<Vec<u8>> {
    let pt = self.0.build_programmable_transaction(&client.0).await.wasm_result()?;
    bcs::to_bytes(&pt).wasm_result()
  }

  #[wasm_bindgen]
  pub async fn apply(
    self,
    wasm_effects: &WasmIotaTransactionBlockEffects,
    client: &WasmIdentityClientReadOnly,
  ) -> Result<()> {
    let mut effects = wasm_effects.clone().into();
    let apply_result = self.0.apply(&mut effects, &client.0).await;
    let rem_wasm_effects = WasmIotaTransactionBlockEffects::from(&effects);
    Object::assign(wasm_effects, &rem_wasm_effects);

    apply_result.wasm_result()
  }
}

/// A transaction to delete a given {@link DelegationToken}.
#[wasm_bindgen(js_name = DeleteDelegationToken)]
pub struct WasmDeleteDelegationToken(pub(crate) DeleteDelegationToken);

#[wasm_bindgen(js_class = DeleteDelegationToken)]
impl WasmDeleteDelegationToken {
  #[wasm_bindgen(constructor)]
  pub fn new(identity: &WasmOnChainIdentity, delegation_token: WasmDelegationToken) -> Result<Self> {
    let identity = identity.0.try_read().wasm_result()?;
    let inner = DeleteDelegationToken::new(&identity, delegation_token.0).wasm_result()?;

    Ok(Self(inner))
  }

  #[wasm_bindgen(js_name = tokenId)]
  pub fn token_id(&self) -> String {
    self.0.token_id().to_string()
  }

  #[wasm_bindgen(js_name = buildProgrammableTransaction)]
  pub async fn build_programmable_transaction(&self, client: &WasmIdentityClientReadOnly) -> Result<Vec<u8>> {
    let pt = self.0.build_programmable_transaction(&client.0).await.wasm_result()?;
    bcs::to_bytes(&pt).wasm_result()
  }

  #[wasm_bindgen]
  pub async fn apply(
    self,
    wasm_effects: &WasmIotaTransactionBlockEffects,
    client: &WasmIdentityClientReadOnly,
  ) -> Result<()> {
    let mut effects = wasm_effects.clone().into();
    let apply_result = self.0.apply(&mut effects, &client.0).await;
    let rem_wasm_effects = WasmIotaTransactionBlockEffects::from(&effects);
    Object::assign(wasm_effects, &rem_wasm_effects);

    apply_result.wasm_result()
  }
}
