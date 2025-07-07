// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::OnChainIdentity;

use crate::rebased::iota::move_calls;

use crate::rebased::iota::move_calls::ControllerTokenRef;
use crate::rebased::iota::package::identity_package_id;
use crate::rebased::Error;
use async_trait::async_trait;
use iota_interaction::move_types::language_storage::TypeTag;
use iota_interaction::rpc_types::IotaExecutionStatus;
use iota_interaction::rpc_types::IotaTransactionBlockEffects;
use iota_interaction::rpc_types::IotaTransactionBlockEffectsAPI;
use iota_interaction::types::base_types::IotaAddress;
use iota_interaction::types::base_types::ObjectID;
use iota_interaction::types::id::UID;
use iota_interaction::types::object::Owner;
use iota_interaction::types::transaction::ProgrammableTransaction;
use iota_interaction::IotaTransactionBlockEffectsMutAPI;
use iota_interaction::MoveType;
use iota_interaction::OptionalSync;
use itertools::Itertools as _;
use product_common::core_client::CoreClientReadOnly;
use product_common::transaction::transaction_builder::Transaction;
use product_common::transaction::transaction_builder::TransactionBuilder;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use std::fmt::Display;
use std::ops::BitAnd;
use std::ops::BitAndAssign;
use std::ops::BitOr;
use std::ops::BitOrAssign;
use std::ops::BitXor;
use std::ops::BitXorAssign;
use std::ops::Not;

/// A token that proves ownership over an object.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ControllerToken {
  /// A Controller Capability.
  Controller(ControllerCap),
  /// A Delegation Token.
  Delegate(DelegationToken),
}

impl ControllerToken {
  /// Returns the ID of this [ControllerToken].
  pub fn id(&self) -> ObjectID {
    match self {
      Self::Controller(controller) => controller.id,
      Self::Delegate(delegate) => delegate.id,
    }
  }

  /// Returns the ID of the this token's controller.
  /// For [ControllerToken::Controller] this is the same as its ID, but
  /// for [ControllerToken::Delegate] this is [DelegationToken::controller].
  pub fn controller_id(&self) -> ObjectID {
    match self {
      Self::Controller(controller) => controller.id,
      Self::Delegate(delegate) => delegate.controller,
    }
  }

  /// Returns the ID of the object this token controls.
  pub fn controller_of(&self) -> ObjectID {
    match self {
      Self::Controller(controller) => controller.controller_of,
      Self::Delegate(delegate) => delegate.controller_of,
    }
  }

  /// Returns a reference to [ControllerCap], if this token is a [ControllerCap].
  pub fn as_controller(&self) -> Option<&ControllerCap> {
    match self {
      Self::Controller(controller) => Some(controller),
      Self::Delegate(_) => None,
    }
  }

  /// Attepts to return the [ControllerToken::Controller] variant of this [ControllerToken].
  pub fn try_controller(self) -> Option<ControllerCap> {
    match self {
      Self::Controller(controller) => Some(controller),
      Self::Delegate(_) => None,
    }
  }

  /// Returns a reference to [DelegationToken], if this token is a [DelegationToken].
  pub fn as_delegate(&self) -> Option<&DelegationToken> {
    match self {
      Self::Controller(_) => None,
      Self::Delegate(delegate) => Some(delegate),
    }
  }

  /// Attepts to return the [ControllerToken::Delegate] variant of this [ControllerToken].
  pub fn try_delegate(self) -> Option<DelegationToken> {
    match self {
      Self::Controller(_) => None,
      Self::Delegate(delegate) => Some(delegate),
    }
  }

  /// Returns the Move type of this token.
  pub fn move_type(&self, package: ObjectID) -> TypeTag {
    match self {
      Self::Controller(_) => ControllerCap::move_type(package),
      Self::Delegate(_) => DelegationToken::move_type(package),
    }
  }

  pub(crate) async fn controller_ref<C>(&self, client: &C) -> Result<ControllerTokenRef, Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    let obj_ref = client
      .get_object_ref_by_id(self.id())
      .await?
      .expect("token exists on-chain")
      .reference
      .to_object_ref();

    Ok(match self {
      Self::Controller(_) => ControllerTokenRef::Controller(obj_ref),
      Self::Delegate(_) => ControllerTokenRef::Delegate(obj_ref),
    })
  }

  #[inline(always)]
  fn as_type_name(&self) -> &'static str {
    match self {
      Self::Controller(_) => "ControllerCap",
      Self::Delegate(_) => "DelegationToken",
    }
  }
}

/// A token that authenticates its bearer as a controller of a specific shared object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControllerCap {
  #[serde(deserialize_with = "deserialize_from_uid")]
  id: ObjectID,
  controller_of: ObjectID,
  can_delegate: bool,
}

fn deserialize_from_uid<'de, D>(deserializer: D) -> Result<ObjectID, D::Error>
where
  D: Deserializer<'de>,
{
  UID::deserialize(deserializer).map(|uid| *uid.object_id())
}

impl MoveType for ControllerCap {
  fn move_type(package: ObjectID) -> TypeTag {
    format!("{package}::controller::ControllerCap")
      .parse()
      .expect("valid Move type")
  }
}

impl ControllerCap {
  /// Returns the ID of this [ControllerCap].
  pub fn id(&self) -> ObjectID {
    self.id
  }

  /// Returns the ID of the object this token controls.
  pub fn controller_of(&self) -> ObjectID {
    self.controller_of
  }

  /// Returns whether this controller is allowed to delegate
  /// its access to the controlled object.
  pub fn can_delegate(&self) -> bool {
    self.can_delegate
  }

  /// If this token can be delegated, this function will return
  /// a [DelegateTransaction] that will mint a new [DelegationToken]
  /// and send it to `recipient`.
  pub fn delegate(
    &self,
    recipient: IotaAddress,
    permissions: Option<DelegatePermissions>,
  ) -> Option<TransactionBuilder<DelegateToken>> {
    if !self.can_delegate {
      return None;
    }

    let tx = {
      let permissions = permissions.unwrap_or_default();
      DelegateToken::new_with_permissions(self, recipient, permissions)
    };

    Some(TransactionBuilder::new(tx))
  }
}

impl From<ControllerCap> for ControllerToken {
  fn from(cap: ControllerCap) -> Self {
    Self::Controller(cap)
  }
}

/// A token minted by a controller that allows another entity to act in
/// its stead - with full or reduced permissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationToken {
  #[serde(deserialize_with = "deserialize_from_uid")]
  id: ObjectID,
  permissions: DelegatePermissions,
  controller: ObjectID,
  controller_of: ObjectID,
}

impl DelegationToken {
  /// Returns the ID of this [DelegationToken].
  pub fn id(&self) -> ObjectID {
    self.id
  }

  /// Returns the ID of the [ControllerCap] that minted
  /// this [DelegationToken].
  pub fn controller(&self) -> ObjectID {
    self.controller
  }

  /// Returns the ID of the object this token controls.
  pub fn controller_of(&self) -> ObjectID {
    self.controller_of
  }

  /// Returns the permissions of this token.
  pub fn permissions(&self) -> DelegatePermissions {
    self.permissions
  }
}

impl From<DelegationToken> for ControllerToken {
  fn from(value: DelegationToken) -> Self {
    Self::Delegate(value)
  }
}

impl MoveType for DelegationToken {
  fn move_type(package: ObjectID) -> TypeTag {
    format!("{package}::controller::DelegationToken")
      .parse()
      .expect("valid Move type")
  }
}

/// Permissions of a [DelegationToken].
///
/// Permissions can be operated on as if they were bit vectors:
/// ```
/// use identity_iota_core::rebased::migration::DelegatePermissions;
///
/// let permissions = DelegatePermissions::CREATE_PROPOSAL | DelegatePermissions::APPROVE_PROPOSAL;
/// assert!(permissions & DelegatePermissions::DELETE_PROPOSAL == DelegatePermissions::NONE);
/// ```
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(transparent)]
pub struct DelegatePermissions(u32);

impl Default for DelegatePermissions {
  fn default() -> Self {
    Self(u32::MAX)
  }
}

impl From<u32> for DelegatePermissions {
  fn from(value: u32) -> Self {
    Self(value)
  }
}

impl From<DelegatePermissions> for u32 {
  fn from(value: DelegatePermissions) -> Self {
    value.0
  }
}

impl DelegatePermissions {
  /// No permissions.
  pub const NONE: Self = Self(0);
  /// Permission that enables the creation of new proposals.
  pub const CREATE_PROPOSAL: Self = Self(1);
  /// Permission that enables the approval of existing proposals.
  pub const APPROVE_PROPOSAL: Self = Self(1 << 1);
  /// Permission that enables the execution of existing proposals.
  pub const EXECUTE_PROPOSAL: Self = Self(1 << 2);
  /// Permission that enables the deletion of existing proposals.
  pub const DELETE_PROPOSAL: Self = Self(1 << 3);
  /// Permission that enables the remove of one's approval for an existing proposal.
  pub const REMOVE_APPROVAL: Self = Self(1 << 4);
  /// All permissions.
  pub const ALL: Self = Self(u32::MAX);

  /// Returns whether this set of permissions contains `permission`.
  /// ```
  /// use identity_iota_core::rebased::migration::DelegatePermissions;
  ///
  /// let all_permissions = DelegatePermissions::ALL;
  /// assert_eq!(
  ///   all_permissions.has(DelegatePermissions::CREATE_PROPOSAL),
  ///   true
  /// );
  /// ```
  pub fn has(&self, permission: Self) -> bool {
    *self | permission != Self::NONE
  }
}

impl Not for DelegatePermissions {
  type Output = Self;
  fn not(self) -> Self::Output {
    Self(!self.0)
  }
}
impl BitOr for DelegatePermissions {
  type Output = Self;
  fn bitor(self, rhs: Self) -> Self::Output {
    Self(self.0 | rhs.0)
  }
}
impl BitOrAssign for DelegatePermissions {
  fn bitor_assign(&mut self, rhs: Self) {
    self.0 |= rhs.0;
  }
}
impl BitAnd for DelegatePermissions {
  type Output = Self;
  fn bitand(self, rhs: Self) -> Self::Output {
    Self(self.0 & rhs.0)
  }
}
impl BitAndAssign for DelegatePermissions {
  fn bitand_assign(&mut self, rhs: Self) {
    self.0 &= rhs.0;
  }
}
impl BitXor for DelegatePermissions {
  type Output = Self;
  fn bitxor(self, rhs: Self) -> Self::Output {
    Self(self.0 ^ rhs.0)
  }
}
impl BitXorAssign for DelegatePermissions {
  fn bitxor_assign(&mut self, rhs: Self) {
    self.0 ^= rhs.0;
  }
}

/// A [Transaction] that creates a new [DelegationToken]
/// for a given [ControllerCap].
#[derive(Debug, Clone)]
pub struct DelegateToken {
  cap_id: ObjectID,
  permissions: DelegatePermissions,
  recipient: IotaAddress,
}

impl DelegateToken {
  /// Creates a new [DelegateToken] transaction that will create a new [DelegationToken] with all permissions
  /// for `controller_cap` and send it to `recipient`.
  pub fn new(controller_cap: &ControllerCap, recipient: IotaAddress) -> Self {
    Self::new_with_permissions(controller_cap, recipient, DelegatePermissions::default())
  }

  /// Same as [DelegateToken::new] but permissions for the new token can be specified.
  pub fn new_with_permissions(
    controller_cap: &ControllerCap,
    recipient: IotaAddress,
    permissions: DelegatePermissions,
  ) -> Self {
    Self {
      cap_id: controller_cap.id(),
      permissions,
      recipient,
    }
  }
}

#[cfg_attr(feature = "send-sync", async_trait)]
#[cfg_attr(not(feature = "send-sync"), async_trait(?Send))]
impl Transaction for DelegateToken {
  type Output = DelegationToken;
  type Error = Error;
  async fn build_programmable_transaction<C>(&self, client: &C) -> Result<ProgrammableTransaction, Self::Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    let package = identity_package_id(client).await?;
    let controller_cap_ref = client
      .get_object_ref_by_id(self.cap_id)
      .await?
      .expect("ControllerCap exists on-chain")
      .reference
      .to_object_ref();

    let ptb_bcs =
      move_calls::identity::delegate_controller_cap(controller_cap_ref, self.recipient, self.permissions.0, package)
        .await?;
    Ok(bcs::from_bytes(&ptb_bcs)?)
  }

  async fn apply<C>(self, effects: &mut IotaTransactionBlockEffects, client: &C) -> Result<Self::Output, Self::Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    if let IotaExecutionStatus::Failure { error } = effects.status() {
      return Err(Error::TransactionUnexpectedResponse(error.clone()));
    }

    let created_objects = effects
      .created()
      .iter()
      .enumerate()
      .filter(|(_, elem)| matches!(elem.owner, Owner::AddressOwner(addr) if addr == self.recipient))
      .map(|(i, obj)| (i, obj.object_id()));

    let is_target_token = |delegation_token: &DelegationToken| -> bool {
      delegation_token.controller == self.cap_id && delegation_token.permissions == self.permissions
    };
    let mut target_token_pos = None;
    let mut target_token = None;
    for (i, obj_id) in created_objects {
      match client.get_object_by_id(obj_id).await {
        Ok(token) if is_target_token(&token) => {
          target_token_pos = Some(i);
          target_token = Some(token);
          break;
        }
        _ => continue,
      }
    }

    let (Some(i), Some(token)) = (target_token_pos, target_token) else {
      return Err(Error::TransactionUnexpectedResponse(
        "failed to find the correct identity in this transaction's effects".to_owned(),
      ));
    };

    effects.created_mut().swap_remove(i);

    Ok(token)
  }
}

/// [Transaction] for revoking / unrevoking a [DelegationToken].
#[derive(Debug, Clone)]
pub struct DelegationTokenRevocation {
  identity_id: ObjectID,
  controller_cap_id: ObjectID,
  delegation_token_id: ObjectID,
  // `true` revokes the token, `false` un-revokes it.
  revoke: bool,
}

impl DelegationTokenRevocation {
  fn revocation_impl(
    identity: &OnChainIdentity,
    controller_cap: &ControllerCap,
    delegation_token: &DelegationToken,
    is_revocation: bool,
  ) -> Result<Self, Error> {
    if delegation_token.controller_of != identity.id() {
      return Err(Error::Identity(format!(
        "DelegationToken {} has no control over Identity {}",
        delegation_token.id,
        identity.id()
      )));
    }

    Ok(Self {
      identity_id: identity.id(),
      controller_cap_id: controller_cap.id(),
      delegation_token_id: delegation_token.id,
      revoke: is_revocation,
    })
  }
  /// Returns a new [DelegationTokenRevocation] that will revoke [DelegationToken] `delegation_token_id`.
  pub fn revoke(
    identity: &OnChainIdentity,
    controller_cap: &ControllerCap,
    delegation_token: &DelegationToken,
  ) -> Result<Self, Error> {
    Self::revocation_impl(identity, controller_cap, delegation_token, true)
  }

  /// Returns a new [DelegationTokenRevocation] that will un-revoke [DelegationToken] `delegation_token_id`.
  pub fn unrevoke(
    identity: &OnChainIdentity,
    controller_cap: &ControllerCap,
    delegation_token: &DelegationToken,
  ) -> Result<Self, Error> {
    Self::revocation_impl(identity, controller_cap, delegation_token, false)
  }

  /// Returns `true` if this transaction is used to revoke a token.
  pub fn is_revocation(&self) -> bool {
    self.revoke
  }

  /// Return the ID of the [DelegationToken] handled by this transaction.
  pub fn token_id(&self) -> ObjectID {
    self.delegation_token_id
  }
}

#[cfg_attr(feature = "send-sync", async_trait)]
#[cfg_attr(not(feature = "send-sync"), async_trait(?Send))]
impl Transaction for DelegationTokenRevocation {
  type Output = ();
  type Error = Error;

  async fn build_programmable_transaction<C>(&self, client: &C) -> Result<ProgrammableTransaction, Self::Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    let package = identity_package_id(client).await?;
    let identity_ref = client
      .get_object_ref_by_id(self.identity_id)
      .await?
      .expect("identity exists on-chain");
    let controller_cap_ref = client
      .get_object_ref_by_id(self.controller_cap_id)
      .await?
      .expect("controller_cap exists on-chain")
      .reference
      .to_object_ref();

    let tx_bytes = if self.is_revocation() {
      move_calls::identity::revoke_delegation_token(identity_ref, controller_cap_ref, self.delegation_token_id, package)
    } else {
      move_calls::identity::unrevoke_delegation_token(
        identity_ref,
        controller_cap_ref,
        self.delegation_token_id,
        package,
      )
    }?;

    Ok(bcs::from_bytes(&tx_bytes)?)
  }

  async fn apply<C>(self, effects: &mut IotaTransactionBlockEffects, _client: &C) -> Result<Self::Output, Self::Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    if let IotaExecutionStatus::Failure { error } = effects.status() {
      return Err(Error::TransactionUnexpectedResponse(error.clone()));
    }

    Ok(())
  }
}

/// [Transaction] for deleting a given [DelegationToken].
#[derive(Debug, Clone)]
pub struct DeleteDelegationToken {
  identity_id: ObjectID,
  delegation_token_id: ObjectID,
}

impl DeleteDelegationToken {
  /// Returns a new [DeleteDelegationToken] [Transaction], that will delete the given [DelegationToken].
  pub fn new(identity: &OnChainIdentity, delegation_token: DelegationToken) -> Result<Self, Error> {
    if identity.id() != delegation_token.controller_of {
      return Err(Error::Identity(format!(
        "DelegationToken {} has no control over Identity {}",
        delegation_token.id,
        identity.id()
      )));
    }

    Ok(Self {
      identity_id: identity.id(),
      delegation_token_id: delegation_token.id,
    })
  }

  /// Returns the ID of the [DelegationToken] to be deleted.
  pub fn token_id(&self) -> ObjectID {
    self.delegation_token_id
  }
}

#[cfg_attr(feature = "send-sync", async_trait)]
#[cfg_attr(not(feature = "send-sync"), async_trait(?Send))]
impl Transaction for DeleteDelegationToken {
  type Output = ();
  type Error = Error;

  async fn build_programmable_transaction<C>(&self, client: &C) -> Result<ProgrammableTransaction, Self::Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    let package = identity_package_id(client).await?;
    let identity_ref = client
      .get_object_ref_by_id(self.identity_id)
      .await?
      .ok_or_else(|| Error::ObjectLookup(format!("Identity {} doesn't exist on-chain", self.identity_id)))?;
    let delegation_token_ref = client
      .get_object_ref_by_id(self.delegation_token_id)
      .await?
      .ok_or_else(|| {
        Error::ObjectLookup(format!(
          "DelegationToken {} doesn't exist on-chain",
          self.delegation_token_id,
        ))
      })?
      .reference
      .to_object_ref();

    let tx_bytes = move_calls::identity::destroy_delegation_token(identity_ref, delegation_token_ref, package).await?;

    Ok(bcs::from_bytes(&tx_bytes)?)
  }

  async fn apply<C>(self, effects: &mut IotaTransactionBlockEffects, _client: &C) -> Result<Self::Output, Self::Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    if let IotaExecutionStatus::Failure { error } = effects.status() {
      return Err(Error::TransactionUnexpectedResponse(error.clone()));
    }

    let Some(deleted_token_pos) = effects
      .deleted()
      .iter()
      .find_position(|obj_ref| obj_ref.object_id == self.delegation_token_id)
      .map(|(pos, _)| pos)
    else {
      return Err(Error::TransactionUnexpectedResponse(format!(
        "DelegationToken {} wasn't deleted in this transaction",
        self.delegation_token_id,
      )));
    };

    effects.deleted_mut().swap_remove(deleted_token_pos);

    Ok(())
  }
}

/// An invalid [ControllerToken] was presented to a controller-restricted
/// [OnChainIdentity] operation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub struct InvalidControllerTokenForIdentity {
  /// The ID of the [OnChainIdentity] this operation attempted to access.
  pub identity: ObjectID,
  /// The presented controller token.
  pub controller_token: ControllerToken,
}

impl Display for InvalidControllerTokenForIdentity {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let token_type = self.controller_token.as_type_name();
    let token_id = self.controller_token.id();
    let identity_id = self.identity;

    write!(
      f,
      "the presented {token_type} `{token_id}` does not grant access to Identity `{identity_id}`"
    )
  }
}
