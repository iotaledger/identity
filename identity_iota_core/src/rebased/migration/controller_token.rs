// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::OnChainIdentity;

use crate::IotaDID;

use crate::rebased::iota::package::identity_package_id;
use crate::rebased::iota::package::identity_package_id_blocking;
use crate::rebased::Error;
use futures::Stream;
use futures::StreamExt;
use iota_sdk::graphql_client::Client as IotaClient;
use iota_sdk::transaction_builder::TransactionBuilder;
use iota_sdk::types::Address;
use iota_sdk::types::ObjectId;
use iota_sdk::types::TransactionEffects;
use iota_sdk::types::TypeTag;
use itertools::Itertools as _;
use product_core::move_repr::deserialize_object_id_from_uid;
use product_core::move_type::MoveType;
use product_core::move_type::UnknownTypeForNetwork;
use product_core::network::Network;
use product_core::operation::Operation;
use product_core::operation::OperationBuilder;
use product_core::product_client::ProductClient;
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
  pub fn id(&self) -> ObjectId {
    match self {
      Self::Controller(controller) => controller.id,
      Self::Delegate(delegate) => delegate.id,
    }
  }

  /// Returns the ID of the this token's controller.
  /// For [ControllerToken::Controller] this is the same as its ID, but
  /// for [ControllerToken::Delegate] this is [DelegationToken::controller].
  pub fn controller_id(&self) -> ObjectId {
    match self {
      Self::Controller(controller) => controller.id,
      Self::Delegate(delegate) => delegate.controller,
    }
  }

  /// Returns the ID of the object this token controls.
  pub fn controller_of(&self) -> ObjectId {
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
  pub fn move_type(&self, network: Network) -> Result<TypeTag, UnknownTypeForNetwork> {
    match self {
      Self::Controller(_) => ControllerCap::move_type(network),
      Self::Delegate(_) => DelegationToken::move_type(network),
    }
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
  #[serde(deserialize_with = "deserialize_object_id_from_uid")]
  id: ObjectId,
  controller_of: ObjectId,
  can_delegate: bool,
}

impl MoveType for ControllerCap {
  fn move_type(network: Network) -> Result<TypeTag, UnknownTypeForNetwork> {
    let package = match network {
      Network::Mainnet => "0x84cf5d12de2f9731a89bb519bc0c982a941b319a33abefdd5ed2054ad931de08",
      Network::Testnet => "0x222741bbdff74b42df48a7b4733185e9b24becb8ccfbafe8eac864ab4e4cc555",
      Network::Devnet => "0xe6fa03d273131066036f1d2d4c3d919b9abbca93910769f26a924c7a01811103",
      _ => identity_package_id_blocking(network)
        .map_err(|_| UnknownTypeForNetwork::new("ControllerCap", network))?
        .to_string()
        .as_str(),
    };

    format!("{package}::controller::ControllerCap")
      .parse()
      .expect("valid TypeTag")
  }
}

impl ControllerCap {
  /// Returns the ID of this [ControllerCap].
  pub fn id(&self) -> ObjectId {
    self.id
  }

  /// Returns the ID of the object this token controls.
  pub fn controller_of(&self) -> ObjectId {
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
    recipient: Address,
    permissions: Option<DelegatePermissions>,
  ) -> Option<OperationBuilder<DelegateToken>> {
    if !self.can_delegate {
      return None;
    }

    let tx = {
      let permissions = permissions.unwrap_or_default();
      DelegateToken::new_with_permissions(self, recipient, permissions)
    };

    Some(OperationBuilder::new(tx))
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
  #[serde(deserialize_with = "deserialize_object_id_from_uid")]
  id: ObjectId,
  permissions: DelegatePermissions,
  controller: ObjectId,
  controller_of: ObjectId,
}

impl DelegationToken {
  /// Returns the ID of this [DelegationToken].
  pub fn id(&self) -> ObjectId {
    self.id
  }

  /// Returns the ID of the [ControllerCap] that minted
  /// this [DelegationToken].
  pub fn controller(&self) -> ObjectId {
    self.controller
  }

  /// Returns the ID of the object this token controls.
  pub fn controller_of(&self) -> ObjectId {
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
  fn move_type(network: Network) -> Result<TypeTag, UnknownTypeForNetwork> {
    let package = match network {
      Network::Mainnet => "0x84cf5d12de2f9731a89bb519bc0c982a941b319a33abefdd5ed2054ad931de08",
      Network::Testnet => "0x222741bbdff74b42df48a7b4733185e9b24becb8ccfbafe8eac864ab4e4cc555",
      Network::Devnet => "0xe6fa03d273131066036f1d2d4c3d919b9abbca93910769f26a924c7a01811103",
      _ => identity_package_id_blocking(network)
        .map_err(|_| UnknownTypeForNetwork::new("DelegationToken", network))?
        .to_string()
        .as_str(),
    };

    format!("{package}::controller::DelegationToken")
      .parse()
      .expect("valid TypeTag")
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

/// An [Operation] that creates a new [DelegationToken] for a given [ControllerCap].
#[derive(Debug, Clone)]
pub struct DelegateToken {
  cap_id: ObjectId,
  permissions: DelegatePermissions,
  recipient: Address,
}

impl DelegateToken {
  /// Creates a new [DelegateToken] transaction that will create a new [DelegationToken] with all permissions
  /// for `controller_cap` and send it to `recipient`.
  pub fn new(controller_cap: &ControllerCap, recipient: Address) -> Self {
    Self::new_with_permissions(controller_cap, recipient, DelegatePermissions::default())
  }

  /// Same as [DelegateToken::new] but permissions for the new token can be specified.
  pub fn new_with_permissions(
    controller_cap: &ControllerCap,
    recipient: Address,
    permissions: DelegatePermissions,
  ) -> Self {
    Self {
      cap_id: controller_cap.id(),
      permissions,
      recipient,
    }
  }
}

impl Operation for DelegateToken {
  type Output = DelegationToken;
  type Error = Error;

  async fn to_transaction(
    &self,
    client: &impl ProductClient,
    mut ptb: TransactionBuilder<IotaClient>,
  ) -> Result<TransactionBuilder<IotaClient>, Self::Error> {
    let package = identity_package_id(client.network()).await?;

    let cap = ptb.apply_argument(self.cap_id);
    let permissions = ptb.pure(self.permissions.into());
    let delegation_token = ptb
      .move_call(package, "controller", "delegate_with_permissions")
      .arguments([cap, permissions])
      .arg();
    ptb.transfer_objects(self.recipient, [delegation_token]);

    Ok(ptb)
  }

  async fn apply_effects(
    self,
    client: &impl ProductClient,
    tx_effects: &mut TransactionEffects,
  ) -> Result<Self::Output, Self::Error> {
    if let Some(tx_error) = tx_effects.status().error() {
      return Err(tx_error.into());
    }

    // Find the objects that were created in this transaction and are owned by the recipient.
    let possibly_valid_objects = tx_effects
      .as_v1()
      .changed_objects
      .iter()
      .filter_map(|obj| {
        (obj.id_operation.is_created() && obj.output_state.object_owner_opt() == Some(self.recipient.into()))
          .then_some(obj.object_id)
      })
      .collect();

    // Find the correct delegation token among the created objects.
    let delegation_token = client
      .objects_for_address(self.recipient, Some(&possibly_valid_objects))
      .next()
      .await
      .transpose()?
      .ok_or_else(|| Error::TransactionUnexpectedResponse("no DelegationToken was found".into()))?;

    // Remove the delegation token from the changed objects so it is not processed again later.
    let _ = tx_effects
      .as_mut_v1()
      .changed_objects
      .retain(|obj| obj.object_id != delegation_token.id());

    Ok(delegation_token)
  }
}

/// [Transaction] for revoking / unrevoking a [DelegationToken].
#[derive(Debug, Clone)]
pub struct DelegationTokenRevocation {
  identity_id: ObjectId,
  controller_cap_id: ObjectId,
  delegation_token_id: ObjectId,
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
  pub fn token_id(&self) -> ObjectId {
    self.delegation_token_id
  }
}

impl Operation for DelegationTokenRevocation {
  type Output = ();
  type Error = Error;

  async fn to_transaction(
    &self,
    client: &impl ProductClient,
    mut ptb: TransactionBuilder<IotaClient>,
  ) -> Result<TransactionBuilder<IotaClient>, Self::Error> {
    let package = identity_package_id(client.network()).await?;

    let cap = ptb.apply_argument(self.cap_id);
    let identity = ptb.apply_argument(self.identity_id);
    let delegation_token_id = ptb.pure(self.delegation_token_id);

    let fn_name = if self.is_revocation() {
      "revoke_token"
    } else {
      "unrevoke_token"
    };

    ptb
      .move_call(package, "identity", fn_name)
      .arguments([identity, cap, delegation_token_id]);

    Ok(ptb)
  }

  async fn apply_effects(
    self,
    client: &impl ProductClient,
    tx_effects: &mut TransactionEffects,
  ) -> Result<Self::Output, Self::Error> {
    if let Some(tx_error) = tx_effects.status().error() {
      Err(tx_error.into())
    } else {
      Ok(())
    }
  }
}

/// [Transaction] for deleting a given [DelegationToken].
#[derive(Debug, Clone)]
pub struct DeleteDelegationToken {
  identity_id: ObjectId,
  delegation_token_id: ObjectId,
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
  pub fn token_id(&self) -> ObjectId {
    self.delegation_token_id
  }
}

impl Operation for DeleteDelegationToken {
  type Output = ();
  type Error = Error;

  async fn to_transaction(
    &self,
    client: &impl ProductClient,
    mut ptb: TransactionBuilder<IotaClient>,
  ) -> Result<TransactionBuilder<IotaClient>, Self::Error> {
    let package = identity_package_id(client.network()).await?;

    let identity = ptb.apply_argument(self.identity_id);
    let delegation_token = ptb.apply_argument(self.delegation_token_id);

    ptb
      .move_call(package, "identity", "destroy_delegation_token")
      .arguments([identity, delegation_token]);

    Ok(ptb)
  }

  async fn apply_effects(
    self,
    client: &impl ProductClient,
    tx_effects: &mut TransactionEffects,
  ) -> Result<Self::Output, Self::Error> {
    if let Some(tx_error) = tx_effects.status().error() {
      return Err(tx_error.into());
    }

    if let Some((idx, _)) = tx_effects
      .as_v1()
      .changed_objects
      .iter()
      .find_position(|obj| obj.id_operation.is_deleted() && obj.object_id == self.delegation_token_id)
    {
      tx_effects.as_mut_v1().changed_objects.swap_remove(idx);
      Ok(())
    } else {
      Err(Error::TransactionUnexpectedResponse(format!(
        "DelegationToken {} wasn't deleted in this transaction",
        self.delegation_token_id,
      )))
    }
  }
}

/// An address tried to access a certain identity, but the operation
/// failed because the address is not an identity's controller.
#[derive(Debug, thiserror::Error)]
#[error("address '{address}' is not a controller of '{identity}'")]
#[non_exhaustive]
pub struct NotAController {
  /// The address that attempted to access an Identity.
  pub address: Address,
  /// The identity that tried to be accessed.
  pub identity: IotaDID,
}

/// A controller doesn't have enough voting power to perform a given operation.
#[derive(Debug, thiserror::Error)]
#[error(
  "controller '{controller_token_id}' has a voting power of {controller_voting_power}, but {required} is required"
)]
#[non_exhaustive]
pub struct InsufficientControllerVotingPower {
  /// ID of the controller token.
  pub controller_token_id: ObjectId,
  /// Voting power of the controller.
  pub controller_voting_power: u64,
  /// Required voting power.
  pub required: u64,
}

/// An invalid [ControllerToken] was presented to a controller-restricted
/// [OnChainIdentity] operation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub struct InvalidControllerTokenForIdentity {
  /// The ID of the [OnChainIdentity] this operation attempted to access.
  pub identity: ObjectId,
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
