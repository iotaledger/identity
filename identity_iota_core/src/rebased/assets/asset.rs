// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr as _;

use crate::rebased::client::IdentityClientReadOnly;
use crate::rebased::iota::move_calls;

use crate::rebased::Error;
use anyhow::anyhow;
use anyhow::Context;
use async_trait::async_trait;

use iota_interaction::ident_str;
use iota_interaction::move_types::language_storage::StructTag;
use iota_interaction::rpc_types::IotaData as _;
use iota_interaction::rpc_types::IotaExecutionStatus;
use iota_interaction::rpc_types::IotaObjectDataOptions;
use iota_interaction::rpc_types::IotaTransactionBlockEffects;
use iota_interaction::rpc_types::IotaTransactionBlockEffectsAPI as _;
use iota_interaction::types::base_types::IotaAddress;
use iota_interaction::types::base_types::ObjectID;
use iota_interaction::types::base_types::ObjectRef;
use iota_interaction::types::base_types::SequenceNumber;
use iota_interaction::types::id::UID;
use iota_interaction::types::object::Owner;
use iota_interaction::types::transaction::ProgrammableTransaction;
use iota_interaction::types::TypeTag;
use iota_interaction::IotaClientTrait;
use iota_interaction::IotaTransactionBlockEffectsMutAPI as _;
use iota_interaction::MoveType;
use iota_interaction::OptionalSync;
use product_common::core_client::CoreClientReadOnly;
use product_common::transaction::transaction_builder::Transaction;
use product_common::transaction::transaction_builder::TransactionBuilder;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use tokio::sync::OnceCell;

/// An on-chain asset that carries information about its owner and its creator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedAsset<T> {
  id: UID,
  #[serde(
    deserialize_with = "deserialize_inner",
    bound(deserialize = "T: for<'a> Deserialize<'a>")
  )]
  inner: T,
  owner: IotaAddress,
  origin: IotaAddress,
  mutable: bool,
  transferable: bool,
  deletable: bool,
}

fn deserialize_inner<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
  D: Deserializer<'de>,
  T: for<'a> Deserialize<'a>,
{
  use serde::de::Error as _;

  match std::any::type_name::<T>() {
    "u8" | "u16" | "u32" | "u64" | "u128" | "usize" | "i8" | "i16" | "i32" | "i64" | "i128" | "isize" => {
      String::deserialize(deserializer).and_then(|s| serde_json::from_str(&s).map_err(D::Error::custom))
    }
    _ => T::deserialize(deserializer),
  }
}

impl<T> AuthenticatedAsset<T>
where
  T: DeserializeOwned,
{
  /// Resolves an [`AuthenticatedAsset`] by its ID `id`.
  pub async fn get_by_id(id: ObjectID, client: &impl CoreClientReadOnly) -> Result<Self, Error> {
    let res = client
      .client_adapter()
      .read_api()
      .get_object_with_options(id, IotaObjectDataOptions::new().with_content())
      .await?;
    let Some(data) = res.data else {
      return Err(Error::ObjectLookup(res.error.map_or(String::new(), |e| e.to_string())));
    };
    data
      .content
      .ok_or_else(|| anyhow!("No content for object with ID {id}"))
      .and_then(|content| content.try_into_move().context("not a Move object"))
      .and_then(|obj_data| {
        serde_json::from_value(obj_data.fields.to_json_value()).context("failed to deserialize move object")
      })
      .map_err(|e| Error::ObjectLookup(e.to_string()))
  }
}

impl<T: MoveType + Send + Sync> AuthenticatedAsset<T> {
  async fn object_ref(&self, client: &impl CoreClientReadOnly) -> Result<ObjectRef, Error> {
    client
      .client_adapter()
      .read_api()
      .get_object_with_options(self.id(), IotaObjectDataOptions::default())
      .await?
      .object_ref_if_exists()
      .ok_or_else(|| Error::ObjectLookup("missing object reference in response".to_owned()))
  }

  /// Returns this [`AuthenticatedAsset`]'s ID.
  pub fn id(&self) -> ObjectID {
    *self.id.object_id()
  }

  /// Returns a reference to this [`AuthenticatedAsset`]'s content.
  pub fn content(&self) -> &T {
    &self.inner
  }

  /// Transfers ownership of this [`AuthenticatedAsset`] to `recipient`.
  /// # Notes
  /// This function doesn't perform the transfer right away, but instead creates a [`Transaction`] that
  /// can be executed to carry out the transfer.
  /// # Failures
  /// * Returns an [`Error::InvalidConfig`] if this asset is not transferable.
  pub fn transfer(
    self,
    recipient: IotaAddress,
    client: &IdentityClientReadOnly,
  ) -> Result<TransactionBuilder<TransferAsset<T>>, Error> {
    if !self.transferable {
      return Err(Error::InvalidConfig(format!(
        "`AuthenticatedAsset` {} is not transferable",
        self.id()
      )));
    }
    Ok(TransactionBuilder::new(TransferAsset::new(self, recipient, client)))
  }

  /// Destroys this [`AuthenticatedAsset`].
  /// # Notes
  /// This function doesn't delete the asset right away, but instead creates a [`Transaction`] that
  /// can be executed in order to destroy the asset.
  /// # Failures
  /// * Returns an [`Error::InvalidConfig`] if this asset cannot be deleted.
  pub fn delete(self, client: &IdentityClientReadOnly) -> Result<TransactionBuilder<DeleteAsset<T>>, Error> {
    if !self.deletable {
      return Err(Error::InvalidConfig(format!(
        "`AuthenticatedAsset` {} cannot be deleted",
        self.id()
      )));
    }

    Ok(TransactionBuilder::new(DeleteAsset::new(self, client)))
  }

  /// Changes this [`AuthenticatedAsset`]'s content.
  /// # Notes
  /// This function doesn't update the asset right away, but instead creates a [`Transaction`] that
  /// can be executed in order to update the asset's content.
  /// # Failures
  /// * Returns an [`Error::InvalidConfig`] if this asset cannot be updated.
  pub fn set_content(
    &mut self,
    new_content: T,
    client: &IdentityClientReadOnly,
  ) -> Result<TransactionBuilder<UpdateContent<'_, T>>, Error> {
    if !self.mutable {
      return Err(Error::InvalidConfig(format!(
        "`AuthenticatedAsset` {} is immutable",
        self.id()
      )));
    }

    Ok(TransactionBuilder::new(UpdateContent::new(self, new_content, client)))
  }
}

/// Builder-style struct to ease the creation of a new [`AuthenticatedAsset`].
#[derive(Debug)]
pub struct AuthenticatedAssetBuilder<T> {
  inner: T,
  mutable: bool,
  transferable: bool,
  deletable: bool,
}

impl<T: MoveType> MoveType for AuthenticatedAsset<T> {
  fn move_type(package: ObjectID) -> TypeTag {
    TypeTag::Struct(Box::new(StructTag {
      address: package.into(),
      module: ident_str!("asset").into(),
      name: ident_str!("AuthenticatedAsset").into(),
      type_params: vec![T::move_type(package)],
    }))
  }
}

impl<T> AuthenticatedAssetBuilder<T>
where
  T: MoveType + Send + Sync + DeserializeOwned + PartialEq,
{
  /// Initializes the builder with the asset's content.
  pub fn new(content: T) -> Self {
    Self {
      inner: content,
      mutable: false,
      transferable: false,
      deletable: false,
    }
  }

  /// Sets whether the new asset allows for its modification.
  ///
  /// By default an [`AuthenticatedAsset`] is **immutable**.
  pub fn mutable(mut self, mutable: bool) -> Self {
    self.mutable = mutable;
    self
  }

  /// Sets whether the new asset allows the transfer of its ownership.
  ///
  /// By default an [`AuthenticatedAsset`] **cannot** be transferred.
  pub fn transferable(mut self, transferable: bool) -> Self {
    self.transferable = transferable;
    self
  }

  /// Sets whether the new asset can be deleted.
  ///
  /// By default an [`AuthenticatedAsset`] **cannot** be deleted.
  pub fn deletable(mut self, deletable: bool) -> Self {
    self.deletable = deletable;
    self
  }

  /// Returns a [`Transaction`] that will create the specified [`AuthenticatedAsset`] when executed.
  pub fn finish(self, client: &IdentityClientReadOnly) -> TransactionBuilder<CreateAsset<T>> {
    TransactionBuilder::new(CreateAsset::new(self, client))
  }
}

/// Proposal for the transfer of an [`AuthenticatedAsset`]'s ownership from one [`IotaAddress`] to another.
///
/// # Detailed Workflow
/// A [`TransferProposal`] is a **shared** _Move_ object that represents a request to transfer ownership
/// of an [`AuthenticatedAsset`] to a new owner.
///
/// When a [`TransferProposal`] is created, it will seize the asset and send a `SenderCap` token to the current asset's
/// owner and a `RecipientCap` to the specified `recipient` address.
/// `recipient` can accept the transfer by presenting its `RecipientCap` (this prevents other users from claiming the
/// asset for themselves).
/// The current owner can cancel the proposal at any time - given the transfer hasn't been concluded yet - by presenting
/// its `SenderCap`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferProposal {
  id: UID,
  asset_id: ObjectID,
  sender_cap_id: ObjectID,
  sender_address: IotaAddress,
  recipient_cap_id: ObjectID,
  recipient_address: IotaAddress,
  done: bool,
}

impl MoveType for TransferProposal {
  fn move_type(package: ObjectID) -> TypeTag {
    TypeTag::Struct(Box::new(StructTag {
      address: package.into(),
      module: ident_str!("asset").into(),
      name: ident_str!("TransferProposal").into(),
      type_params: vec![],
    }))
  }
}

impl TransferProposal {
  /// Resolves a [`TransferProposal`] by its ID `id`.
  pub async fn get_by_id(id: ObjectID, client: &impl CoreClientReadOnly) -> Result<Self, Error> {
    let res = client
      .client_adapter()
      .read_api()
      .get_object_with_options(id, IotaObjectDataOptions::new().with_content())
      .await?;
    let Some(data) = res.data else {
      return Err(Error::ObjectLookup(res.error.map_or(String::new(), |e| e.to_string())));
    };
    data
      .content
      .ok_or_else(|| anyhow!("No content for object with ID {id}"))
      .and_then(|content| content.try_into_move().context("not a Move object"))
      .and_then(|obj_data| {
        serde_json::from_value(obj_data.fields.to_json_value()).context("failed to deserialize move object")
      })
      .map_err(|e| Error::ObjectLookup(e.to_string()))
  }

  async fn get_cap<C>(&self, cap_type: &str, client: &C) -> Result<ObjectRef, Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    let cap_tag = StructTag::from_str(&format!("{}::asset::{cap_type}", client.package_id()))
      .map_err(|e| Error::ParsingFailed(e.to_string()))?;
    let owner_address = match cap_type {
      "SenderCap" => self.sender_address,
      "RecipientCap" => self.recipient_address,
      _ => unreachable!(),
    };
    client
      .find_owned_ref_for_address(owner_address, cap_tag, |obj_data| {
        cap_type == "SenderCap" && self.sender_cap_id == obj_data.object_id
          || cap_type == "RecipientCap" && self.recipient_cap_id == obj_data.object_id
      })
      .await?
      .ok_or_else(|| {
        Error::MissingPermission(format!(
          "no owned `{cap_type}` for transfer proposal {}",
          self.id.object_id(),
        ))
      })
  }

  async fn asset_metadata(&self, client: &impl CoreClientReadOnly) -> anyhow::Result<(ObjectRef, TypeTag)> {
    let res = client
      .client_adapter()
      .read_api()
      .get_object_with_options(self.asset_id, IotaObjectDataOptions::default().with_type())
      .await?;
    let asset_ref = res
      .object_ref_if_exists()
      .context("missing object reference in response")?;
    let param_type = res
      .data
      .context("missing data")
      .and_then(|data| data.type_.context("missing type"))
      .and_then(StructTag::try_from)
      .and_then(|mut tag| {
        if tag.type_params.is_empty() {
          anyhow::bail!("no type parameter")
        } else {
          Ok(tag.type_params.remove(0))
        }
      })?;

    Ok((asset_ref, param_type))
  }

  async fn initial_shared_version(&self, client: &impl CoreClientReadOnly) -> anyhow::Result<SequenceNumber> {
    let owner = client
      .client_adapter()
      .read_api()
      .get_object_with_options(*self.id.object_id(), IotaObjectDataOptions::default().with_owner())
      .await?
      .owner()
      .context("missing owner information")?;
    match owner {
      Owner::Shared { initial_shared_version } => Ok(initial_shared_version),
      _ => anyhow::bail!("`TransferProposal` is not a shared object"),
    }
  }

  /// Accepts this [`TransferProposal`].
  /// # Warning
  /// This operation only has an effects when it's invoked by this [`TransferProposal`]'s `recipient`.
  pub fn accept(self, client: &IdentityClientReadOnly) -> TransactionBuilder<AcceptTransfer> {
    TransactionBuilder::new(AcceptTransfer::new(self, client))
  }

  /// Concludes or cancels this [`TransferProposal`].
  /// # Warning
  /// * This operation only has an effects when it's invoked by this [`TransferProposal`]'s `sender`.
  /// * Accepting a [`TransferProposal`] **doesn't** consume it from the ledger. This function must be used to correctly
  ///   consume both [`TransferProposal`] and `SenderCap`.
  pub fn conclude_or_cancel(self, client: &IdentityClientReadOnly) -> TransactionBuilder<ConcludeTransfer> {
    TransactionBuilder::new(ConcludeTransfer::new(self, client))
  }

  /// Returns this [`TransferProposal`]'s ID.
  pub fn id(&self) -> ObjectID {
    *self.id.object_id()
  }

  /// Returns this [`TransferProposal`]'s `sender`'s address.
  pub fn sender(&self) -> IotaAddress {
    self.sender_address
  }

  /// Returns this [`TransferProposal`]'s `recipient`'s address.
  pub fn recipient(&self) -> IotaAddress {
    self.recipient_address
  }

  /// Returns `true` if this [`TransferProposal`] is concluded.
  pub fn is_concluded(&self) -> bool {
    self.done
  }
}

/// A [`Transaction`] that updates an [`AuthenticatedAsset`]'s content.
#[derive(Debug)]
pub struct UpdateContent<'a, T> {
  asset: &'a mut AuthenticatedAsset<T>,
  new_content: T,
  cached_ptb: OnceCell<ProgrammableTransaction>,
  package: ObjectID,
}

impl<'a, T: MoveType + Send + Sync> UpdateContent<'a, T> {
  /// Returns a [Transaction] to update the content of `asset`.
  pub fn new(asset: &'a mut AuthenticatedAsset<T>, new_content: T, client: &IdentityClientReadOnly) -> Self {
    Self {
      asset,
      new_content,
      cached_ptb: OnceCell::new(),
      package: client.package_id(),
    }
  }

  async fn make_ptb(&self, client: &impl CoreClientReadOnly) -> Result<ProgrammableTransaction, Error> {
    let tx_bcs = move_calls::asset::update(self.asset.object_ref(client).await?, &self.new_content, self.package)?;

    Ok(bcs::from_bytes(&tx_bcs)?)
  }
}

#[cfg_attr(not(feature = "send-sync"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync", async_trait)]
impl<T> Transaction for UpdateContent<'_, T>
where
  T: MoveType + Send + Sync,
{
  type Output = ();
  type Error = Error;

  async fn build_programmable_transaction<C>(&self, client: &C) -> Result<ProgrammableTransaction, Self::Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    self.cached_ptb.get_or_try_init(|| self.make_ptb(client)).await.cloned()
  }
  async fn apply<C>(self, effects: &mut IotaTransactionBlockEffects, _client: &C) -> Result<Self::Output, Self::Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    if let IotaExecutionStatus::Failure { error } = effects.status() {
      return Err(Error::TransactionUnexpectedResponse(error.clone()));
    }

    if let Some(asset_pos) = effects
      .mutated()
      .iter()
      .enumerate()
      .find(|(_, obj)| obj.object_id() == self.asset.id())
      .map(|(i, _)| i)
    {
      effects.mutated_mut().swap_remove(asset_pos);
      self.asset.inner = self.new_content;
    }

    Ok(())
  }
}

/// A [`Transaction`] that deletes an [`AuthenticatedAsset`].
#[derive(Debug)]
pub struct DeleteAsset<T> {
  asset: AuthenticatedAsset<T>,
  cached_ptb: OnceCell<ProgrammableTransaction>,
  package: ObjectID,
}

impl<T: MoveType + Send + Sync> DeleteAsset<T> {
  /// Returns a [Transaction] to delete `asset`.
  pub fn new(asset: AuthenticatedAsset<T>, client: &IdentityClientReadOnly) -> Self {
    Self {
      asset,
      cached_ptb: OnceCell::new(),
      package: client.package_id(),
    }
  }

  async fn make_ptb(&self, client: &impl CoreClientReadOnly) -> Result<ProgrammableTransaction, Error> {
    let asset_ref = self.asset.object_ref(client).await?;
    let tx_bcs = move_calls::asset::delete::<T>(asset_ref, self.package)?;

    Ok(bcs::from_bytes(&tx_bcs)?)
  }
}

#[cfg_attr(not(feature = "send-sync"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync", async_trait)]
impl<T> Transaction for DeleteAsset<T>
where
  T: MoveType + Send + Sync,
{
  type Output = ();
  type Error = Error;

  async fn build_programmable_transaction<C>(&self, client: &C) -> Result<ProgrammableTransaction, Self::Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    self.cached_ptb.get_or_try_init(|| self.make_ptb(client)).await.cloned()
  }
  async fn apply<C>(self, effects: &mut IotaTransactionBlockEffects, _client: &C) -> Result<Self::Output, Self::Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    if let IotaExecutionStatus::Failure { error } = effects.status() {
      return Err(Error::TransactionUnexpectedResponse(error.clone()));
    }

    if let Some(asset_pos) = effects
      .deleted()
      .iter()
      .enumerate()
      .find_map(|(i, obj)| (obj.object_id == self.asset.id()).then_some(i))
    {
      effects.deleted_mut().swap_remove(asset_pos);
      Ok(())
    } else {
      Err(Error::TransactionUnexpectedResponse(format!(
        "cannot find asset {} in the list of delete objects",
        self.asset.id()
      )))
    }
  }
}
/// A [`Transaction`] that creates a new [`AuthenticatedAsset`].
#[derive(Debug)]
pub struct CreateAsset<T> {
  builder: AuthenticatedAssetBuilder<T>,
  cached_ptb: OnceCell<ProgrammableTransaction>,
  package: ObjectID,
}

impl<T: MoveType> CreateAsset<T> {
  /// Returns a [Transaction] to create the asset described by `builder`.
  pub fn new(builder: AuthenticatedAssetBuilder<T>, client: &IdentityClientReadOnly) -> Self {
    Self {
      builder,
      cached_ptb: OnceCell::new(),
      package: client.package_id(),
    }
  }

  async fn make_ptb(&self, _client: &impl CoreClientReadOnly) -> Result<ProgrammableTransaction, Error> {
    let AuthenticatedAssetBuilder {
      ref inner,
      mutable,
      transferable,
      deletable,
    } = self.builder;
    let pt_bcs = move_calls::asset::new_asset(inner, mutable, transferable, deletable, self.package)?;
    Ok(bcs::from_bytes(&pt_bcs)?)
  }
}

#[cfg_attr(not(feature = "send-sync"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync", async_trait)]
impl<T> Transaction for CreateAsset<T>
where
  T: MoveType + DeserializeOwned + PartialEq + Send + Sync,
{
  type Output = AuthenticatedAsset<T>;
  type Error = Error;

  async fn build_programmable_transaction<C>(&self, client: &C) -> Result<ProgrammableTransaction, Self::Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    self.cached_ptb.get_or_try_init(|| self.make_ptb(client)).await.cloned()
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
      .filter(|(_, obj)| obj.owner.is_address_owned())
      .map(|(i, obj)| (i, obj.object_id()));

    let is_target_asset = |asset: &AuthenticatedAsset<T>| -> bool {
      asset.inner == self.builder.inner
        && asset.transferable == self.builder.transferable
        && asset.mutable == self.builder.mutable
        && asset.deletable == self.builder.deletable
    };

    let mut target_asset_pos = None;
    let mut target_asset = None;
    for (i, obj_id) in created_objects {
      match AuthenticatedAsset::get_by_id(obj_id, client).await {
        Ok(asset) if is_target_asset(&asset) => {
          target_asset_pos = Some(i);
          target_asset = Some(asset);
          break;
        }
        _ => continue,
      }
    }

    let (Some(pos), Some(asset)) = (target_asset_pos, target_asset) else {
      return Err(Error::TransactionUnexpectedResponse(
        "failed to find the asset created by this operation in transaction's effects".to_owned(),
      ));
    };

    effects.created_mut().swap_remove(pos);

    Ok(asset)
  }
}

/// A [`Transaction`] that proposes the transfer of an [`AuthenticatedAsset`].
#[derive(Debug)]
pub struct TransferAsset<T> {
  asset: AuthenticatedAsset<T>,
  recipient: IotaAddress,
  cached_ptb: OnceCell<ProgrammableTransaction>,
  package: ObjectID,
}

impl<T: MoveType + Send + Sync> TransferAsset<T> {
  /// Returns a [Transaction] to transfer `asset` to `recipient`.
  pub fn new(asset: AuthenticatedAsset<T>, recipient: IotaAddress, client: &IdentityClientReadOnly) -> Self {
    Self {
      asset,
      recipient,
      cached_ptb: OnceCell::new(),
      package: client.package_id(),
    }
  }

  async fn make_ptb(&self, client: &impl CoreClientReadOnly) -> Result<ProgrammableTransaction, Error> {
    let bcs = move_calls::asset::transfer::<T>(self.asset.object_ref(client).await?, self.recipient, self.package)?;

    Ok(bcs::from_bytes(&bcs)?)
  }
}

#[cfg_attr(not(feature = "send-sync"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync", async_trait)]
impl<T> Transaction for TransferAsset<T>
where
  T: MoveType + Send + Sync,
{
  type Output = TransferProposal;
  type Error = Error;

  async fn build_programmable_transaction<C>(&self, client: &C) -> Result<ProgrammableTransaction, Self::Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    self.cached_ptb.get_or_try_init(|| self.make_ptb(client)).await.cloned()
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
      .filter(|(_, obj)| obj.owner.is_shared())
      .map(|(i, obj)| (i, obj.object_id()));

    let is_target_proposal = |proposal: &TransferProposal| -> bool {
      proposal.asset_id == self.asset.id() && proposal.recipient_address == self.recipient
    };

    let mut target_proposal_pos = None;
    let mut target_proposal = None;
    for (i, obj_id) in created_objects {
      match TransferProposal::get_by_id(obj_id, client).await {
        Ok(proposal) if is_target_proposal(&proposal) => {
          target_proposal_pos = Some(i);
          target_proposal = Some(proposal);
          break;
        }
        _ => continue,
      }
    }

    let (Some(pos), Some(proposal)) = (target_proposal_pos, target_proposal) else {
      return Err(Error::TransactionUnexpectedResponse(
        "failed to find the TransferProposal created by this operation in transaction's effects".to_owned(),
      ));
    };

    effects.created_mut().swap_remove(pos);

    Ok(proposal)
  }
}

/// A [`Transaction`] that accepts the transfer of an [`AuthenticatedAsset`].
#[derive(Debug)]
pub struct AcceptTransfer {
  proposal: TransferProposal,
  cached_ptb: OnceCell<ProgrammableTransaction>,
  package: ObjectID,
}

impl AcceptTransfer {
  /// Returns a [Transaction] to accept `proposal`.
  pub fn new(proposal: TransferProposal, client: &IdentityClientReadOnly) -> Self {
    Self {
      proposal,
      cached_ptb: OnceCell::new(),
      package: client.package_id(),
    }
  }

  async fn make_ptb<C>(&self, client: &C) -> Result<ProgrammableTransaction, Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    if self.proposal.done {
      return Err(Error::TransactionBuildingFailed(
        "the transfer has already been concluded".to_owned(),
      ));
    }

    let cap = self.proposal.get_cap("RecipientCap", client).await?;
    let (asset_ref, param_type) = self
      .proposal
      .asset_metadata(client)
      .await
      .map_err(|e| Error::ObjectLookup(e.to_string()))?;
    let initial_shared_version = self
      .proposal
      .initial_shared_version(client)
      .await
      .map_err(|e| Error::ObjectLookup(e.to_string()))?;
    let bcs = move_calls::asset::accept_proposal(
      (self.proposal.id(), initial_shared_version),
      cap,
      asset_ref,
      param_type,
      self.package,
    )?;

    Ok(bcs::from_bytes(&bcs)?)
  }
}

#[cfg_attr(not(feature = "send-sync"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync", async_trait)]
impl Transaction for AcceptTransfer {
  type Output = ();
  type Error = Error;

  async fn build_programmable_transaction<C>(&self, client: &C) -> Result<ProgrammableTransaction, Self::Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    self.cached_ptb.get_or_try_init(|| self.make_ptb(client)).await.cloned()
  }

  async fn apply<C>(self, effects: &mut IotaTransactionBlockEffects, _client: &C) -> Result<Self::Output, Self::Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    if let IotaExecutionStatus::Failure { error } = effects.status() {
      return Err(Error::TransactionUnexpectedResponse(error.clone()));
    }

    if let Some(i) = effects
      .deleted()
      .iter()
      .enumerate()
      // The tx was successful if the recipient cap was consumed.
      .find_map(|(i, obj)| (obj.object_id == self.proposal.recipient_cap_id).then_some(i))
    {
      effects.deleted_mut().swap_remove(i);
      Ok(())
    } else {
      Err(Error::TransactionUnexpectedResponse(format!(
        "transfer of asset {} through proposal {} wasn't successful",
        self.proposal.asset_id,
        self.proposal.id.object_id()
      )))
    }
  }
}

/// A [`Transaction`] that concludes the transfer of an [`AuthenticatedAsset`].
#[derive(Debug)]
pub struct ConcludeTransfer {
  proposal: TransferProposal,
  cached_ptb: OnceCell<ProgrammableTransaction>,
  package: ObjectID,
}

impl ConcludeTransfer {
  /// Returns a [Transaction] to consume `proposal`.
  pub fn new(proposal: TransferProposal, client: &IdentityClientReadOnly) -> Self {
    Self {
      proposal,
      cached_ptb: OnceCell::new(),
      package: client.package_id(),
    }
  }

  async fn make_ptb<C>(&self, client: &C) -> Result<ProgrammableTransaction, Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    let cap = self.proposal.get_cap("SenderCap", client).await?;
    let (asset_ref, param_type) = self
      .proposal
      .asset_metadata(client)
      .await
      .map_err(|e| Error::ObjectLookup(e.to_string()))?;
    let initial_shared_version = self
      .proposal
      .initial_shared_version(client)
      .await
      .map_err(|e| Error::ObjectLookup(e.to_string()))?;

    let tx_bcs = move_calls::asset::conclude_or_cancel(
      (self.proposal.id(), initial_shared_version),
      cap,
      asset_ref,
      param_type,
      self.package,
    )?;

    Ok(bcs::from_bytes(&tx_bcs)?)
  }
}

#[cfg_attr(not(feature = "send-sync"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync", async_trait)]
impl Transaction for ConcludeTransfer {
  type Output = ();
  type Error = Error;

  async fn build_programmable_transaction<C>(&self, client: &C) -> Result<ProgrammableTransaction, Self::Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    self.cached_ptb.get_or_try_init(|| self.make_ptb(client)).await.cloned()
  }

  async fn apply<C>(self, effects: &mut IotaTransactionBlockEffects, _client: &C) -> Result<Self::Output, Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    if let IotaExecutionStatus::Failure { error } = effects.status() {
      return Err(Error::TransactionUnexpectedResponse(error.clone()));
    }

    let mut idx_to_remove = effects
      .deleted()
      .iter()
      .enumerate()
      .filter_map(|(i, obj)| {
        (obj.object_id == *self.proposal.id.object_id() || obj.object_id == self.proposal.sender_cap_id).then_some(i)
      })
      .collect::<Vec<_>>();

    if idx_to_remove.len() < 2 {
      return Err(Error::TransactionUnexpectedResponse(format!(
        "conclusion or canceling of proposal {} wasn't successful",
        self.proposal.id.object_id()
      )));
    }

    // Ordering the list of indexis to remove is important to avoid invalidating the positions
    // of the objects in the list. If we remove them from the higher index to the lower this
    // shouldn't happen.
    idx_to_remove.sort_unstable();
    for i in idx_to_remove.into_iter().rev() {
      effects.deleted_mut().swap_remove(i);
    }

    Ok(())
  }
}
