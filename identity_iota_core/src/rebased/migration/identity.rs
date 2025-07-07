// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::collections::HashSet;
use std::error::Error as StdError;

use crate::rebased::iota::move_calls;

use crate::rebased::iota::package::identity_package_id;
use crate::rebased::proposals::access_sub_identity::AccessSubIdentityBuilder;
use iota_interaction::types::transaction::ProgrammableTransaction;
use iota_interaction::IotaKeySignature;
use iota_interaction::IotaTransactionBlockEffectsMutAPI as _;
use iota_interaction::OptionalSync;
use iota_sdk::types::error::IotaObjectResponseError;
use product_common::core_client::CoreClient;
use product_common::core_client::CoreClientReadOnly;
use product_common::network_name::NetworkName;
use product_common::transaction::transaction_builder::Transaction;
use product_common::transaction::transaction_builder::TransactionBuilder;
use secret_storage::Signer;
use tokio::sync::OnceCell;

use crate::rebased::iota::types::Number;
use crate::rebased::proposals::Upgrade;
use crate::IotaDID;
use crate::IotaDocument;

use crate::StateMetadataDocument;
use crate::StateMetadataEncoding;
use async_trait::async_trait;
use identity_core::common::Timestamp;
use iota_interaction::ident_str;
use iota_interaction::move_types::language_storage::StructTag;
use iota_interaction::rpc_types::IotaExecutionStatus;
use iota_interaction::rpc_types::IotaObjectData;
use iota_interaction::rpc_types::IotaObjectDataOptions;
use iota_interaction::rpc_types::IotaParsedData;
use iota_interaction::rpc_types::IotaParsedMoveObject;
use iota_interaction::rpc_types::IotaPastObjectResponse;
use iota_interaction::rpc_types::IotaTransactionBlockEffects;
use iota_interaction::rpc_types::IotaTransactionBlockEffectsAPI as _;
use iota_interaction::types::base_types::IotaAddress;
use iota_interaction::types::base_types::ObjectID;
use iota_interaction::types::id::UID;
use iota_interaction::types::object::Owner;
use iota_interaction::types::TypeTag;
use serde;
use serde::Deserialize;
use serde::Serialize;

use crate::rebased::client::IdentityClientReadOnly;
use crate::rebased::proposals::BorrowAction;
use crate::rebased::proposals::ConfigChange;
use crate::rebased::proposals::ControllerExecution;
use crate::rebased::proposals::ProposalBuilder;
use crate::rebased::proposals::SendAction;
use crate::rebased::proposals::UpdateDidDocument;
use crate::rebased::rebased_err;
use crate::rebased::Error;
use iota_interaction::IotaClientTrait;
use iota_interaction::MoveType;

use super::ControllerCap;
use super::ControllerToken;
use super::DelegationToken;
use super::DelegationTokenRevocation;
use super::DeleteDelegationToken;
use super::Multicontroller;
use super::UnmigratedAlias;

const MODULE: &str = "identity";
const NAME: &str = "Identity";
const HISTORY_DEFAULT_PAGE_SIZE: usize = 10;

/// The data stored in an on-chain identity.
pub(crate) struct IdentityData {
  pub(crate) id: UID,
  pub(crate) multicontroller: Multicontroller<Option<Vec<u8>>>,
  pub(crate) legacy_id: Option<ObjectID>,
  pub(crate) created: Timestamp,
  pub(crate) updated: Timestamp,
  pub(crate) version: u64,
  pub(crate) deleted: bool,
  pub(crate) deleted_did: bool,
}

/// An on-chain object holding a DID Document.
#[derive(Clone)]
pub enum Identity {
  /// A legacy IOTA Stardust's Identity.
  Legacy(UnmigratedAlias),
  /// An on-chain Identity.
  FullFledged(OnChainIdentity),
}

impl Identity {
  /// Returns the [`IotaDocument`] DID Document stored inside this [`Identity`].
  pub fn did_document(&self, network: &NetworkName) -> Result<IotaDocument, Error> {
    match self {
      Self::FullFledged(onchain_identity) => Ok(onchain_identity.did_doc.clone()),
      Self::Legacy(alias) => {
        let state_metadata = alias.state_metadata.as_deref().ok_or_else(|| {
          Error::DidDocParsingFailed("legacy stardust alias doesn't contain a DID Document".to_string())
        })?;
        let did = IotaDID::from_object_id(&alias.id.object_id().to_string(), network);
        StateMetadataDocument::unpack(state_metadata)
          .and_then(|state_metadata_doc| state_metadata_doc.into_iota_document(&did))
          .map_err(|e| Error::DidDocParsingFailed(e.to_string()))
      }
    }
  }
}

/// An on-chain entity that wraps an optional DID Document.
#[derive(Debug, Clone, Serialize)]
pub struct OnChainIdentity {
  id: UID,
  multi_controller: Multicontroller<Option<Vec<u8>>>,
  pub(crate) did_doc: IotaDocument,
  version: u64,
  deleted: bool,
  deleted_did: bool,
}

impl OnChainIdentity {
  /// Returns the [`ObjectID`] of this [`OnChainIdentity`].
  pub fn id(&self) -> ObjectID {
    *self.id.object_id()
  }

  /// Returns the [`IotaDocument`] contained in this [`OnChainIdentity`].
  pub fn did_document(&self) -> &IotaDocument {
    &self.did_doc
  }

  pub(crate) fn did_document_mut(&mut self) -> &mut IotaDocument {
    &mut self.did_doc
  }

  /// Returns whether the [IotaDocument] contained in this [OnChainIdentity] has been deleted.
  /// Once a DID Document is deleted, it cannot be reactivated.
  ///
  /// When calling [OnChainIdentity::did_document] on an Identity whose DID Document
  /// had been deleted, an *empty* and *deactivated* [IotaDocument] will be returned.
  pub fn has_deleted_did(&self) -> bool {
    self.deleted_did
  }

  /// Returns true if this [`OnChainIdentity`] is shared between multiple controllers.
  pub fn is_shared(&self) -> bool {
    self.multi_controller.controllers().len() > 1
  }

  /// Returns this [`OnChainIdentity`]'s list of active proposals.
  pub fn proposals(&self) -> &HashSet<ObjectID> {
    self.multi_controller.proposals()
  }

  /// Returns this [`OnChainIdentity`]'s controllers as the map: `controller_id -> controller_voting_power`.
  pub fn controllers(&self) -> &HashMap<ObjectID, u64> {
    self.multi_controller.controllers()
  }

  /// Returns the threshold required by this [`OnChainIdentity`] for executing a proposal.
  pub fn threshold(&self) -> u64 {
    self.multi_controller.threshold()
  }

  /// Returns the voting power of controller with ID `controller_id`, if any.
  pub fn controller_voting_power(&self, controller_id: ObjectID) -> Option<u64> {
    self.multi_controller.controller_voting_power(controller_id)
  }

  /// Returns a [ControllerToken] owned by `address` that grants access to this Identity.
  /// ## Notes
  /// [None] is returned if `address` doesn't own a valid [ControllerToken].
  pub async fn get_controller_token_for_address(
    &self,
    address: IotaAddress,
    client: &(impl CoreClientReadOnly + Sync),
  ) -> Result<Option<ControllerToken>, Error> {
    let maybe_controller_cap = client
      .find_object_for_address::<ControllerCap, _>(address, |token| token.controller_of() == self.id())
      .await;

    if let Ok(Some(controller_cap)) = maybe_controller_cap {
      return Ok(Some(controller_cap.into()));
    }

    client
      .find_object_for_address::<DelegationToken, _>(address, |token| token.controller_of() == self.id())
      .await
      .map(|maybe_delegate| maybe_delegate.map(ControllerToken::from))
      .map_err(|e| Error::RpcError(format!("{e:#}")))
  }

  /// Returns a [ControllerToken], owned by `client`'s sender address, that grants access to this Identity.
  /// ## Notes
  /// [None] is returned if `client`'s sender address doesn't own a valid [ControllerToken].
  pub async fn get_controller_token<S: Signer<IotaKeySignature> + OptionalSync>(
    &self,
    client: &(impl CoreClient<S> + Sync),
  ) -> Result<Option<ControllerToken>, Error> {
    self
      .get_controller_token_for_address(client.sender_address(), client)
      .await
  }

  pub(crate) fn multicontroller(&self) -> &Multicontroller<Option<Vec<u8>>> {
    &self.multi_controller
  }

  /// Updates this [`OnChainIdentity`]'s DID Document.
  pub fn update_did_document<'i, 'c>(
    &'i mut self,
    updated_doc: IotaDocument,
    controller_token: &'c ControllerToken,
  ) -> ProposalBuilder<'i, 'c, UpdateDidDocument> {
    ProposalBuilder::new(self, controller_token, UpdateDidDocument::new(updated_doc))
  }

  /// Updates this [`OnChainIdentity`]'s configuration.
  pub fn update_config<'i, 'c>(
    &'i mut self,
    controller_token: &'c ControllerToken,
  ) -> ProposalBuilder<'i, 'c, ConfigChange> {
    ProposalBuilder::new(self, controller_token, ConfigChange::default())
  }

  /// Deactivates the DID Document represented by this [`OnChainIdentity`].
  pub fn deactivate_did<'i, 'c>(
    &'i mut self,
    controller_token: &'c ControllerToken,
  ) -> ProposalBuilder<'i, 'c, UpdateDidDocument> {
    ProposalBuilder::new(self, controller_token, UpdateDidDocument::deactivate())
  }

  /// Deletes the DID Document contained in this [OnChainIdentity].
  pub fn delete_did<'i, 'c>(
    &'i mut self,
    controller_token: &'c ControllerToken,
  ) -> ProposalBuilder<'i, 'c, UpdateDidDocument> {
    ProposalBuilder::new(self, controller_token, UpdateDidDocument::delete())
  }

  /// Upgrades this [`OnChainIdentity`]'s version to match the package's.
  pub fn upgrade_version<'i, 'c>(
    &'i mut self,
    controller_token: &'c ControllerToken,
  ) -> ProposalBuilder<'i, 'c, Upgrade> {
    ProposalBuilder::new(self, controller_token, Upgrade)
  }

  /// Sends assets owned by this [`OnChainIdentity`] to other addresses.
  pub fn send_assets<'i, 'c>(
    &'i mut self,
    controller_token: &'c ControllerToken,
  ) -> ProposalBuilder<'i, 'c, SendAction> {
    ProposalBuilder::new(self, controller_token, SendAction::default())
  }

  /// Borrows assets owned by this [`OnChainIdentity`] to use them in a custom transaction.
  pub fn borrow_assets<'i, 'c>(
    &'i mut self,
    controller_token: &'c ControllerToken,
  ) -> ProposalBuilder<'i, 'c, BorrowAction> {
    ProposalBuilder::new(self, controller_token, BorrowAction::default())
  }

  /// Borrows a `ControllerCap` with ID `controller_cap` owned by this identity in a transaction.
  /// This proposal is used to perform operation on a sub-identity controlled
  /// by this one.
  pub fn controller_execution<'i, 'c>(
    &'i mut self,
    controller_cap: ObjectID,
    controller_token: &'c ControllerToken,
  ) -> ProposalBuilder<'i, 'c, ControllerExecution> {
    let action = ControllerExecution::new(controller_cap, self);
    ProposalBuilder::new(self, controller_token, action)
  }

  /// Perform an action on an Identity that is controlled by this Identity.
  pub fn access_sub_identity<'i, 'sub>(
    &'i mut self,
    sub_identity: &'sub mut OnChainIdentity,
    controller_token: &ControllerToken,
  ) -> AccessSubIdentityBuilder<'i, 'sub> {
    AccessSubIdentityBuilder::new(self, sub_identity, controller_token)
  }

  /// Returns historical data for this [`OnChainIdentity`].
  pub async fn get_history(
    &self,
    client: &IdentityClientReadOnly,
    last_version: Option<&IotaObjectData>,
    page_size: Option<usize>,
  ) -> Result<Vec<IotaObjectData>, Error> {
    let identity_ref = client
      .get_object_ref_by_id(self.id())
      .await?
      .ok_or_else(|| Error::InvalidIdentityHistory("no reference to identity loaded".to_string()))?;
    let object_id = identity_ref.object_id();

    let mut history: Vec<IotaObjectData> = vec![];
    let mut current_version = if let Some(last_version_value) = last_version {
      // starting version given, this will be skipped in paging
      last_version_value.clone()
    } else {
      // no version given, this version will be included in history
      let version = identity_ref.version();
      let response = client.get_past_object(object_id, version).await.map_err(rebased_err)?;
      let latest_version = if let IotaPastObjectResponse::VersionFound(response_value) = response {
        response_value
      } else {
        return Err(Error::InvalidIdentityHistory(format!(
          "could not find current version {version} of object {object_id}, response {response:?}"
        )));
      };
      history.push(latest_version.clone()); // include current version in history if we start from now
      latest_version
    };

    // limit lookup count to prevent locking on large histories
    let page_size = page_size.unwrap_or(HISTORY_DEFAULT_PAGE_SIZE);
    while history.len() < page_size {
      let lookup = get_previous_version(client, current_version).await?;
      if let Some(value) = lookup {
        current_version = value;
        history.push(current_version.clone());
      } else {
        break;
      }
    }

    Ok(history)
  }

  /// Returns a [Transaction] to revoke a [DelegationToken].
  pub fn revoke_delegation_token(
    &self,
    controller_capability: &ControllerCap,
    delegation_token: &DelegationToken,
  ) -> Result<TransactionBuilder<DelegationTokenRevocation>, Error> {
    DelegationTokenRevocation::revoke(self, controller_capability, delegation_token).map(TransactionBuilder::new)
  }

  /// Returns a [Transaction] to *un*revoke a [DelegationToken].
  pub fn unrevoke_delegation_token(
    &self,
    controller_capability: &ControllerCap,
    delegation_token: &DelegationToken,
  ) -> Result<TransactionBuilder<DelegationTokenRevocation>, Error> {
    DelegationTokenRevocation::unrevoke(self, controller_capability, delegation_token).map(TransactionBuilder::new)
  }

  /// Returns a [Transaction] to delete a [DelegationToken].
  pub fn delete_delegation_token(
    &self,
    delegation_token: DelegationToken,
  ) -> Result<TransactionBuilder<DeleteDelegationToken>, Error> {
    DeleteDelegationToken::new(self, delegation_token).map(TransactionBuilder::new)
  }
}

/// Returns the previous version of the given `history_item`.
pub fn has_previous_version(history_item: &IotaObjectData) -> Result<bool, Error> {
  if let Some(Owner::Shared { initial_shared_version }) = history_item.owner {
    Ok(history_item.version != initial_shared_version)
  } else {
    Err(Error::InvalidIdentityHistory(format!(
      "provided history item does not seem to be a valid identity; {history_item}"
    )))
  }
}

async fn get_previous_version(
  client: &IdentityClientReadOnly,
  iod: IotaObjectData,
) -> Result<Option<IotaObjectData>, Error> {
  client.get_previous_version(iod).await.map_err(rebased_err)
}

/// Returns the [`OnChainIdentity`] having ID `object_id`, if it exists.
pub async fn get_identity(
  client: &impl CoreClientReadOnly,
  object_id: ObjectID,
) -> Result<Option<OnChainIdentity>, Error> {
  use IdentityResolutionErrorKind::NotFound;

  match get_identity_impl(client, object_id).await {
    Ok(identity) => Ok(Some(identity)),
    Err(IdentityResolutionError { kind: NotFound, .. }) => Ok(None),
    Err(e) => {
      // Use anyhow to format the error in such a way that all its causes are displayed too.
      let formatted_err_msg = format!("{:#}", anyhow::Error::new(e));
      Err(Error::ObjectLookup(formatted_err_msg))
    }
  }
}

pub(crate) async fn get_identity_impl(
  client: &impl CoreClientReadOnly,
  object_id: ObjectID,
) -> Result<OnChainIdentity, IdentityResolutionError> {
  let response = client
    .client_adapter()
    .read_api()
    .get_object_with_options(object_id, IotaObjectDataOptions::new().with_content())
    .await
    .map_err(|e| IdentityResolutionError {
      kind: IdentityResolutionErrorKind::RpcError(e.into()),
      resolving: object_id,
    })?;

  if let Some(response_error) = response.error {
    match response_error {
      IotaObjectResponseError::NotExists { .. } | IotaObjectResponseError::Deleted { .. } => {
        return Err(IdentityResolutionError {
          resolving: object_id,
          kind: IdentityResolutionErrorKind::NotFound,
        })
      }
      _ => unreachable!(),
    }
  }

  let data = response.data.expect("already handled errors in response");
  let network = client.network_name();
  let did = IotaDID::from_object_id(&object_id.to_string(), network);
  let IdentityData {
    id,
    multicontroller,
    legacy_id,
    created,
    updated,
    version,
    deleted,
    deleted_did,
  } = unpack_identity_data(data)?;
  let legacy_did = legacy_id.map(|legacy_id| IotaDID::from_object_id(&legacy_id.to_string(), client.network_name()));

  let did_doc = multicontroller
    .controlled_value()
    .as_deref()
    .map(|did_doc_bytes| IotaDocument::from_iota_document_data(did_doc_bytes, true, &did, legacy_did, created, updated))
    .transpose()
    .map_err(|e| IdentityResolutionError {
      resolving: object_id,
      kind: IdentityResolutionErrorKind::InvalidDidDocument(e.into()),
    })?
    .unwrap_or_else(|| {
      let mut empty_did_doc = IotaDocument::new(network);
      empty_did_doc.metadata.deactivated = Some(true);

      empty_did_doc
    });

  Ok(OnChainIdentity {
    id,
    multi_controller: multicontroller,
    did_doc,
    version,
    deleted,
    deleted_did,
  })
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IdentityResolutionErrorKind {
  #[error("object lookup RPC request failed")]
  RpcError(#[source] Box<dyn StdError + Send + Sync>),
  #[error("object does not exist")]
  NotFound,
  #[error("invalid object type: expected `iota_identity::identity::Identity`, found `{0}`")]
  InvalidType(String),
  #[error("invalid or malformed DID Document")]
  InvalidDidDocument(#[source] Box<dyn StdError + Send + Sync>),
  #[error("malformed Identity object")]
  Malformed(#[source] Box<dyn StdError + Send + Sync>),
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[error("failed to resolve Identity `{resolving}`")]
pub struct IdentityResolutionError {
  pub resolving: ObjectID,
  #[source]
  pub kind: IdentityResolutionErrorKind,
}

fn is_identity(value: &IotaParsedMoveObject) -> bool {
  // if available we might also check if object stems from expected module
  // but how would this act upon package updates?
  value.type_.module.as_ident_str().as_str() == MODULE && value.type_.name.as_ident_str().as_str() == NAME
}

/// Unpack identity data from given `IotaObjectData`
///
/// # Errors:
/// * in case given data for DID is not an object
/// * parsing identity data from object fails
pub(crate) fn unpack_identity_data(data: IotaObjectData) -> Result<IdentityData, IdentityResolutionError> {
  let content = data.content.ok_or_else(|| IdentityResolutionError {
    resolving: data.object_id,
    kind: IdentityResolutionErrorKind::RpcError("no content in RPC response".into()),
  })?;

  let IotaParsedData::MoveObject(value) = content else {
    return Err(IdentityResolutionError {
      resolving: data.object_id,
      kind: IdentityResolutionErrorKind::InvalidType("Move Package".to_owned()),
    });
  };

  if !is_identity(&value) {
    return Err(IdentityResolutionError {
      resolving: data.object_id,
      kind: IdentityResolutionErrorKind::InvalidType(value.type_.to_canonical_string(true)),
    });
  }

  #[derive(Deserialize)]
  struct TempOnChainIdentity {
    id: UID,
    did_doc: Multicontroller<Option<Vec<u8>>>,
    legacy_id: Option<ObjectID>,
    created: Number<u64>,
    updated: Number<u64>,
    version: Number<u64>,
    deleted: bool,
    deleted_did: bool,
  }

  let TempOnChainIdentity {
    id,
    did_doc: multicontroller,
    legacy_id,
    created,
    updated,
    version,
    deleted,
    deleted_did,
  } = serde_json::from_value::<TempOnChainIdentity>(value.fields.to_json_value()).map_err(|err| {
    IdentityResolutionError {
      resolving: data.object_id,
      kind: IdentityResolutionErrorKind::Malformed(err.into()),
    }
  })?;

  // Parse DID document timestamps
  let created = {
    let timestamp_ms: u64 = created.try_into().expect("Move string-encoded u64 are valid u64");
    // `Timestamp` requires a timestamp expressed in seconds.
    Timestamp::from_unix(timestamp_ms as i64 / 1000).expect("On-chain clock produces valid timestamps")
  };
  let updated = {
    let timestamp_ms: u64 = updated.try_into().expect("Move string-encoded u64 are valid u64");
    // `Timestamp` requires a timestamp expressed in seconds.
    Timestamp::from_unix(timestamp_ms as i64 / 1000).expect("On-chain clock produces valid timestamps")
  };
  let version = version.try_into().expect("Move string-encoded u64 are valid u64");

  Ok(IdentityData {
    id,
    multicontroller,
    legacy_id,
    created,
    updated,
    version,
    deleted,
    deleted_did,
  })
}

impl From<OnChainIdentity> for IotaDocument {
  fn from(identity: OnChainIdentity) -> Self {
    identity.did_doc
  }
}

/// Builder-style struct to create a new [`OnChainIdentity`].
#[derive(Debug)]
pub struct IdentityBuilder {
  did_doc: IotaDocument,
  threshold: Option<u64>,
  controllers: HashMap<IotaAddress, (u64, bool)>,
}

impl IdentityBuilder {
  /// Initializes a new builder for an [`OnChainIdentity`], where the passed `did_doc` will be
  /// used as the identity's DID Document.
  /// ## Warning
  /// Validation of `did_doc` is deferred to [CreateIdentity].
  pub fn new(did_doc: IotaDocument) -> Self {
    Self {
      did_doc,
      threshold: None,
      controllers: HashMap::new(),
    }
  }

  /// Gives `address` the capability to act as a controller with voting power `voting_power`.
  pub fn controller(mut self, address: IotaAddress, voting_power: u64) -> Self {
    self.controllers.insert(address, (voting_power, false));
    self
  }

  /// Gives `address` the capability to act as a controller with voting power `voting_power` and
  /// the ability to delegate its access to third parties.
  pub fn controller_with_delegation(mut self, address: IotaAddress, voting_power: u64) -> Self {
    self.controllers.insert(address, (voting_power, true));
    self
  }

  /// Sets the identity's threshold.
  pub fn threshold(mut self, threshold: u64) -> Self {
    self.threshold = Some(threshold);
    self
  }

  /// Sets multiple controllers in a single step. See [`IdentityBuilder::controller`].
  pub fn controllers<I>(self, controllers: I) -> Self
  where
    I: IntoIterator<Item = (IotaAddress, u64)>,
  {
    controllers
      .into_iter()
      .fold(self, |builder, (addr, vp)| builder.controller(addr, vp))
  }

  /// Sets multiple controllers in a single step.
  /// Differently from [IdentityBuilder::controllers], this method requires
  /// the controller's data to be passed as the triple `(address, voting power, delegate-ability)`.
  /// A `true` value as the tuple's third value means the controller *CAN* delegate its access.
  pub fn controllers_with_delegation<I>(self, controllers: I) -> Self
  where
    I: IntoIterator<Item = (IotaAddress, u64, bool)>,
  {
    controllers.into_iter().fold(self, |builder, (addr, vp, can_delegate)| {
      if can_delegate {
        builder.controller_with_delegation(addr, vp)
      } else {
        builder.controller(addr, vp)
      }
    })
  }

  /// Turns this builder into a [`Transaction`], ready to be executed.
  pub fn finish(self) -> TransactionBuilder<CreateIdentity> {
    TransactionBuilder::new(CreateIdentity::new(self))
  }
}

impl MoveType for OnChainIdentity {
  fn move_type(package: ObjectID) -> TypeTag {
    TypeTag::Struct(Box::new(StructTag {
      address: package.into(),
      module: ident_str!("identity").into(),
      name: ident_str!("Identity").into(),
      type_params: vec![],
    }))
  }
}

/// A [`Transaction`] for creating a new [`OnChainIdentity`] from an [`IdentityBuilder`].
#[derive(Debug)]
pub struct CreateIdentity {
  builder: IdentityBuilder,
  cached_ptb: OnceCell<ProgrammableTransaction>,
}

impl CreateIdentity {
  /// Returns a new [CreateIdentity] [Transaction] from an [IdentityBuilder]
  pub fn new(builder: IdentityBuilder) -> CreateIdentity {
    Self {
      builder,
      cached_ptb: OnceCell::new(),
    }
  }

  async fn make_ptb(&self, client: &impl CoreClientReadOnly) -> Result<ProgrammableTransaction, Error> {
    let IdentityBuilder {
      did_doc,
      threshold,
      controllers,
    } = &self.builder;
    let package = identity_package_id(client).await?;
    let did_doc = StateMetadataDocument::from(did_doc.clone())
      .pack(StateMetadataEncoding::default())
      .map_err(|e| Error::DidDocSerialization(e.to_string()))?;
    let pt_bcs = if controllers.is_empty() {
      move_calls::identity::new_identity(Some(&did_doc), package).await?
    } else {
      let threshold = match threshold {
        Some(t) => t,
        None if controllers.len() == 1 => {
          &controllers
            .values()
            .next()
            .ok_or_else(|| Error::Identity("could not get controller".to_string()))?
            .0
        }
        None => {
          return Err(Error::TransactionBuildingFailed(
            "Missing field `threshold` in identity creation".to_owned(),
          ))
        }
      };
      let controllers = controllers
        .iter()
        .map(|(addr, (vp, can_delegate))| (*addr, *vp, *can_delegate));
      move_calls::identity::new_with_controllers(Some(&did_doc), controllers, *threshold, package).await?
    };

    Ok(bcs::from_bytes(&pt_bcs)?)
  }
}

#[cfg_attr(not(feature = "send-sync"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync", async_trait)]
impl Transaction for CreateIdentity {
  type Output = OnChainIdentity;
  type Error = Error;

  async fn build_programmable_transaction<C>(&self, client: &C) -> Result<ProgrammableTransaction, Self::Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    self.cached_ptb.get_or_try_init(|| self.make_ptb(client)).await.cloned()
  }

  async fn apply<C>(
    mut self,
    effects: &mut IotaTransactionBlockEffects,
    client: &C,
  ) -> Result<Self::Output, Self::Error>
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
      .filter(|(_, elem)| matches!(elem.owner, Owner::Shared { .. }))
      .map(|(i, obj)| (i, obj.object_id()));

    let target_did_bytes = StateMetadataDocument::from(self.builder.did_doc)
      .pack(StateMetadataEncoding::Json)
      .map_err(|e| Error::DidDocSerialization(e.to_string()))?;

    let is_target_identity = |identity: &OnChainIdentity| -> bool {
      let did_bytes = identity
        .multicontroller()
        .controlled_value()
        .as_deref()
        .unwrap_or_default();
      target_did_bytes == did_bytes && self.builder.threshold.unwrap_or(1) == identity.threshold()
    };

    let mut target_identity_pos = None;
    let mut target_identity = None;
    for (i, obj_id) in created_objects {
      match get_identity(client, obj_id).await {
        Ok(Some(identity)) if is_target_identity(&identity) => {
          target_identity_pos = Some(i);
          target_identity = Some(identity);
          break;
        }
        _ => continue,
      }
    }

    let (Some(i), Some(identity)) = (target_identity_pos, target_identity) else {
      return Err(Error::TransactionUnexpectedResponse(
        "failed to find the correct identity in this transaction's effects".to_owned(),
      ));
    };

    effects.created_mut().swap_remove(i);

    Ok(identity)
  }
}
