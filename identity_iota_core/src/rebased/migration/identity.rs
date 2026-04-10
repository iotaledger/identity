// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::collections::HashSet;
use std::error::Error as StdError;

use crate::rebased::iota::move_calls;

use crate::rebased::iota::package::identity_package_id;
use crate::rebased::iota::package::identity_package_id_blocking;
use crate::rebased::proposals::AccessSubIdentityBuilder;
use iota_sdk::graphql_client::Client;
use iota_sdk::transaction_builder::TransactionBuilder;
use iota_sdk::types::Address;
use iota_sdk::types::ObjectId;
use iota_sdk::types::Owner;
use iota_sdk::types::TransactionEffects;
use iota_sdk::types::TypeTag;
use product_core::move_repr::Uid;
use product_core::move_type::MoveType;
use product_core::move_type::UnknownTypeForNetwork;
use product_core::network::Network;
use product_core::operation::Operation;
use product_core::operation::OperationBuilder;
use product_core::product_client::ProductClient;
use secret_storage::Signer;

use crate::rebased::iota::types::Number;
use crate::rebased::proposals::Upgrade;
use crate::IotaDID;
use crate::IotaDocument;

use crate::StateMetadataDocument;
use crate::StateMetadataEncoding;
use identity_core::common::Timestamp;
use serde::Deserialize;
use serde::Serialize;

use crate::rebased::proposals::BorrowAction;
use crate::rebased::proposals::ConfigChange;
use crate::rebased::proposals::ControllerExecution;
use crate::rebased::proposals::ProposalBuilder;
use crate::rebased::proposals::SendAction;
use crate::rebased::proposals::UpdateDidDocument;
use crate::rebased::Error;

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
  pub(crate) id: Uid,
  pub(crate) multicontroller: Multicontroller<Option<Vec<u8>>>,
  pub(crate) legacy_id: Option<ObjectId>,
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
  pub fn did_document(&self, network: Network) -> Result<IotaDocument, Error> {
    match self {
      Self::FullFledged(onchain_identity) => Ok(onchain_identity.did_doc.clone()),
      Self::Legacy(alias) => {
        let state_metadata = alias.state_metadata.as_deref().ok_or_else(|| {
          Error::DidDocParsingFailed("legacy stardust alias doesn't contain a DID Document".to_string())
        })?;
        let did = IotaDID::from_object_id(*alias.id.object_id(), network);
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
  id: Uid,
  multi_controller: Multicontroller<Option<Vec<u8>>>,
  pub(crate) did_doc: IotaDocument,
  version: u64,
  deleted: bool,
  deleted_did: bool,
}

impl OnChainIdentity {
  /// Returns the [`ObjectId`] of this [`OnChainIdentity`].
  pub fn id(&self) -> ObjectId {
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
  pub fn proposals(&self) -> &HashSet<ObjectId> {
    self.multi_controller.proposals()
  }

  /// Returns this [`OnChainIdentity`]'s controllers as the map: `controller_id -> controller_voting_power`.
  pub fn controllers(&self) -> &HashMap<ObjectId, u64> {
    self.multi_controller.controllers()
  }

  /// Returns the threshold required by this [`OnChainIdentity`] for executing a proposal.
  pub fn threshold(&self) -> u64 {
    self.multi_controller.threshold()
  }

  /// Returns the voting power of controller with ID `controller_id`, if any.
  pub fn controller_voting_power(&self, controller_id: ObjectId) -> Option<u64> {
    self.multi_controller.controller_voting_power(controller_id)
  }

  /// Returns a [ControllerToken] owned by `address` that grants access to this Identity.
  /// ## Notes
  /// [None] is returned if `address` doesn't own a valid [ControllerToken].
  pub async fn get_controller_token_for_address(
    &self,
    address: Address,
    client: &impl ProductClient,
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
  pub async fn get_controller_token(
    &self,
    address: Address,
    client: &impl ProductClient,
  ) -> Result<Option<ControllerToken>, Error> {
    self.get_controller_token_for_address(address, client).await
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
  #[deprecated = "use `OnChainIdentity::access_sub_identity` instead."]
  pub fn controller_execution<'i, 'c>(
    &'i mut self,
    controller_cap: ObjectId,
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
  // pub async fn get_history(
  //   &self,
  //   client: &IdentityClientReadOnly,
  //   last_version: Option<&IotaObjectData>,
  //   page_size: Option<usize>,
  // ) -> Result<Vec<IotaObjectData>, Error> {
  //   let identity_ref = client
  //     .get_object_ref_by_id(self.id())
  //     .await?
  //     .ok_or_else(|| Error::InvalidIdentityHistory("no reference to identity loaded".to_string()))?;
  //   let object_id = identity_ref.object_id();

  //   let mut history: Vec<IotaObjectData> = vec![];
  //   let mut current_version = if let Some(last_version_value) = last_version {
  //     // starting version given, this will be skipped in paging
  //     last_version_value.clone()
  //   } else {
  //     // no version given, this version will be included in history
  //     let version = identity_ref.version();
  //     let response = client.get_past_object(object_id, version).await.map_err(rebased_err)?;
  //     let latest_version = if let IotaPastObjectResponse::VersionFound(response_value) = response {
  //       response_value
  //     } else {
  //       return Err(Error::InvalidIdentityHistory(format!(
  //         "could not find current version {version} of object {object_id}, response {response:?}"
  //       )));
  //     };
  //     history.push(latest_version.clone()); // include current version in history if we start from now
  //     latest_version
  //   };

  //   // limit lookup count to prevent locking on large histories
  //   let page_size = page_size.unwrap_or(HISTORY_DEFAULT_PAGE_SIZE);
  //   while history.len() < page_size {
  //     let lookup = get_previous_version(client, current_version).await?;
  //     if let Some(value) = lookup {
  //       current_version = value;
  //       history.push(current_version.clone());
  //     } else {
  //       break;
  //     }
  //   }

  //   Ok(history)
  // }

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

/// Returns the [`OnChainIdentity`] having ID `object_id`, if it exists.
pub async fn get_identity(client: &impl ProductClient, object_id: ObjectId) -> Result<Option<OnChainIdentity>, Error> {
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
  client: &impl ProductClient,
  object_id: ObjectId,
) -> Result<OnChainIdentity, IdentityResolutionError> {
  use IdentityResolutionErrorKind as ErrorKind;
  let resolution_error = |kind| IdentityResolutionError {
    resolving: object_id,
    kind,
  };

  let json_object = client
    .move_object_contents(object_id, None)
    .await
    .map_err(|e| resolution_error(ErrorKind::RpcError(e.into())))?
    .ok_or_else(|| resolution_error(ErrorKind::NotFound))?;

  let identity_data = unpack_identity_json_value(json_object, object_id)?;
  let did = IotaDID::from_object_id(object_id, client.network());
  let legacy_did = identity_data
    .legacy_id
    .map(|id| IotaDID::from_object_id(id, client.network()));

  let did_doc = identity_data
    .multicontroller
    .controlled_value()
    .as_deref()
    .map(|did_doc_bytes| {
      IotaDocument::from_iota_document_data(
        did_doc_bytes,
        true,
        &did,
        legacy_did,
        identity_data.created,
        identity_data.updated,
      )
    })
    .transpose()
    .map_err(|e| IdentityResolutionError {
      resolving: object_id,
      kind: IdentityResolutionErrorKind::InvalidDidDocument(e.into()),
    })?
    .unwrap_or_else(|| {
      let mut empty_did_doc = IotaDocument::new(client.network());
      empty_did_doc.metadata.deactivated = Some(true);

      empty_did_doc
    });

  Ok(OnChainIdentity {
    id: identity_data.id,
    multi_controller: identity_data.multicontroller,
    did_doc,
    version: identity_data.version,
    deleted: identity_data.deleted,
    deleted_did: identity_data.deleted_did,
  })
}

/// Type of failures that can be encountered when resolving an Identity.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IdentityResolutionErrorKind {
  /// RPC request to an IOTA Node failed.
  #[error("object lookup RPC request failed")]
  RpcError(#[source] Box<dyn StdError + Send + Sync>),
  /// The queried object ID doesn't exist on-chain.
  #[error("Identity does not exist")]
  NotFound,
  /// Type.
  #[error("invalid object type: expected `iota_identity::identity::Identity`, found `{0}`")]
  InvalidType(String),
  /// Malformed DID Document.
  #[error("invalid or malformed DID Document")]
  InvalidDidDocument(#[source] Box<dyn StdError + Send + Sync>),
  /// Malformed Identity object
  #[error("malformed Identity object")]
  Malformed(#[source] Box<dyn StdError + Send + Sync>),
}

/// Failed to resolve an Identity by its ID.
#[derive(Debug, thiserror::Error)]
#[error("failed to resolve Identity `{resolving}`")]
#[non_exhaustive]
pub struct IdentityResolutionError {
  /// The Identity's ID.
  pub resolving: ObjectId,
  /// Specific type of failure for this error.
  #[source]
  pub kind: IdentityResolutionErrorKind,
}

/// Unpack identity data from given `IotaObjectData`
///
/// # Errors:
/// * in case given data for DID is not an object
/// * parsing identity data from object fails
pub(crate) fn unpack_identity_json_value(
  value: serde_json::Value,
  resolving: ObjectId,
) -> Result<IdentityData, IdentityResolutionError> {
  #[derive(Deserialize)]
  struct TempOnChainIdentity {
    id: Uid,
    did_doc: Multicontroller<Option<Vec<u8>>>,
    legacy_id: Option<ObjectId>,
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
      resolving,
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
  controllers: HashMap<Address, (u64, bool)>,
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
  pub fn controller(mut self, address: Address, voting_power: u64) -> Self {
    self.controllers.insert(address, (voting_power, false));
    self
  }

  /// Gives `address` the capability to act as a controller with voting power `voting_power` and
  /// the ability to delegate its access to third parties.
  pub fn controller_with_delegation(mut self, address: Address, voting_power: u64) -> Self {
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
    I: IntoIterator<Item = (Address, u64)>,
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
    I: IntoIterator<Item = (Address, u64, bool)>,
  {
    controllers.into_iter().fold(self, |builder, (addr, vp, can_delegate)| {
      if can_delegate {
        builder.controller_with_delegation(addr, vp)
      } else {
        builder.controller(addr, vp)
      }
    })
  }

  /// Turns this builder into an [`Operation`], ready to be executed.
  pub fn finish(self) -> OperationBuilder<CreateIdentity> {
    OperationBuilder::new(CreateIdentity::new(self))
  }
}

impl MoveType for OnChainIdentity {
  fn move_type(network: Network) -> Result<TypeTag, UnknownTypeForNetwork> {
    let package = match network {
      Network::Mainnet => "0x84cf5d12de2f9731a89bb519bc0c982a941b319a33abefdd5ed2054ad931de08",
      Network::Testnet => "0x222741bbdff74b42df48a7b4733185e9b24becb8ccfbafe8eac864ab4e4cc555",
      Network::Devnet => "0xe6fa03d273131066036f1d2d4c3d919b9abbca93910769f26a924c7a01811103",
      _ => identity_package_id_blocking(network)
        .map_err(|_| UnknownTypeForNetwork::new("Identity", network))?
        .to_string()
        .as_str(),
    };

    format!("{package}::identity::Identity").parse().expect("valid TypeTag")
  }
}

/// An [`Operation`] for creating a new [`OnChainIdentity`] from an [`IdentityBuilder`].
#[derive(Debug)]
pub struct CreateIdentity {
  builder: IdentityBuilder,
}

impl CreateIdentity {
  /// Returns a new [CreateIdentity] [Transaction] from an [IdentityBuilder]
  pub fn new(builder: IdentityBuilder) -> CreateIdentity {
    Self { builder }
  }
}

impl Operation for CreateIdentity {
  type Output = OnChainIdentity;
  type Error = Error;

  async fn to_transaction(
    &self,
    client: &impl ProductClient,
    ptb: TransactionBuilder<Client>,
  ) -> Result<TransactionBuilder<Client>, Self::Error> {
    let IdentityBuilder {
      did_doc,
      threshold,
      controllers,
    } = &self.builder;
    let package = identity_package_id(client.network()).await?;
    let did_doc = StateMetadataDocument::from(did_doc.clone())
      .pack(StateMetadataEncoding::default())
      .map_err(|e| Error::DidDocSerialization(e.to_string()))?;
    let mut ptb = TransactionBuilder::new(Address::ZERO).with_client((*client).clone());
    if controllers.is_empty() {
      move_calls::identity::new_identity(&mut ptb, Some(&did_doc), package);
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
      move_calls::identity::new_with_controllers(&mut ptb, Some(&did_doc), controllers, *threshold, package);
    };

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

    let target_did_bytes = StateMetadataDocument::from(self.did_document)
      .pack(StateMetadataEncoding::Json)
      .map_err(|e| Error::DidDocSerialization(e.to_string()))?;

    let is_target_identity = |identity: &OnChainIdentity| -> bool {
      let did_bytes = identity
        .multicontroller()
        .controlled_value()
        .as_deref()
        .unwrap_or_default();
      target_did_bytes == did_bytes && identity.threshold() == 1
    };

    let create_identity_candidates = tx_effects
      .as_v1()
      .changed_objects
      .iter()
      .filter(|obj| obj.id_operation.is_created() && obj.output_state.object_owner_opt().is_some_and(Owner::is_shared))
      .map(|obj| obj.object_id);

    let mut target_identity = None;
    for id in create_identity_candidates {
      let Some(identity) = get_identity(client, id).await? else {
        continue;
      };

      if is_target_identity(&identity) {
        target_identity = Some(identity);
      }
    }

    if let Some(identity) = target_identity {
      tx_effects
        .as_mut_v1()
        .changed_objects
        .retain(|obj| obj.object_id != identity.id().to_object_id());
      Ok(identity.did_doc)
    } else {
      Err(Error::TransactionUnexpectedResponse(
        "failed to find the correct identity in this transaction's effects".to_owned(),
      ))
    }
  }
}
