// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::rebased::iota::package::identity_package_id;
use crate::rebased::iota::package::identity_package_id_blocking;

use std::collections::HashMap;
use std::collections::HashSet;
use std::marker::PhantomData;
use std::ops::DerefMut as _;
use std::str::FromStr as _;

use crate::rebased::iota::move_calls;
use crate::rebased::migration::ControllerToken;

use crate::rebased::migration::Proposal;
use async_trait::async_trait;
use iota_sdk::transaction_builder::TransactionBuilder;
use iota_sdk::types::Address;
use iota_sdk::types::ObjectId;
use iota_sdk::types::TransactionEffects;
use iota_sdk::types::TypeTag;
use product_core::move_type::MoveType;
use product_core::move_type::UnknownTypeForNetwork;
use product_core::network::Network;
use product_core::operation::OperationBuilder;
use product_core::product_client::ProductClient;
use serde::Deserialize;
use serde::Serialize;

use crate::rebased::iota::types::Number;
use crate::rebased::migration::OnChainIdentity;
use crate::rebased::Error;

use super::CreateProposal;
use super::ExecuteProposal;
use super::ProposalBuilder;
use super::ProposalT;

/// [`Proposal`] action that modifies an [`OnChainIdentity`]'s configuration - e.g:
/// - remove controllers
/// - add controllers
/// - update controllers voting powers
/// - update threshold
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(try_from = "Modify")]
pub struct ConfigChange {
  threshold: Option<u64>,
  controllers_to_add: HashMap<Address, u64>,
  controllers_to_remove: HashSet<ObjectId>,
  controllers_voting_power: HashMap<ObjectId, u64>,
}

impl MoveType for ConfigChange {
  fn move_type(network: Network) -> Result<TypeTag, UnknownTypeForNetwork> {
    let package = match network {
      Network::Mainnet => "0x84cf5d12de2f9731a89bb519bc0c982a941b319a33abefdd5ed2054ad931de08",
      Network::Testnet => "0x222741bbdff74b42df48a7b4733185e9b24becb8ccfbafe8eac864ab4e4cc555",
      Network::Devnet => "0xe6fa03d273131066036f1d2d4c3d919b9abbca93910769f26a924c7a01811103",
      _ => identity_package_id_blocking(network)
        .map_err(|_| UnknownTypeForNetwork::new("Modify", network))?
        .to_string()
        .as_str(),
    };

    format!("{package}::config_proposal::Modify")
      .parse()
      .expect("valid TypeTag")
  }
}

impl ProposalBuilder<'_, '_, ConfigChange> {
  /// Sets a new value for the identity's threshold.
  pub fn threshold(mut self, threshold: u64) -> Self {
    self.set_threshold(threshold);
    self
  }

  /// Makes address `address` a new controller with voting power `voting_power`.
  pub fn add_controller(mut self, address: Address, voting_power: u64) -> Self {
    self.deref_mut().add_controller(address, voting_power);
    self
  }

  /// Adds multiple controllers. See [`ProposalBuilder::add_controller`].
  pub fn add_multiple_controllers<I>(mut self, controllers: I) -> Self
  where
    I: IntoIterator<Item = (Address, u64)>,
  {
    self.deref_mut().add_multiple_controllers(controllers);
    self
  }

  /// Removes an existing controller.
  pub fn remove_controller(mut self, controller_id: ObjectId) -> Self {
    self.deref_mut().remove_controller(controller_id);
    self
  }

  /// Removes many controllers.
  pub fn remove_multiple_controllers<I>(mut self, controllers: I) -> Self
  where
    I: IntoIterator<Item = ObjectId>,
  {
    self.deref_mut().remove_multiple_controllers(controllers);
    self
  }

  /// Sets a new voting power for a controller.
  pub fn update_controller(mut self, controller_id: ObjectId, voting_power: u64) -> Self {
    self.action.controllers_voting_power.insert(controller_id, voting_power);
    self
  }

  /// Updates many controllers' voting power.
  pub fn update_multiple_controllers<I>(mut self, controllers: I) -> Self
  where
    I: IntoIterator<Item = (ObjectId, u64)>,
  {
    let controllers_to_update = &mut self.action.controllers_voting_power;
    for (id, vp) in controllers {
      controllers_to_update.insert(id, vp);
    }

    self
  }
}

impl ConfigChange {
  /// Creates a new [`ConfigChange`] proposal action.
  pub fn new() -> Self {
    Self::default()
  }

  /// Sets the new threshold.
  pub fn set_threshold(&mut self, new_threshold: u64) {
    self.threshold = Some(new_threshold);
  }

  /// Returns the value for the new threshold.
  pub fn threshold(&self) -> Option<u64> {
    self.threshold
  }

  /// Returns the controllers that will be added, as the map [Address] -> [u64].
  pub fn controllers_to_add(&self) -> &HashMap<Address, u64> {
    &self.controllers_to_add
  }

  /// Returns the set of controllers that will be removed.
  pub fn controllers_to_remove(&self) -> &HashSet<ObjectId> {
    &self.controllers_to_remove
  }

  /// Returns the controllers that will be updated as the map [Address] -> [u64].
  pub fn controllers_to_update(&self) -> &HashMap<ObjectId, u64> {
    &self.controllers_voting_power
  }

  /// Adds a controller.
  pub fn add_controller(&mut self, address: Address, voting_power: u64) {
    self.controllers_to_add.insert(address, voting_power);
  }

  /// Adds many controllers.
  pub fn add_multiple_controllers<I>(&mut self, controllers: I)
  where
    I: IntoIterator<Item = (Address, u64)>,
  {
    for (addr, vp) in controllers {
      self.add_controller(addr, vp)
    }
  }

  /// Removes an existing controller.
  pub fn remove_controller(&mut self, controller_id: ObjectId) {
    self.controllers_to_remove.insert(controller_id);
  }

  /// Removes many controllers.
  pub fn remove_multiple_controllers<I>(&mut self, controllers: I)
  where
    I: IntoIterator<Item = ObjectId>,
  {
    for controller in controllers {
      self.remove_controller(controller)
    }
  }

  fn validate(&self, identity: &OnChainIdentity) -> Result<(), Error> {
    let new_threshold = self.threshold.unwrap_or(identity.threshold());
    let mut controllers = identity.controllers().clone();
    // check if update voting powers is valid
    for (controller, new_vp) in &self.controllers_voting_power {
      match controllers.get_mut(controller) {
        Some(vp) => *vp = *new_vp,
        None => {
          return Err(Error::InvalidConfig(format!(
            "object \"{controller}\" is not among identity \"{}\"'s controllers",
            identity.id()
          )))
        }
      }
    }
    // check if deleting controllers is valid
    for controller in &self.controllers_to_remove {
      if controllers.remove(controller).is_none() {
        return Err(Error::InvalidConfig(format!(
          "object \"{controller}\" is not among identity \"{}\"'s controllers",
          identity.id()
        )));
      }
    }
    // check if adding controllers is valid
    for (controller, vp) in &self.controllers_to_add {
      if controllers.insert((*controller).into(), *vp).is_some() {
        return Err(Error::InvalidConfig(format!(
          "object \"{controller}\" is already among identity \"{}\"'s controllers",
          identity.id()
        )));
      }
    }
    // check whether the new threshold allows to interact with the identity
    if new_threshold > controllers.values().sum::<u64>() {
      return Err(Error::InvalidConfig(
        "the resulting configuration will result in an unaccessible identity".to_string(),
      ));
    }
    Ok(())
  }
}

#[cfg_attr(not(feature = "send-sync"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync", async_trait)]
impl ProposalT for Proposal<ConfigChange> {
  type Action = ConfigChange;
  type Output = ();

  async fn create<'i>(
    action: Self::Action,
    expiration: Option<u64>,
    identity: &'i mut OnChainIdentity,
    controller_token: &ControllerToken,
    client: &impl ProductClient,
  ) -> Result<OperationBuilder<CreateProposal<'i, Self::Action>>, Error> {
    // Check the validity of the proposed changes.
    action.validate(identity)?;

    if identity.id() != controller_token.controller_of() {
      return Err(Error::Identity(format!(
        "token {} doesn't grant access to identity {}",
        controller_token.id(),
        identity.id()
      )));
    }

    let package = identity_package_id(client.network()).await?;
    let sender_vp = identity
      .controller_voting_power(controller_token.controller_id())
      .expect("controller exists");
    let chained_execution = sender_vp >= identity.threshold();
    let mut ptb = TransactionBuilder::new(Address::ZERO).with_client((*client).clone());
    move_calls::identity::propose_config_change(
      &mut ptb,
      identity.id(),
      controller_token,
      expiration,
      action.threshold,
      action.controllers_to_add,
      action.controllers_to_remove,
      action.controllers_voting_power,
      package,
    );

    Ok(OperationBuilder::new(CreateProposal {
      identity,
      tx: ptb,
      chained_execution,
      _action: PhantomData,
    }))
  }

  async fn into_tx<'i>(
    self,
    identity: &'i mut OnChainIdentity,
    controller_token: &ControllerToken,
    client: &impl ProductClient,
  ) -> Result<OperationBuilder<ExecuteProposal<'i, Self::Action>>, Error> {
    if identity.id() != controller_token.controller_of() {
      return Err(Error::Identity(format!(
        "token {} doesn't grant access to identity {}",
        controller_token.id(),
        identity.id()
      )));
    }

    let proposal_id = self.id();
    let package = identity_package_id(client.network()).await?;
    let mut ptb = TransactionBuilder::new(Address::ZERO).with_client((*client).clone());

    move_calls::identity::execute_config_change(&mut ptb, identity.id(), controller_token, proposal_id, package);

    Ok(OperationBuilder::new(ExecuteProposal {
      identity,
      tx: ptb,
      _action: PhantomData,
    }))
  }

  fn parse_tx_effects(_effects: &TransactionEffects) -> Result<Self::Output, Error> {
    Ok(())
  }
}

#[derive(Debug, Deserialize)]
struct Modify {
  threshold: Option<Number<u64>>,
  controllers_to_add: VecMap<Address, Number<u64>>,
  controllers_to_remove: HashSet<ObjectId>,
  controllers_to_update: VecMap<ObjectId, Number<u64>>,
}

impl TryFrom<Modify> for ConfigChange {
  type Error = <u64 as TryFrom<Number<u64>>>::Error;
  fn try_from(value: Modify) -> Result<Self, Self::Error> {
    let Modify {
      threshold,
      controllers_to_add,
      controllers_to_remove,
      controllers_to_update,
    } = value;
    let threshold = threshold.map(|num| num.try_into()).transpose()?;
    let controllers_to_add = controllers_to_add
      .contents
      .into_iter()
      .map(|Entry { key, value }| value.try_into().map(|n| (key, n)))
      .collect::<Result<_, _>>()?;
    let controllers_to_update = controllers_to_update
      .contents
      .into_iter()
      .map(|Entry { key, value }| value.try_into().map(|n| (key, n)))
      .collect::<Result<_, _>>()?;
    Ok(Self {
      threshold,
      controllers_to_add,
      controllers_to_remove,
      controllers_voting_power: controllers_to_update,
    })
  }
}
