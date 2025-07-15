// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::collections::HashSet;

use crate::rebased::iota::types::Bag;
use crate::rebased::iota::types::Number;
use iota_interaction::types::base_types::ObjectID;
use iota_interaction::types::collection_types::Entry;
use iota_interaction::types::collection_types::VecMap;
use iota_interaction::types::collection_types::VecSet;
use iota_interaction::types::id::UID;
use serde::Deserialize;
use serde::Serialize;

/// A [`Multicontroller`]'s proposal for changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
  try_from = "IotaProposal::<T>",
  into = "IotaProposal::<T>",
  bound(serialize = "T: Serialize + Clone")
)]
pub struct Proposal<T> {
  id: UID,
  expiration_epoch: Option<u64>,
  votes: u64,
  voters: HashSet<ObjectID>,
  pub(crate) action: T,
}

impl<T> Proposal<T> {
  /// Returns this [Proposal]'s ID.
  pub fn id(&self) -> ObjectID {
    *self.id.object_id()
  }

  /// Returns the votes received by this [`Proposal`].
  pub fn votes(&self) -> u64 {
    self.votes
  }

  pub(crate) fn votes_mut(&mut self) -> &mut u64 {
    &mut self.votes
  }

  /// Returns a reference to the action contained by this [`Proposal`].
  pub fn action(&self) -> &T {
    &self.action
  }

  /// Consumes the [`Proposal`] returning its action.
  pub fn into_action(self) -> T {
    self.action
  }

  /// Returns the set of voters' IDs.
  pub fn voters(&self) -> &HashSet<ObjectID> {
    &self.voters
  }

  /// Returns the epoch ID for this proposal's expiration.
  pub fn expiration_epoch(&self) -> Option<u64> {
    self.expiration_epoch
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IotaProposal<T> {
  id: UID,
  expiration_epoch: Option<Number<u64>>,
  votes: Number<u64>,
  voters: VecSet<ObjectID>,
  action: T,
}

impl<T> TryFrom<IotaProposal<T>> for Proposal<T> {
  type Error = <u64 as TryFrom<Number<u64>>>::Error;
  fn try_from(proposal: IotaProposal<T>) -> Result<Self, Self::Error> {
    let IotaProposal {
      id,
      expiration_epoch,
      votes,
      voters,
      action,
    } = proposal;
    let expiration_epoch = expiration_epoch.map(TryInto::try_into).transpose()?;
    let votes = votes.try_into()?;
    let voters = voters.contents.into_iter().collect();

    Ok(Self {
      id,
      expiration_epoch,
      votes,
      voters,
      action,
    })
  }
}

impl<T> From<Proposal<T>> for IotaProposal<T> {
  fn from(value: Proposal<T>) -> Self {
    let Proposal {
      id,
      expiration_epoch,
      votes,
      voters,
      action,
    } = value;
    let contents = voters.into_iter().collect();
    IotaProposal {
      id,
      expiration_epoch: expiration_epoch.map(Into::into),
      votes: votes.into(),
      voters: VecSet { contents },
      action,
    }
  }
}

/// Representation of `identity`'s `multicontroller::Multicontroller` Move type.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "IotaMulticontroller::<T>")]
pub struct Multicontroller<T> {
  controlled_value: T,
  controllers: HashMap<ObjectID, u64>,
  threshold: u64,
  active_proposals: HashSet<ObjectID>,
  proposals: Bag,
}

impl<T> Multicontroller<T> {
  /// Returns a reference to the value that is shared between many controllers.
  pub fn controlled_value(&self) -> &T {
    &self.controlled_value
  }

  /// Returns this [`Multicontroller`]'s threshold.
  pub fn threshold(&self) -> u64 {
    self.threshold
  }

  /// Returns the lists of active [`Proposal`]s for this [`Multicontroller`].
  pub fn proposals(&self) -> &HashSet<ObjectID> {
    &self.active_proposals
  }

  pub(crate) fn proposals_bag_id(&self) -> ObjectID {
    *self.proposals.id.object_id()
  }

  /// Returns the voting power for controller with ID `controller_cap_id`, if any.
  pub fn controller_voting_power(&self, controller_cap_id: ObjectID) -> Option<u64> {
    self.controllers.get(&controller_cap_id).copied()
  }

  /// Consumes this [`Multicontroller`], returning the wrapped value.
  pub fn into_inner(self) -> T {
    self.controlled_value
  }

  pub(crate) fn controllers(&self) -> &HashMap<ObjectID, u64> {
    &self.controllers
  }

  /// Returns `true` if `cap_id` is among this [`Multicontroller`]'s controllers' IDs.
  pub fn has_member(&self, cap_id: ObjectID) -> bool {
    self.controllers.contains_key(&cap_id)
  }
}

impl<T> TryFrom<IotaMulticontroller<T>> for Multicontroller<T> {
  type Error = <u64 as TryFrom<Number<u64>>>::Error;
  fn try_from(value: IotaMulticontroller<T>) -> Result<Self, Self::Error> {
    let IotaMulticontroller {
      controlled_value,
      controllers,
      threshold,
      active_proposals,
      proposals,
    } = value;
    let controllers = controllers
      .contents
      .into_iter()
      .map(|Entry { key: id, value: vp }| (u64::try_from(vp).map(|vp| (id, vp))))
      .collect::<Result<_, _>>()?;

    Ok(Multicontroller {
      controlled_value,
      controllers,
      threshold: threshold.try_into()?,
      active_proposals,
      proposals,
    })
  }
}

#[derive(Debug, Serialize, Deserialize)]
struct IotaMulticontroller<T> {
  controlled_value: T,
  controllers: VecMap<ObjectID, Number<u64>>,
  threshold: Number<u64>,
  active_proposals: HashSet<ObjectID>,
  proposals: Bag,
}
