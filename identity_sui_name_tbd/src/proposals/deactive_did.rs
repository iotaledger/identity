use std::str::FromStr;

use crate::iota_sdk_abstraction::IotaTransactionBlockResponseT;
use crate::iota_sdk_abstraction::rpc_types::OwnedObjectRef;
use crate::iota_sdk_abstraction::types::base_types::ObjectID;
use crate::iota_sdk_abstraction::types::base_types::ObjectRef;
use crate::iota_sdk_abstraction::types::transaction::Argument;
use crate::iota_sdk_abstraction::ProgrammableTransactionBcs;
use crate::iota_sdk_abstraction::types::TypeTag;
use serde::Deserialize;
use serde::Serialize;

use crate::migration::OnChainIdentity;
use crate::migration::Proposal;
use crate::iota_sdk_abstraction::IdentityMoveCalls;
use crate::utils::MoveType;
use crate::Error;

use super::ProposalT;

/// Action for deactivating a DID Document inside an Identity.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct DeactiveDid;

impl DeactiveDid {
  pub const fn new() -> Self {
    Self
  }
}

impl MoveType for DeactiveDid {
  fn move_type(package: ObjectID) -> TypeTag {
    TypeTag::from_str(&format!("{package}::identity::DeactivateDid")).expect("valid utf8")
  }
}

impl ProposalT for Proposal<DeactiveDid> {
  type Action = DeactiveDid;
  type Output = ();
  fn make_create_tx<M: IdentityMoveCalls>(
    _action: Self::Action,
    expiration: Option<u64>,
    identity: OwnedObjectRef,
    controller_cap: ObjectRef,
    _identity_ref: OnChainIdentity,
    package: ObjectID,
  ) -> Result<(<M as IdentityMoveCalls>::TxBuilder, Argument), Error> {
    M::propose_deactivation(identity, controller_cap, expiration, package)
      .map_err(|e| Error::TransactionBuildingFailed(e.to_string()))
  }
  fn make_chained_execution_tx<M: IdentityMoveCalls>(
    ptb: <M as IdentityMoveCalls>::TxBuilder,
    proposal_arg: Argument,
    identity: OwnedObjectRef,
    controller_cap: ObjectRef,
    package: ObjectID,
  ) -> Result<ProgrammableTransactionBcs, Error> {
    M::execute_deactivation(
      Some(ptb),
      Some(proposal_arg),
      identity,
      controller_cap,
      ObjectID::ZERO,
      package,
    )
    .map_err(|e| Error::TransactionBuildingFailed(e.to_string()))
  }
  fn make_execute_tx<M: IdentityMoveCalls>(
    &self,
    identity: OwnedObjectRef,
    controller_cap: ObjectRef,
    package: ObjectID,
  ) -> Result<ProgrammableTransactionBcs, Error> {
    M::execute_deactivation(None, None, identity, controller_cap, self.id(), package)
      .map_err(|e| Error::TransactionBuildingFailed(e.to_string()))
  }
  fn parse_tx_effects(_tx_response: &dyn IotaTransactionBlockResponseT<Error = Error>) -> Result<Self::Output, Error> {
    Ok(())
  }
}
