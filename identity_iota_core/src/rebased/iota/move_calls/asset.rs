// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use serde::Serialize;

use crate::rebased::Error;
use iota_interaction::ident_str;
use iota_interaction::types::base_types::IotaAddress;
use iota_interaction::types::base_types::ObjectID;
use iota_interaction::types::base_types::ObjectRef;
use iota_interaction::types::base_types::SequenceNumber;
use iota_interaction::types::programmable_transaction_builder::ProgrammableTransactionBuilder;
use iota_interaction::types::transaction::Argument;
use iota_interaction::types::transaction::Command;
use iota_interaction::types::transaction::ObjectArg;
use iota_interaction::types::transaction::ProgrammableMoveCall;
use iota_interaction::types::TypeTag;
use iota_interaction::MoveType;
use iota_interaction::ProgrammableTransactionBcs;
use iota_interaction::TypedValue;

fn try_to_argument<T: MoveType + Serialize>(
  content: &T,
  ptb: &mut ProgrammableTransactionBuilder,
  package: ObjectID,
) -> Result<Argument, Error> {
  match content.get_typed_value(package) {
    TypedValue::IotaVerifiableCredential(value) => {
      let values = ptb
        .pure(value.data())
        .map_err(|e| Error::InvalidArgument(e.to_string()))?;
      Ok(ptb.command(Command::MoveCall(Box::new(ProgrammableMoveCall {
        package,
        module: ident_str!("public_vc").into(),
        function: ident_str!("new").into(),
        type_arguments: vec![],
        arguments: vec![values],
      }))))
    }
    TypedValue::Other(value) => ptb.pure(value).map_err(|e| Error::InvalidArgument(e.to_string())),
  }
}

pub(crate) fn new_asset<T: Serialize + MoveType>(
  inner: &T,
  mutable: bool,
  transferable: bool,
  deletable: bool,
  package: ObjectID,
) -> Result<ProgrammableTransactionBcs, Error> {
  let mut ptb = ProgrammableTransactionBuilder::new();
  let inner = try_to_argument(inner, &mut ptb, package)?;
  let mutable = ptb.pure(mutable).map_err(|e| Error::InvalidArgument(e.to_string()))?;
  let transferable = ptb
    .pure(transferable)
    .map_err(|e| Error::InvalidArgument(e.to_string()))?;
  let deletable = ptb.pure(deletable).map_err(|e| Error::InvalidArgument(e.to_string()))?;

  ptb.command(Command::MoveCall(Box::new(ProgrammableMoveCall {
    package,
    module: ident_str!("asset").into(),
    function: ident_str!("new_with_config").into(),
    type_arguments: vec![T::move_type(package)],
    arguments: vec![inner, mutable, transferable, deletable],
  })));

  Ok(bcs::to_bytes(&ptb.finish())?)
}

pub(crate) fn delete<T>(asset: ObjectRef, package: ObjectID) -> Result<ProgrammableTransactionBcs, Error>
where
  T: MoveType,
{
  let mut ptb = ProgrammableTransactionBuilder::new();

  let asset = ptb
    .obj(ObjectArg::ImmOrOwnedObject(asset))
    .map_err(|e| Error::InvalidArgument(e.to_string()))?;

  ptb.command(Command::move_call(
    package,
    ident_str!("asset").into(),
    ident_str!("delete").into(),
    vec![T::move_type(package)],
    vec![asset],
  ));

  Ok(bcs::to_bytes(&ptb.finish())?)
}

pub(crate) fn transfer<T: MoveType>(
  asset: ObjectRef,
  recipient: IotaAddress,
  package: ObjectID,
) -> Result<ProgrammableTransactionBcs, Error> {
  let mut ptb = ProgrammableTransactionBuilder::new();
  let asset = ptb
    .obj(ObjectArg::ImmOrOwnedObject(asset))
    .map_err(|e| Error::InvalidArgument(e.to_string()))?;
  let recipient = ptb.pure(recipient).map_err(|e| Error::InvalidArgument(e.to_string()))?;

  ptb.command(Command::move_call(
    package,
    ident_str!("asset").into(),
    ident_str!("transfer").into(),
    vec![T::move_type(package)],
    vec![asset, recipient],
  ));

  Ok(bcs::to_bytes(&ptb.finish())?)
}

pub(crate) fn make_tx(
  proposal: (ObjectID, SequenceNumber),
  cap: ObjectRef,
  asset: ObjectRef,
  asset_type_param: TypeTag,
  package: ObjectID,
  function_name: &'static str,
) -> Result<ProgrammableTransactionBcs, Error> {
  let mut ptb = ProgrammableTransactionBuilder::new();
  let proposal = ptb
    .obj(ObjectArg::SharedObject {
      id: proposal.0,
      initial_shared_version: proposal.1,
      mutable: true,
    })
    .map_err(|e| Error::InvalidArgument(e.to_string()))?;
  let cap = ptb
    .obj(ObjectArg::ImmOrOwnedObject(cap))
    .map_err(|e| Error::InvalidArgument(e.to_string()))?;
  let asset = ptb
    .obj(ObjectArg::Receiving(asset))
    .map_err(|e| Error::InvalidArgument(e.to_string()))?;

  ptb.command(Command::move_call(
    package,
    ident_str!("asset").into(),
    ident_str!(function_name).into(),
    vec![asset_type_param],
    vec![proposal, cap, asset],
  ));

  Ok(bcs::to_bytes(&ptb.finish())?)
}

pub(crate) fn accept_proposal(
  proposal: (ObjectID, SequenceNumber),
  recipient_cap: ObjectRef,
  asset: ObjectRef,
  asset_type_param: TypeTag,
  package: ObjectID,
) -> Result<ProgrammableTransactionBcs, Error> {
  make_tx(proposal, recipient_cap, asset, asset_type_param, package, "accept")
}

pub(crate) fn conclude_or_cancel(
  proposal: (ObjectID, SequenceNumber),
  sender_cap: ObjectRef,
  asset: ObjectRef,
  asset_type_param: TypeTag,
  package: ObjectID,
) -> Result<ProgrammableTransactionBcs, Error> {
  make_tx(
    proposal,
    sender_cap,
    asset,
    asset_type_param,
    package,
    "conclude_or_cancel",
  )
}

pub(crate) fn update<T>(
  asset: ObjectRef,
  new_content: &T,
  package: ObjectID,
) -> Result<ProgrammableTransactionBcs, Error>
where
  T: MoveType + Serialize,
{
  let mut ptb = ProgrammableTransactionBuilder::new();

  let asset = ptb
    .obj(ObjectArg::ImmOrOwnedObject(asset))
    .map_err(|e| Error::InvalidArgument(e.to_string()))?;
  let new_content = ptb
    .pure(new_content)
    .map_err(|e| Error::InvalidArgument(e.to_string()))?;

  ptb.command(Command::move_call(
    package,
    ident_str!("asset").into(),
    ident_str!("set_content").into(),
    vec![T::move_type(package)],
    vec![asset, new_content],
  ));

  Ok(bcs::to_bytes(&ptb.finish())?)
}
