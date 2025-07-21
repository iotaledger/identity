// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod move_calls;
pub(crate) mod package;
pub(crate) mod types;

use std::collections::HashMap;
use std::collections::VecDeque;

use iota_interaction::types::programmable_transaction_builder::ProgrammableTransactionBuilder as Ptb;
use iota_interaction::types::transaction::Argument;
use iota_interaction::types::transaction::CallArg;
use iota_interaction::types::transaction::Command;
use iota_interaction::types::transaction::ProgrammableTransaction;

pub(crate) fn ptb_merge_tx_with_inputs_replacement(
  ptb: &mut Ptb,
  other: ProgrammableTransaction,
  replacements: Vec<(CallArg, Argument)>,
) {
  let mut commands = VecDeque::from(other.commands);

  // Move inputs over whilst applying replacements.
  let mut inputs_map = HashMap::with_capacity(other.inputs.len());
  for (idx, input) in other.inputs.into_iter().enumerate() {
    let argument = replacements
      .iter()
      .find_map(|(to_replace, replacement)| (*to_replace == input).then_some(*replacement))
      .unwrap_or_else(|| ptb.input(input).expect("an input in other is a valid input"));

    inputs_map.insert(idx as u16, argument);
  }

  // Move the first command over, obtaining the results offset to use.
  // Note: the very first command can only reference inputs as there
  //   aren't any results yet.
  let Some(mut fst_cmd) = commands.pop_front() else {
    // Transaction doesn't have any commands?
    return;
  };
  cmd_update_args(&mut fst_cmd, |arg| update_input_arg(arg, &inputs_map));
  let Argument::Result(offset) = ptb.command(fst_cmd) else {
    unreachable!("Ptb::command always returns a Result variant");
  };

  // Update `other` PT's commands by updating their inputs and arguments.
  commands.iter_mut().for_each(|cmd| {
    cmd_update_args(cmd, |arg| update_input_and_result(arg, &inputs_map, offset));
  });
  // Move the updated commands to PTB.
  for cmd in commands {
    ptb.command(cmd);
  }
}

#[cfg(test)]
#[inline]
pub(crate) fn ptb_merge_tx(ptb: &mut Ptb, other: ProgrammableTransaction) {
  ptb_merge_tx_with_inputs_replacement(ptb, other, vec![]);
}

fn update_input_arg(input_arg: &mut Argument, inputs_map: &HashMap<u16, Argument>) {
  let Argument::Input(ref idx) = input_arg else {
    return;
  };

  *input_arg = *inputs_map.get(idx).expect("all inputs have been mapped");
}

fn update_input_and_result(arg: &mut Argument, inputs_map: &HashMap<u16, Argument>, result_offset: u16) {
  match arg {
    Argument::Input(_) => update_input_arg(arg, inputs_map),
    Argument::Result(idx) => *idx += result_offset,
    Argument::NestedResult(idx, _) => *idx += result_offset,
    Argument::GasCoin => {}
  }
}

fn cmd_update_args<F>(cmd: &mut Command, update_fn: F)
where
  F: Fn(&mut Argument),
{
  let arguments = match cmd {
    Command::MoveCall(move_call) => move_call.arguments.iter_mut(),
    Command::MakeMoveVec(_, args) => args.iter_mut(),
    Command::TransferObjects(args, arg) => {
      update_fn(arg);
      args.iter_mut()
    }
    Command::MergeCoins(arg, args) => {
      update_fn(arg);
      args.iter_mut()
    }
    Command::SplitCoins(arg, args) => {
      update_fn(arg);
      args.iter_mut()
    }
    Command::Upgrade(_, _, _, arg) => std::slice::from_mut(arg).iter_mut(),
    Command::Publish(_, _) => std::slice::IterMut::default(),
  };

  arguments.for_each(update_fn);
}

#[cfg(test)]
mod tests {
  use super::*;
  use iota_interaction::ident_str;
  use iota_interaction::types::base_types::IotaAddress;
  use iota_interaction::types::base_types::ObjectID;
  use iota_interaction::types::transaction::ObjectArg;
  use iota_interaction::types::IOTA_FRAMEWORK_PACKAGE_ID;
  use iota_interaction::IOTA_COIN_TYPE;

  /// Returns a PTB with a single call to `0x2::coin::zero`, together with its result.
  fn empty_iota_coin_ptb() -> (Ptb, Argument) {
    let mut ptb = Ptb::new();
    let empty_coin = ptb.programmable_move_call(
      IOTA_FRAMEWORK_PACKAGE_ID,
      ident_str!("coin").into(),
      ident_str!("zero").into(),
      vec![IOTA_COIN_TYPE.parse().unwrap()],
      vec![],
    );

    (ptb, empty_coin)
  }

  #[test]
  fn merging_pt_into_empty_ptb_works() {
    let mut ptb = Ptb::new();
    let pt = {
      let (mut ptb, coin) = empty_iota_coin_ptb();
      ptb.transfer_arg(IotaAddress::random_for_testing_only(), coin);
      ptb.finish()
    };

    ptb_merge_tx(&mut ptb, pt.clone());
    assert_eq!(ptb.finish(), pt);
  }

  #[test]
  fn merging_pt_with_replacements_works() {
    let recipient = IotaAddress::random_for_testing_only();
    let object_to_replace = CallArg::Object(ObjectArg::SharedObject {
      id: ObjectID::random(),
      initial_shared_version: 0.into(),
      mutable: true,
    });
    // Base-PTB, where coin is the argument we'd like to use in the PT that we'll be merging.
    let (mut ptb, coin) = empty_iota_coin_ptb();
    // In this PT we have two transfers: the first is a dummy that simply makes sure inputs and arguments
    // are handled as intented, the other is the transfer of an object that will be replaced with the 
    // argument coming from the base PTB after the merge.
    let pt = {
      let mut ptb = Ptb::new();
      let pure_arg = ptb.pure_bytes(vec![1, 2, 3], false);
      ptb.transfer_arg(recipient, pure_arg); 

      let obj = ptb.input(object_to_replace.clone()).unwrap();
      ptb.transfer_arg(recipient, obj);

      ptb.finish()
    };

    ptb_merge_tx_with_inputs_replacement(&mut ptb, pt, vec![(object_to_replace, coin)]);
    let pt = ptb.finish();

    // What the PT should look like if created in a single PTB.
    let expected_pt = {
      let (mut ptb, coin) = empty_iota_coin_ptb();
      let pure_arg = ptb.pure_bytes(vec![1, 2, 3], false);
      ptb.transfer_arg(recipient, pure_arg); 

      ptb.transfer_arg(recipient, coin);

      ptb.finish()
    };

    assert_eq!(pt, expected_pt);
    assert_eq!(pt.inputs.len(), 2);
  }
}
