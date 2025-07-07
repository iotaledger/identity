// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod move_calls;
pub(crate) mod package;
pub(crate) mod types;

use std::collections::HashMap;
use std::collections::VecDeque;

use iota_interaction::types::programmable_transaction_builder::ProgrammableTransactionBuilder as Ptb;
use iota_interaction::types::transaction::Argument;
use iota_interaction::types::transaction::Command;
use iota_interaction::types::transaction::ProgrammableTransaction;
use iota_sdk::types::transaction::CallArg;

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
      .unwrap_or_else(|| ptb.input(input).expect("shouldn't fail. Check this more carefully.."));

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
  use iota_interaction::types::IOTA_FRAMEWORK_PACKAGE_ID;
  use iota_interaction::IOTA_COIN_TYPE;

  fn empty_iota_coin_ptb() -> Ptb {
    let mut ptb = Ptb::new();
    let empty_coin = ptb.programmable_move_call(
      IOTA_FRAMEWORK_PACKAGE_ID,
      ident_str!("coin").into(),
      ident_str!("zero").into(),
      vec![IOTA_COIN_TYPE.parse().unwrap()],
      vec![],
    );
    ptb.transfer_args(IotaAddress::random_for_testing_only(), vec![empty_coin]);
    ptb
  }

  #[test]
  fn merging_pt_into_empty_ptb_works() {
    let mut ptb = Ptb::new();
    let pt = empty_iota_coin_ptb().finish();

    ptb_merge_tx(&mut ptb, pt.clone());
    assert_eq!(ptb.finish(), pt);
  }
}
