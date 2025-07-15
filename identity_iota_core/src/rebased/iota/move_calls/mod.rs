// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_interaction::types::base_types::ObjectRef;

pub(crate) mod asset;
pub(crate) mod identity;
pub(crate) mod migration;
mod utils;

#[derive(Debug, Clone, Copy)]
pub(crate) enum ControllerTokenRef {
  Controller(ObjectRef),
  Delegate(ObjectRef),
}

impl ControllerTokenRef {
  pub(crate) fn object_ref(&self) -> ObjectRef {
    match self {
      Self::Controller(obj_ref) => *obj_ref,
      Self::Delegate(obj_ref) => *obj_ref,
    }
  }
}
