// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_sdk_types::ObjectReference;

pub(crate) mod asset;
pub(crate) mod identity;
pub(crate) mod migration;
mod utils;

#[derive(Debug, Clone, Copy)]
pub(crate) enum ControllerTokenRef {
  Controller(ObjectReference),
  Delegate(ObjectReference),
}

impl ControllerTokenRef {
  pub(crate) fn object_ref(&self) -> ObjectReference {
    match self {
      Self::Controller(obj_ref) => *obj_ref,
      Self::Delegate(obj_ref) => *obj_ref,
    }
  }

  #[inline(always)]
  pub(crate) fn is_controller_cap(&self) -> bool {
    matches!(self, Self::Controller(_))
  }
}
