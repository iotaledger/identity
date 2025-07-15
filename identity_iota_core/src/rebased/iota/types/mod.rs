// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod number;

use iota_interaction::types::base_types::ObjectID;
use iota_interaction::types::id::UID;
pub(crate) use number::*;
use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Bag {
  pub id: UID,
  #[serde(deserialize_with = "serde_aux::field_attributes::deserialize_number_from_string")]
  pub size: u64,
}

impl Default for Bag {
  fn default() -> Self {
    Self {
      id: UID::new(ObjectID::ZERO),
      size: 0,
    }
  }
}
