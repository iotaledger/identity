// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/*
[
  {
    "id": "6364aad5",
    "alias": "iota",
    "packages": [
      "0x84cf5d12de2f9731a89bb519bc0c982a941b319a33abefdd5ed2054ad931de08"
    ]
  },
  {
    "id": "2304aa97",
    "alias": "testnet",
    "packages": [
      "0x222741bbdff74b42df48a7b4733185e9b24becb8ccfbafe8eac864ab4e4cc555",
      "0x3403da7ec4cd2ff9bdf6f34c0b8df5a2bd62c798089feb0d2ebf1c2e953296dc"
    ]
  },
  {
    "id": "e678123a",
    "alias": "devnet",
    "packages": [
      "0xe6fa03d273131066036f1d2d4c3d919b9abbca93910769f26a924c7a01811103",
      "0x6a976d3da90db5d27f8a0c13b3268a37e582b455cfc7bf72d6461f6e8f668823"
    ]
  }
]
*/

use iota_interaction::types::base_types::ObjectID;
use std::sync::LazyLock;
use tokio::sync::RwLock;

use super::package::Env;
use super::package::PackageRegistry;

#[rustfmt::skip]
pub(crate) static IOTA_IDENTITY_PACKAGE_REGISTRY: LazyLock<RwLock<PackageRegistry>> = LazyLock::new(|| {
  RwLock::new({
    let mut registry = PackageRegistry::default();

    registry.insert_env(
      Env::new_with_alias("6364aad5", "iota"),
      vec![
        ObjectID::from_hex_literal("0x84cf5d12de2f9731a89bb519bc0c982a941b319a33abefdd5ed2054ad931de08").unwrap(),
      ],
    );
    registry.insert_env(
      Env::new_with_alias("2304aa97", "testnet"),
      vec![
        ObjectID::from_hex_literal("0x222741bbdff74b42df48a7b4733185e9b24becb8ccfbafe8eac864ab4e4cc555").unwrap(),
        ObjectID::from_hex_literal("0x3403da7ec4cd2ff9bdf6f34c0b8df5a2bd62c798089feb0d2ebf1c2e953296dc").unwrap(),
      ],
    );
    registry.insert_env(
      Env::new_with_alias("e678123a", "devnet"),
      vec![
        ObjectID::from_hex_literal("0xe6fa03d273131066036f1d2d4c3d919b9abbca93910769f26a924c7a01811103").unwrap(),
        ObjectID::from_hex_literal("0x6a976d3da90db5d27f8a0c13b3268a37e582b455cfc7bf72d6461f6e8f668823").unwrap(),
      ],
    );
    registry
  })
});
