// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("./../README.md")]
#![warn(
  rust_2018_idioms,
  unreachable_pub,
  missing_docs,
  rustdoc::missing_crate_level_docs,
  rustdoc::broken_intra_doc_links,
  rustdoc::private_intra_doc_links,
  rustdoc::private_doc_tests,
  clippy::missing_safety_doc
)]
#![allow(clippy::upper_case_acronyms)]

pub use did::IotaDID;
#[cfg(feature = "iota-client")]
pub use did_resolution::DidResolutionHandler;
pub use document::*;
pub use state_metadata::*;

pub use self::error::Error;
pub use self::error::Result;

mod did;
mod document;
mod error;
mod state_metadata;

#[cfg(feature = "iota-client")]
mod did_resolution;
#[cfg(feature = "iota-client")]
mod iota_interaction_adapter;

#[cfg(feature = "iota-client")]
/// Contains the rebased Identity and the interaction with the IOTA Client.
pub mod rebased;

/// Contains the types needed to interact with HTTP-based interfaces.
#[cfg(feature = "gas-station")]
pub mod http {
  pub use product_common::http_client::*;
}
