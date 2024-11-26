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
#[cfg(feature = "kinesis-client")]
pub use did_resolution::DidResolutionHandler;
pub use document::*;
pub use network::NetworkName;
pub use state_metadata::*;

pub use self::error::Error;
pub use self::error::Result;

mod did;
#[cfg(feature = "kinesis-client")]
mod did_resolution;
mod document;
mod error;
mod network;
#[cfg(feature = "kinesis-client")]
pub mod rebased;
mod state_metadata;
