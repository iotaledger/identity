// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::upper_case_acronyms)]
#![warn(
  rust_2018_idioms,
  unreachable_pub,
  // missing_docs,
  // rustdoc::missing_crate_level_docs,
  rustdoc::broken_intra_doc_links,
  rustdoc::private_intra_doc_links,
  rustdoc::private_doc_tests,
  clippy::missing_safety_doc,
  // clippy::missing_errors_doc
)]

#[macro_use]
extern crate log;

#[macro_use]
extern crate serde;

pub mod account;
pub mod crypto;
pub mod error;
pub mod identity;
pub mod storage;
#[cfg(feature = "stronghold")]
pub mod stronghold;
#[cfg(test)]
mod tests;
pub mod types;
pub mod updates;
pub mod utils;

pub use self::error::Error;
pub use self::error::Result;
