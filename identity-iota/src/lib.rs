// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// #![warn(
//   missing_docs,
//   missing_crate_level_docs,
//   broken_intra_doc_links,
//   private_intra_doc_links,
//   private_doc_tests,
//   clippy::missing_safety_doc,
//   clippy::missing_errors_doc,
// )]

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate log;

#[macro_use]
extern crate serde;

pub mod chain;
pub mod client;
pub mod credential;
pub mod did;
pub mod error;
pub mod tangle;
pub mod utils;

/// Re-export `identity_core::crypto`; in the future this will be `crypto.rs`.
pub mod crypto {
    pub use identity_core::crypto::*;
}
