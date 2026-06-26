// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("./../README.md")]
#![allow(clippy::upper_case_acronyms)]
#![warn(
  rust_2018_idioms,
  unreachable_pub,
  missing_docs,
  rustdoc::missing_crate_level_docs,
  rustdoc::broken_intra_doc_links,
  rustdoc::private_intra_doc_links,
  rustdoc::private_doc_tests,
  clippy::missing_safety_doc,
  // clippy::missing_errors_doc
)]

#[doc(inline)]
pub use serde_json::json;

#[forbid(unsafe_code)]
pub mod common;
#[forbid(unsafe_code)]
pub mod convert;
#[forbid(unsafe_code)]
pub mod error;

#[cfg(feature = "custom_time")]
pub mod custom_time;

pub use self::error::Error;
pub use self::error::Result;
