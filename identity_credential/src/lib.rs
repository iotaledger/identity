// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]
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

#[cfg(feature = "credential")]
pub mod credential;
#[cfg(feature = "domain-linkage")]
pub mod domain_linkage;
pub mod error;
#[cfg(feature = "presentation")]
pub mod presentation;
#[cfg(feature = "revocation-bitmap")]
pub mod revocation;
mod utils;
#[cfg(feature = "validator")]
pub mod validator;

/// Implementation of the SD-JWT VC token specification.
#[cfg(feature = "sd-jwt-vc")]
pub mod sd_jwt_vc;

pub use error::Error;
pub use error::Result;

#[cfg(feature = "sd-jwt")]
pub use sd_jwt as sd_jwt_payload;
