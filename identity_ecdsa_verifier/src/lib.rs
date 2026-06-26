// Copyright 2020-2024 IOTA Stiftung, Filancore GmbH
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

mod ecdsa_jws_verifier;
#[cfg(feature = "es256k")]
mod secp256k1;
#[cfg(feature = "es256")]
mod secp256r1;

pub use ecdsa_jws_verifier::*;
#[cfg(feature = "es256k")]
pub use secp256k1::*;
#[cfg(feature = "es256")]
pub use secp256r1::*;

#[cfg(test)]
mod tests;
