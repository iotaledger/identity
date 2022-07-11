// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(
  rust_2018_idioms,
  unreachable_pub,
  rustdoc::broken_intra_doc_links,
  rustdoc::private_intra_doc_links,
  rustdoc::private_doc_tests
)]

pub mod agent;
pub mod didcomm;
mod p2p;
#[cfg(test)]
mod tests;

pub use libp2p::identity::Keypair as IdentityKeypair;
pub use libp2p::Multiaddr;
