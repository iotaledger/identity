// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Types and traits for [Merkle tree][WIKI] operations.
//!
//! [WIKI]: https://en.wikipedia.org/wiki/Merkle_tree

mod consts;
mod digest;
mod hash;
mod math;
mod merkle;
mod node;
mod proof;
mod tree;

pub use self::digest::Digest;
pub use self::digest::DigestExt;
pub use self::hash::Hash;
pub use self::merkle::MTree;
pub use self::node::Node;
pub use self::proof::Proof;
