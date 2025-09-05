// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod address;
mod network;
mod resource;

#[cfg(feature = "resolver")]
pub mod resolver;

pub use address::*;
pub use network::*;
pub use resource::*;
