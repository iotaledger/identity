// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod builder;
mod claims;
mod error;
/// Additional metadata defined by the SD-JWT VC specification
/// such as issuer's metadata and credential type metadata.
pub mod metadata;
mod presentation;
/// Resolver trait.
pub mod resolver;
mod status;
#[cfg(test)]
pub(crate) mod tests;
mod token;

pub use builder::*;
pub use claims::*;
pub use error::Error;
pub use error::Result;
pub use presentation::*;
pub use resolver::Resolver;
pub use status::*;
pub use token::*;
