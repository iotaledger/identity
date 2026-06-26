// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use thiserror::Error;

pub(crate) type Result<T> = std::result::Result<T, Error>;

/// [`Resolver`]'s errors.
#[derive(Debug, Error)]
pub enum Error {
  /// The queried item doesn't exist.
  #[error("The requested item \"{0}\" was not found.")]
  NotFound(String),
  /// Failed to parse input.
  #[error("Failed to parse the provided input into a resolvable type: {0}")]
  ParsingFailure(#[source] anyhow::Error),
  /// Generic error.
  #[error(transparent)]
  Generic(#[from] anyhow::Error),
}

/// A type capable of asynchronously producing values of type `T` from inputs of type `I`.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait Resolver<I: Sync, T> {
  /// Fetch the resource of type [`Resolver::Target`] using `input`.
  async fn resolve(&self, input: &I) -> Result<T>;
}
