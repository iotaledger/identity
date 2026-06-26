// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod irl_resolver;
mod resolver_config;
mod resolver_types;
mod wasm_did_resolution_handler;
mod wasm_resolver;

pub use irl_resolver::*;
pub use resolver_types::*;
pub use wasm_did_resolution_handler::WasmDidResolutionHandler;
