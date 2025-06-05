// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod controller;
mod identity;
mod proposals;
mod wasm_identity_client;
mod wasm_identity_client_read_only;

pub use controller::*;
pub use identity::*;
pub use wasm_identity_client::*;
pub use wasm_identity_client_read_only::*;

pub type WasmIotaAddress = String;
pub type WasmObjectID = String;
