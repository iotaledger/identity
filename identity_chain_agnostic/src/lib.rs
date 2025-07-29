// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/// Implementation of the types described in [CAIP-19](https://chainagnostic.org/CAIPs/caip-19).
pub mod asset_type;
/// Implementation of the types described in [CAIP-2](https://chainagnostic.org/CAIPs/caip-2).
pub mod chain_id;
#[cfg(feature = "iota")]
/// IOTA-specific implementation for [CAIP-2](https://chainagnostic.org/CAIPs/caip-2) and [CAIP-19](https://chainagnostic.org/CAIPs/caip-19).
pub mod iota;

mod parser;

pub use asset_type::AssetId;
pub use asset_type::AssetType;
pub use chain_id::ChainId;
