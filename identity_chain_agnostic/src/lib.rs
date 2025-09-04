// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/// Implementation of the types described in [CAIP-2](https://chainagnostic.org/CAIPs/caip-2).
pub mod chain_id;

/// Implementation of the types described in [CAIP-10](https://chainagnostic.org/CAIPs/caip-10).
pub mod account_id;

/// Implementation of the types described in [CAIP-19](https://chainagnostic.org/CAIPs/caip-19).
pub mod asset_type;

#[cfg(feature = "iota")]
/// IOTA-specific implementation for [CAIP-2](https://chainagnostic.org/CAIPs/caip-2),
/// [CAIP-10](https://chainagnostic.org/CAIPs/caip-10), and [CAIP-19](https://chainagnostic.org/CAIPs/caip-19).
pub mod iota;
mod parser;

/// An implementation for a to-be-submitted new CAIP, Chain-Agnostic Resource Locator (CARL).
pub mod resource;

pub use account_id::AccountId;
pub use asset_type::AssetId;
pub use asset_type::AssetType;
pub use chain_id::ChainId;
pub use resource::ChainAgnosticResourceLocator;
