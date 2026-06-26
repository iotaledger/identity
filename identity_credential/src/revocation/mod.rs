// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Contains the implementations for all the credential revocation methods that can be used with IOTA's Identity
//! framework.

mod error;
mod revocation_bitmap_2022;
#[cfg(feature = "status-list-2021")]
pub mod status_list_2021;

#[cfg(feature = "jpt-bbs-plus")]
pub mod validity_timeframe_2024;

pub use self::error::RevocationError;
pub use self::error::RevocationResult;
pub use revocation_bitmap_2022::*;
#[cfg(feature = "jpt-bbs-plus")]
pub use validity_timeframe_2024::*;
