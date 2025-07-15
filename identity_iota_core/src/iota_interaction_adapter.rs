// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// The following platform compile switch provides all the
// ...Adapter types from iota_interaction_rust or iota_interaction_ts
// like IotaClientAdapter, AssetMoveCallsAdapter, IdentityMoveCallsAdapter,
// TransactionBuilderAdapter, MigrationMoveCallsAdapter, ... and so on

cfg_if::cfg_if! {
    if #[cfg(target_arch = "wasm32")] {
        pub(crate) use iota_interaction_ts::*;
    } else {
        pub(crate) use iota_interaction_rust::*;
    }
}
