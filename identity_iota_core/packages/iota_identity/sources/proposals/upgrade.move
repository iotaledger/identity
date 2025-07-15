// Copyright (c) 2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

module iota_identity::upgrade_proposal;

/// Proposal's action used to upgrade an `Identity` to the package's current version.
public struct Upgrade has copy, drop, store {}

/// Creates a new `Upgrade` action.
public fun new(): Upgrade {
    Upgrade {}
}
