// Copyright (c) 2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

module iota_identity::delete_proposal;

public struct Delete has copy, drop, store {}

public fun new(): Delete {
    Delete {}
}
