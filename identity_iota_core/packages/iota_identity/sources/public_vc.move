// Copyright (c) 2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

module iota_identity::public_vc;

public struct PublicVc has store {
    data: vector<u8>,
}

public fun new(data: vector<u8>): PublicVc {
    PublicVc { data }
}

public fun data(self: &PublicVc): &vector<u8> {
    &self.data
}

public fun set_data(self: &mut PublicVc, data: vector<u8>) {
    self.data = data
}
