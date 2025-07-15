// Copyright (c) 2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

module iota_identity::utils;

use iota::vec_map::{Self, VecMap};

public fun vec_map_from_keys_values<K: store + copy, V: store>(
    keys: vector<K>,
    values: vector<V>,
): VecMap<K, V> {
    vec_map::from_keys_values(keys, values)
}

#[test]
fun from_keys_values_works() {
    let addresses = vector[@0x1, @0x2];
    let vps = vector[1, 1];

    let map = vec_map_from_keys_values(addresses, vps);
    assert!(map.size() == 2, 0);
}
