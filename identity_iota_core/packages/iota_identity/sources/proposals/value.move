// Copyright (c) 2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

module iota_identity::update_value_proposal;

use iota_identity::controller::DelegationToken;
use iota_identity::multicontroller::Multicontroller;

public struct UpdateValue<V: store> has drop, store {
    new_value: V,
}

public fun propose_update<V: store>(
    multi: &mut Multicontroller<V>,
    cap: &DelegationToken,
    new_value: V,
    expiration: Option<u64>,
    ctx: &mut TxContext,
): ID {
    let update_action = UpdateValue { new_value };
    multi.create_proposal(cap, update_action, expiration, ctx)
}

public fun execute_update<V: store + drop>(
    multi: &mut Multicontroller<V>,
    cap: &DelegationToken,
    proposal_id: ID,
    ctx: &mut TxContext,
) {
    let action = multi.execute_proposal(cap, proposal_id, ctx);
    let UpdateValue { new_value } = action.unpack_action();

    multi.set_controlled_value(new_value)
}

public(package) fun into_inner<V: store>(self: UpdateValue<V>): V {
    let UpdateValue { new_value } = self;
    new_value
}
