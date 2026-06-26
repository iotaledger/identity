// Copyright (c) 2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

module iota_identity::config_proposal;

use iota::vec_map::VecMap;
use iota_identity::controller::DelegationToken;
use iota_identity::multicontroller::Multicontroller;

const ENotMember: u64 = 0;
const EInvalidThreshold: u64 = 1;

public struct Modify has drop, store {
    threshold: Option<u64>,
    controllers_to_add: VecMap<address, u64>,
    controllers_to_remove: vector<ID>,
    controllers_to_update: VecMap<ID, u64>,
}

public fun propose_modify<V>(
    multi: &mut Multicontroller<V>,
    cap: &DelegationToken,
    expiration: Option<u64>,
    threshold: Option<u64>,
    controllers_to_add: VecMap<address, u64>,
    controllers_to_remove: vector<ID>,
    controllers_to_update: VecMap<ID, u64>,
    ctx: &mut TxContext,
): ID {
    let mut max_votes = 0;
    let (cs, vps) = controllers_to_update.into_keys_values();
    vector::zip_do!(cs, vps, |c, vp| {
        assert!(multi.controllers().contains(&c), ENotMember);
        max_votes = max_votes + vp;
    });
    let (_, voting_powers) = controllers_to_add.into_keys_values();
    let voting_power_increase = voting_powers.fold!(0, |acc, vp| acc + vp);

    let voting_power_decrease = controllers_to_remove.fold!(0, |acc, controller_id| {
        assert!(multi.controllers().contains(&controller_id), ENotMember);
        let mut vp = multi.voting_power(controller_id);
        if (controllers_to_update.contains(&controller_id)) {
            vp = *controllers_to_update.get(&controller_id);
        };
        acc + vp
    });

    multi.controllers().do!(|controller_id| {
        if (!controllers_to_update.contains(&controller_id)) {
            max_votes = max_votes + multi.voting_power(controller_id);
        };
    });

    let new_max_votes = max_votes + voting_power_increase - voting_power_decrease;
    let threshold = threshold.destroy_or!(multi.threshold());

    assert!(threshold > 0 && threshold <= new_max_votes, EInvalidThreshold);

    let action = Modify {
        threshold: option::some(threshold),
        controllers_to_add,
        controllers_to_remove,
        controllers_to_update,
    };

    multi.create_proposal(cap, action, expiration, ctx)
}

public fun execute_modify<V>(
    multi: &mut Multicontroller<V>,
    cap: &DelegationToken,
    proposal_id: ID,
    ctx: &mut TxContext,
) {
    let action = multi.execute_proposal(cap, proposal_id, ctx);
    let Modify {
        mut threshold,
        controllers_to_add,
        controllers_to_remove,
        controllers_to_update,
    } = action.unpack_action();

    if (threshold.is_some()) multi.set_threshold(threshold.extract());
    multi.update_members(controllers_to_update);
    multi.add_members(controllers_to_add, ctx);
    multi.remove_members(controllers_to_remove);
}
