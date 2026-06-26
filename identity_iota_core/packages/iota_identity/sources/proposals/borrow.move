// Copyright (c) 2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

module iota_identity::borrow_proposal;

use iota::transfer::Receiving;
use iota_identity::controller::DelegationToken;
use iota_identity::multicontroller::{Multicontroller, Action};

const EInvalidObject: u64 = 0;
const EInvalidOwner: u64 = 1;
const EUnreturnedObjects: u64 = 2;

/// Action used to "borrow" assets in a transaction - enforcing their return.
public struct Borrow has drop, store {
    objects: vector<ID>,
    objects_to_return: vector<ID>,
    owner: address,
}

/// Propose the borrowing of a set of assets owned by this multicontroller.
public fun propose_borrow<V>(
    multi: &mut Multicontroller<V>,
    cap: &DelegationToken,
    expiration: Option<u64>,
    objects: vector<ID>,
    owner: address,
    ctx: &mut TxContext,
): ID {
    let action = Borrow { objects, objects_to_return: vector::empty(), owner };

    multi.create_proposal(cap, action, expiration, ctx)
}

/// Borrows an asset from this action. This function will fail if:
/// - the received object is not among `Borrow::objects`;
/// - controllee does not have the same address as `Borrow::owner`;
public fun borrow<T: key + store>(
    action: &mut Action<Borrow>,
    controllee: &mut UID,
    receiving: Receiving<T>,
): T {
    let borrow_action = action.borrow_mut();
    assert!(borrow_action.owner == controllee.to_address(), EInvalidOwner);
    let receiving_object_id = receiving.receiving_object_id();
    let (obj_exists, obj_idx) = borrow_action.objects.index_of(&receiving_object_id);
    assert!(obj_exists, EInvalidObject);

    borrow_action.objects.swap_remove(obj_idx);
    borrow_action.objects_to_return.push_back(receiving_object_id);

    transfer::public_receive(controllee, receiving)
}

/// Transfer a borrowed object back to its original owner.
public fun put_back<T: key + store>(action: &mut Action<Borrow>, obj: T) {
    let borrow_action = action.borrow_mut();
    let object_id = object::id(&obj);
    let (contains, obj_idx) = borrow_action.objects_to_return.index_of(&object_id);
    assert!(contains, EInvalidObject);

    borrow_action.objects_to_return.swap_remove(obj_idx);
    transfer::public_transfer(obj, borrow_action.owner);
}

/// Consumes a borrow action.
public fun conclude_borrow(action: Action<Borrow>) {
    let Borrow { objects: _, objects_to_return, owner: _ } = action.unpack_action();
    assert!(objects_to_return.is_empty(), EUnreturnedObjects);
}
