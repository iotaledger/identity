// Copyright (c) 2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

module iota_identity::transfer_proposal;

use iota::transfer::Receiving;
use iota_identity::controller::DelegationToken;
use iota_identity::multicontroller::{Multicontroller, Action};

const EDifferentLength: u64 = 0;
const EUnsentAssets: u64 = 1;
const EInvalidObject: u64 = 2;

public struct Send has drop, store {
    objects: vector<ID>,
    recipients: vector<address>,
}

public fun propose_send<V>(
    multi: &mut Multicontroller<V>,
    cap: &DelegationToken,
    expiration: Option<u64>,
    objects: vector<ID>,
    recipients: vector<address>,
    ctx: &mut TxContext,
): ID {
    assert!(objects.length() == recipients.length(), EDifferentLength);
    let action = Send { objects, recipients };

    multi.create_proposal(cap, action, expiration, ctx)
}

public fun send<T: key + store>(
    action: &mut Action<Send>,
    controllee: &mut UID,
    received: Receiving<T>,
) {
    let send_action = action.borrow_mut();
    let object_id = received.receiving_object_id();
    let (object_exists, object_idx) = send_action.objects.index_of(&object_id);
    // Check that the received object is among the objects that are actually supposed to be sent.
    assert!(object_exists, EInvalidObject);

    let object = transfer::public_receive(controllee, received);
    // Get the corresponding recipient.
    let recipient = send_action.recipients.swap_remove(object_idx);

    transfer::public_transfer(object, recipient);
    // Update the list of objects that have not been sent yet.
    send_action.objects.swap_remove(object_idx);
}

public fun complete_send(action: Action<Send>) {
    let Send { objects, recipients } = action.unpack_action();
    assert!(recipients.is_empty() && objects.is_empty(), EUnsentAssets);

    recipients.destroy_empty();
    objects.destroy_empty();
}
