module iota_identity::controller_proposal;

use iota::transfer::Receiving;
use iota_identity::controller::{Self, ControllerCap};
use iota_identity::multicontroller::Action;

/// The received `ControllerCap` does not match the one
/// specified in the `ControllerExecution` action.
const EControllerCapMismatch: u64 = 0;
/// The provided `UID` is not the `UID` of the `Identity`
/// specified in the action.
const EInvalidIdentityUID: u64 = 1;

/// Borrow a given `ControllerCap` from an `Identity` for
/// a single transaction.
public struct ControllerExecution has drop, store {
    /// ID of the `ControllerCap` to borrow.
    controller_cap: ID,
    /// The address of the `Identity` that owns
    /// the `ControllerCap` we are borrowing.
    identity: address,
}

/// Returns a new `ControllerExecution` that - in a Proposal - allows whoever
/// executes it to receive `identity`'s `ControllerCap` (the one that has ID `controller_cap`)
/// for the duration of a single transaction.
public fun new(controller_cap: ID, identity: address): ControllerExecution {
    ControllerExecution {
        controller_cap,
        identity,
    }
}

/// Returns the `ControllerCap` specified in this action.
public fun receive(
    self: &mut Action<ControllerExecution>,
    identity: &mut UID,
    cap: Receiving<ControllerCap>,
): ControllerCap {
    assert!(identity.to_address() == self.borrow().identity, EInvalidIdentityUID);
    assert!(cap.receiving_object_id() == self.borrow().controller_cap, EControllerCapMismatch);

    controller::receive(identity, cap)
}

/// Consumes a `ControllerExecution` action by returning the borrowed `ControllerCap`
/// to the corresponding `Identity`.
public fun put_back(action: Action<ControllerExecution>, cap: ControllerCap) {
    let ControllerExecution { identity, controller_cap } = action.unwrap();
    assert!(object::id(&cap) == controller_cap, EControllerCapMismatch);

    cap.transfer(identity);
}
