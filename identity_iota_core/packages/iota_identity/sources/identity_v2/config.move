// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

module iota_identity::identity_config;

#[error(code = 0)]
const EThresholdZero: vector<u8> = b"Threshold must be greater than zero";
#[error(code = 1)]
const EThresholdTooHigh: vector<u8> =
    b"Threshold cannot be higher than the sum of all controller weights";
#[error(code = 2)]
const EControllersComponentsHaveDifferentLengths: vector<u8> =
    b"Controllers components must have the same length";
#[error(code = 3)]
const EControllersMustNotContainDuplicated: vector<u8> = b"Controllers must not contain duplicates";
#[error(code = 4)]
const EControllerNotFound: vector<u8> = b"Controller not found";

public struct Controller has drop, store {
    addr: address,
    weight: u64,
    permissions: u64,
}

/// Returns the address of the controller.
public fun addr(self: &Controller): address {
    self.addr
}

/// Returns the weight of the controller.
public fun weight(self: &Controller): u64 {
    self.weight
}

/// Sets a new weight for the controller.
public fun set_weight(self: &mut Controller, new_weight: u64) {
    self.weight = new_weight;
}

/// Returns the permissions of the controller.
public fun permissions(self: &Controller): u64 {
    self.permissions
}

/// Sets new permissions for the controller.
public fun set_permissions(self: &mut Controller, new_permissions: u64) {
    self.permissions = new_permissions;
}

/// Returns true if the controller has the specified permission or is an admin.
public fun has_permission(self: &Controller, permission: u64): bool {
    (self.permissions & permission) != 0 || (self.permissions & admin!()) != 0
}

/// Identity configuration. Contains the list of controllers and the threshold.
public struct IdentityConfig has drop, store {
    controllers: vector<Controller>,
    threshold: u64,
}

/// Create a new `IdentityConfig`.
/// - `addresses` and `weights` must have the same length.
/// - `addresses` must not contain duplicates.
/// - `threshold` must be greater than zero and less than or equal to the sum of all weights.
public fun new(
    addresses: vector<address>,
    weights: vector<u64>,
    permissions: vector<u64>,
    threshold: u64,
): IdentityConfig {
    check_controllers(&addresses, &weights, &permissions);

    let total_weight = weights.fold!(0, |total, w| total + w);
    let mut i = 0;
    let mut controllers = vector::empty();
    while (i < permissions.length()) {
        controllers.push_back(Controller {
            addr: addresses[i],
            weight: weights[i],
            permissions: permissions[i],
        });
        i = i + 1;
    };
    assert!(threshold > 0, EThresholdZero);
    assert!(threshold <= total_weight, EThresholdTooHigh);

    IdentityConfig { controllers, threshold }
}

/// Returns a reference to the controllers of the `IdentityConfig`.
public fun controllers(self: &IdentityConfig): &vector<Controller> {
    &self.controllers
}

/// Returns the threshold of the `IdentityConfig`.
public fun threshold(self: &IdentityConfig): u64 {
    self.threshold
}

/// Checks if the given address is a controller of the `IdentityConfig`.
public fun contains(self: &IdentityConfig, addr: address): bool {
    self.controllers.find_index!(|controller| controller.addr == addr).is_some()
}

/// Returns a reference to the controller with the given address.
public fun borrow_controller(self: &IdentityConfig, controller: address): &Controller {
    let idx = self.controllers.find_index!(|c| c.addr == controller);
    assert!(idx.is_some(), EControllerNotFound);

    self.controllers.borrow(idx.destroy_some())
}

/// Returns a mutable reference to the controller with the given address.
public fun borrow_controller_mut(self: &mut IdentityConfig, controller: address): &mut Controller {
    let idx = self.controllers.find_index!(|c| c.addr == controller);
    assert!(idx.is_some(), EControllerNotFound);

    self.controllers.borrow_mut(idx.destroy_some())
}

/// Adds a new controller to the `IdentityConfig`.
public fun add_controller(self: &mut IdentityConfig, addr: address, weight: u64, permissions: u64) {
    assert!(!self.contains(addr), EControllersMustNotContainDuplicated);
    self.controllers.push_back(Controller { addr, weight, permissions });
}

/// Removes a controller from the `IdentityConfig`.
/// - The controller must exist in the `IdentityConfig`.
/// - After removal, the threshold must still be valid
///   (i.e., less than or equal to the sum of the remaining controllers' weights).
public fun remove_controller(self: &mut IdentityConfig, addr: address) {
    let idx = self.controllers.find_index!(|c| c.addr == addr);
    assert!(idx.is_some(), EControllerNotFound);

    self.controllers.swap_remove(idx.destroy_some());

    let total_weight = total_weight(&self.controllers);
    assert!(self.threshold <= total_weight, EThresholdTooHigh);
}

/// Updates the weight of an existing controller in the `IdentityConfig`.
public fun update_controller_weight(
    self: &mut IdentityConfig,
    addr: address,
    new_weight: u64,
    new_permissions: u64,
) {
    let controller = self.borrow_controller_mut(addr);
    controller.weight = new_weight;
    controller.permissions = new_permissions;

    let total_weight = total_weight(&self.controllers);
    assert!(self.threshold <= total_weight, EThresholdTooHigh);
}

/// Sets a new threshold for the `IdentityConfig`.
public fun set_threshold(self: &mut IdentityConfig, new_threshold: u64) {
    let total_weight = total_weight(&self.controllers);
    assert!(new_threshold > 0, EThresholdZero);
    assert!(new_threshold <= total_weight, EThresholdTooHigh);

    self.threshold = new_threshold;
}

fun total_weight(controllers: &vector<Controller>): u64 {
    let mut total = 0;
    controllers.do_ref!(|controller| { total = total + controller.weight; });
    total
}

// Validates the controllers' components.
fun check_controllers(
    addresses: &vector<address>,
    weights: &vector<u64>,
    permissions: &vector<u64>,
) {
    // Check that the lengths of the provided vectors are equal.
    assert!(addresses.length() == weights.length(), EControllersComponentsHaveDifferentLengths);
    assert!(addresses.length() == permissions.length(), EControllersComponentsHaveDifferentLengths);

    // Check that the provided addresses are unique.
    let mut seen = vector::empty<address>();
    addresses.do_ref!(|addr| {
        assert!(!seen.contains(addr), EControllersMustNotContainDuplicated);
        seen.push_back(*addr);
    });
}

public fun is_subset_of(permissions: u64, other_permissions: u64): bool {
    (permissions & other_permissions.bitwise_not()) == 0
}

public macro fun can_propose_tx(): u64 {
    1 << 0
}

public macro fun can_approve_tx(): u64 {
    1 << 1
}

public macro fun can_execute_tx(): u64 {
    1 << 2
}

public macro fun can_update_did(): u64 {
    1 << 3
}

public macro fun can_deactivate_did(): u64 {
    1 << 4
}

public macro fun can_delete_did(): u64 {
    1 << 5
}

public macro fun can_add_controller(): u64 {
    1 << 6
}

public macro fun can_update_controller(): u64 {
    1 << 7
}

public macro fun can_remove_controller(): u64 {
    1 << 8
}

public macro fun can_update_threshold(): u64 {
    1 << 9
}

public macro fun can_transfer_asset(): u64 {
    1 << 10
}

public macro fun admin(): u64 {
    1 << 63
}
