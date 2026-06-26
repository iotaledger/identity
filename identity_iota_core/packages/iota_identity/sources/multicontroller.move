// Copyright (c) 2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

module iota_identity::multicontroller;

use iota::object_bag::{Self, ObjectBag};
use iota::vec_map::{Self, VecMap};
use iota::vec_set::{Self, VecSet};
use iota_identity::controller::{Self, DelegationToken, ControllerCap};
use iota_identity::permissions;

const EInvalidController: u64 = 0;
const EControllerAlreadyVoted: u64 = 1;
const EThresholdNotReached: u64 = 2;
const EInvalidThreshold: u64 = 3;
const EExpiredProposal: u64 = 4;
const ENotVotedYet: u64 = 5;
const EProposalNotFound: u64 = 6;
const ECannotDelete: u64 = 7;

/// Shares control of a value `V` with multiple entities called controllers.
public struct Multicontroller<V> has store {
    threshold: u64,
    owner: ID,
    controllers: VecMap<ID, u64>,
    controlled_value: V,
    active_proposals: vector<ID>,
    proposals: ObjectBag,
    revoked_tokens: VecSet<ID>,
}

/// Wraps a `V` in `Multicontroller`, making the tx's sender a controller with
/// voting power 1.
public fun new<V>(
    controlled_value: V,
    can_delegate: bool,
    owner: ID,
    ctx: &mut TxContext,
): Multicontroller<V> {
    new_with_controller(controlled_value, ctx.sender(), can_delegate, owner, ctx)
}

/// Wraps a `V` in `Multicontroller` and sends `controller` a `ControllerCap`.
public fun new_with_controller<V>(
    controlled_value: V,
    controller: address,
    can_delegate: bool,
    owner: ID,
    ctx: &mut TxContext,
): Multicontroller<V> {
    let mut controllers = vec_map::empty();
    controllers.insert(controller, 1);

    if (can_delegate) {
        new_with_controllers(controlled_value, vec_map::empty(), controllers, 1, owner, ctx)
    } else {
        new_with_controllers(controlled_value, controllers, vec_map::empty(), 1, owner, ctx)
    }
}

/// Wraps a `V` in `Multicontroller`, settings `threshold` as the threshold,
/// and using `controllers` to set controllers: i.e. each `(recipient, voting power)`
/// in `controllers` results in `recipient` obtaining a `ControllerCap` with the
/// specified voting power.
/// Controllers that are able to delegate their access, should be passed through
/// `controllers_that_can_delegate` parameter.
public fun new_with_controllers<V>(
    controlled_value: V,
    controllers: VecMap<address, u64>,
    controllers_that_can_delegate: VecMap<address, u64>,
    threshold: u64,
    owner: ID,
    ctx: &mut TxContext,
): Multicontroller<V> {
    let (addrs, vps) = controllers.into_keys_values();
    let mut controllers = vec_map::empty();
    vector::zip_do!(addrs, vps, |addr, vp| {
        let cap = controller::new(false, owner, ctx);
        controllers.insert(cap.id().to_inner(), vp);

        cap.transfer(addr);
    });

    let (addrs, vps) = controllers_that_can_delegate.into_keys_values();
    vector::zip_do!(addrs, vps, |addr, vp| {
        let cap = controller::new(true, owner, ctx);
        controllers.insert(cap.id().to_inner(), vp);

        cap.transfer(addr)
    });

    let mut multi = Multicontroller {
        controlled_value,
        controllers,
        owner,
        threshold,
        active_proposals: vector[],
        proposals: object_bag::new(ctx),
        revoked_tokens: vec_set::empty(),
    };
    multi.set_threshold(threshold);

    multi
}

/// Structure that encapsulates the logic required to make changes
/// to a multicontrolled value.
public struct Proposal<T: store> has key, store {
    id: UID,
    votes: u64,
    voters: VecSet<ID>,
    expiration_epoch: Option<u64>,
    action: T,
}

/// Returns `true` if `Proposal` `self` is expired.
public fun is_expired<T: store>(self: &Proposal<T>, ctx: &mut TxContext): bool {
    if (self.expiration_epoch.is_some()) {
        let expiration = *self.expiration_epoch.borrow();
        expiration < ctx.epoch()
    } else {
        false
    }
}

/// Structure that encapsulate the kind of change that will be performed
/// when a proposal is carried out.
public struct Action<T: store> {
    inner: T,
}

/// Consumes `Action` returning the inner value.
public fun unwrap<T: store>(action: Action<T>): T {
    let Action { inner } = action;
    inner
}

/// Borrows the content of `action`.
public fun borrow<T: store>(action: &Action<T>): &T {
    &action.inner
}

/// Mutably borrows the content of `action`.
public fun borrow_mut<T: store>(action: &mut Action<T>): &mut T {
    &mut action.inner
}

public(package) fun assert_is_member<V>(multi: &Multicontroller<V>, cap: &DelegationToken) {
    assert!(multi.controllers.contains(&cap.controller()), EInvalidController);
    // Make sure the presented token hasn't been revoked.
    assert!(!multi.revoked_tokens.contains(&cap.id()), EInvalidController);
}

/// Creates a new proposal for `Multicontroller` `multi`.
public fun create_proposal<V, T: store>(
    multi: &mut Multicontroller<V>,
    cap: &DelegationToken,
    action: T,
    expiration_epoch: Option<u64>,
    ctx: &mut TxContext,
): ID {
    multi.assert_is_member(cap);
    cap.assert_has_permission(permissions::can_create_proposal());

    let cap_id = cap.controller();
    let voting_power = multi.voting_power(cap_id);

    let proposal = Proposal {
        id: object::new(ctx),
        votes: voting_power,
        voters: vec_set::singleton(cap_id),
        expiration_epoch,
        action,
    };

    let proposal_id = object::id(&proposal);
    multi.proposals.add(proposal_id, proposal);
    multi.active_proposals.push_back(proposal_id);
    proposal_id
}

/// Approves an active `Proposal` in `multi`.
public fun approve_proposal<V, T: store>(
    multi: &mut Multicontroller<V>,
    cap: &DelegationToken,
    proposal_id: ID,
) {
    multi.assert_is_member(cap);
    cap.assert_has_permission(permissions::can_approve_proposal());

    let cap_id = cap.controller();
    let voting_power = multi.voting_power(cap_id);

    let proposal = multi.proposals.borrow_mut<ID, Proposal<T>>(proposal_id);
    assert!(!proposal.voters.contains(&cap_id), EControllerAlreadyVoted);

    proposal.votes = proposal.votes + voting_power;
    proposal.voters.insert(cap_id);
}

/// Consumes the `multi`'s active `Proposal` with id `proposal_id`,
/// returning its inner `Action`.
/// This call fails if `multi`'s threshold has not been reached.
public fun execute_proposal<V, T: store>(
    multi: &mut Multicontroller<V>,
    cap: &DelegationToken,
    proposal_id: ID,
    ctx: &mut TxContext,
): Action<T> {
    multi.assert_is_member(cap);
    cap.assert_has_permission(permissions::can_execute_proposal());

    let proposal = multi.proposals.remove<ID, Proposal<T>>(proposal_id);
    assert!(proposal.votes >= multi.threshold, EThresholdNotReached);
    assert!(!proposal.is_expired(ctx), EExpiredProposal);

    let Proposal {
        id,
        votes: _,
        voters: _,
        expiration_epoch: _,
        action: inner,
    } = proposal;

    id.delete();

    let (present, i) = multi.active_proposals.index_of(&proposal_id);
    assert!(present, EProposalNotFound);

    multi.active_proposals.remove(i);

    Action { inner }
}

/// Removes the approval given by the controller owning `cap` on `Proposal`
/// `proposal_id`.
public fun remove_approval<V, T: store>(
    multi: &mut Multicontroller<V>,
    cap: &DelegationToken,
    proposal_id: ID,
) {
    cap.assert_has_permission(permissions::can_remove_approval());

    let cap_id = cap.controller();
    let vp = multi.voting_power(cap_id);

    let proposal = multi.proposals.borrow_mut<ID, Proposal<T>>(proposal_id);
    assert!(proposal.voters.contains(&cap_id), ENotVotedYet);

    proposal.voters.remove(&cap_id);
    proposal.votes = proposal.votes - vp;
}

/// Removes a proposal no one has voted for.
public fun delete_proposal<V, T: store + drop>(
    multi: &mut Multicontroller<V>,
    cap: &DelegationToken,
    proposal_id: ID,
    ctx: &mut TxContext,
) {
    cap.assert_has_permission(permissions::can_delete_proposal());

    let proposal = multi.proposals.remove<ID, Proposal<T>>(proposal_id);
    assert!(proposal.votes == 0 || proposal.is_expired(ctx), ECannotDelete);

    let Proposal {
        id,
        votes: _,
        voters: _,
        expiration_epoch: _,
        action: _,
    } = proposal;

    id.delete();

    let (present, i) = multi.active_proposals.index_of(&proposal_id);
    assert!(present, EProposalNotFound);

    multi.active_proposals.remove(i);
}

/// Returns a reference to `multi`'s value.
public fun value<V: store>(multi: &Multicontroller<V>): &V {
    &multi.controlled_value
}

/// Returns the list of `multi`'s controllers - i.e. the `ID` of its `ControllerCap`s.
public fun controllers<V>(multi: &Multicontroller<V>): vector<ID> {
    multi.controllers.keys()
}

/// Returns `multi`'s threshold.
public fun threshold<V>(multi: &Multicontroller<V>): u64 {
    multi.threshold
}

/// Returns the voting power of a given controller, identified by its `ID`.
public fun voting_power<V>(multi: &Multicontroller<V>, controller_id: ID): u64 {
    *multi.controllers.get(&controller_id)
}

public(package) fun set_voting_power<V>(
    multi: &mut Multicontroller<V>,
    controller_id: ID,
    vp: u64,
) {
    assert!(multi.controllers().contains(&controller_id), EInvalidController);
    *multi.controllers.get_mut(&controller_id) = vp;
}

/// Returns the sum of all controllers voting powers.
public fun max_votes<V>(multi: &Multicontroller<V>): u64 {
    let (_, mut values) = multi.controllers.into_keys_values();
    let mut sum = 0;
    while (!values.is_empty()) {
        sum = sum + values.pop_back();
    };

    sum
}

/// Revoke the `DelegationToken` with `ID` `deny_id`. Only controllers can perform this operation.
public fun revoke_token<V>(self: &mut Multicontroller<V>, cap: &ControllerCap, deny_id: ID) {
    assert!(self.controllers.contains(object::borrow_id(cap)), EInvalidController);
    self.revoked_tokens.insert(deny_id);
}

/// Un-revoke a `DelegationToken`.
public fun unrevoke_token<V>(self: &mut Multicontroller<V>, cap: &ControllerCap, token_id: ID) {
    assert!(self.controllers.contains(object::borrow_id(cap)), EInvalidController);
    self.revoked_tokens.remove(&token_id);
}

/// Destroys a `ControllerCap`. Can only be used after a controller has been removed from
/// the controller committee.
public fun destroy_controller_cap<V>(self: &mut Multicontroller<V>, cap: ControllerCap) {
    assert!(!self.controllers.contains(&cap.id().to_inner()), EInvalidController);
    assert!(cap.controller_of() == self.owner, EInvalidController);

    cap.delete();
}

public fun remove_and_destroy_controller<V>(self: &mut Multicontroller<V>, cap: ControllerCap) {
    assert!(cap.controller_of() == self.owner, EInvalidController);

    let controller_id = object::id(&cap);
    if (self.controllers.contains(&controller_id)) {
        self.controllers.remove(&controller_id);
    };

    cap.delete();
}

/// Destroys a `DelegationToken`.
public fun destroy_delegation_token<V>(self: &mut Multicontroller<V>, token: DelegationToken) {
    let token_id = object::id(&token);
    let is_revoked = self.revoked_tokens.contains(&token_id);
    if (is_revoked) {
        self.revoked_tokens.remove(&token_id);
    };

    token.delete();
}

/// Deletes this `Multicontroller` returning the wrapped value.
/// This function can only be called if there are no active proposals.
public fun delete<V>(self: Multicontroller<V>): V {
    assert!(self.active_proposals.is_empty(), ECannotDelete);

    let Multicontroller {
        controlled_value,
        proposals,
        ..,
    } = self;

    proposals.destroy_empty();
    controlled_value
}

public(package) fun unpack_action<T: store>(action: Action<T>): T {
    let Action { inner } = action;
    inner
}

public(package) fun is_proposal_approved<V, A: store>(
    multi: &Multicontroller<V>,
    proposal_id: ID,
): bool {
    let proposal = multi.proposals.borrow<ID, Proposal<A>>(proposal_id);
    proposal.votes >= multi.threshold
}

public(package) fun add_members<V>(
    multi: &mut Multicontroller<V>,
    to_add: VecMap<address, u64>,
    ctx: &mut TxContext,
) {
    let mut i = 0;
    while (i < to_add.size()) {
        let (addr, vp) = to_add.get_entry_by_idx(i);
        let new_cap = controller::new(false, multi.owner, ctx);
        multi.controllers.insert(new_cap.id().to_inner(), *vp);
        new_cap.transfer(*addr);
        i = i + 1;
    }
}

public(package) fun owner<V>(multi: &Multicontroller<V>): ID {
    multi.owner
}

public(package) fun remove_members<V>(multi: &mut Multicontroller<V>, mut to_remove: vector<ID>) {
    while (!to_remove.is_empty()) {
        let id = to_remove.pop_back();
        multi.controllers.remove(&id);
    }
}

public(package) fun update_members<V>(
    multi: &mut Multicontroller<V>,
    mut to_update: VecMap<ID, u64>,
) {
    while (!to_update.is_empty()) {
        let (controller, vp) = to_update.pop();

        multi.set_voting_power(controller, vp);
    }
}

public(package) fun set_threshold<V>(multi: &mut Multicontroller<V>, threshold: u64) {
    assert!(threshold <= multi.max_votes(), EInvalidThreshold);
    multi.threshold = threshold;
}

public(package) fun set_controlled_value<V: store + drop>(
    multi: &mut Multicontroller<V>,
    controlled_value: V,
) {
    multi.controlled_value = controlled_value;
}

public(package) fun force_delete_proposal<V, T: drop + store>(
    self: &mut Multicontroller<V>,
    proposal_id: ID,
) {
    let proposal = self.proposals.remove<ID, Proposal<T>>(proposal_id);

    let Proposal<T> {
        id,
        ..,
    } = proposal;

    id.delete();
}
