// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

module iota_identity::access_sub_entity_proposal {
    use iota::transfer::Receiving;
    use iota_identity::controller::{Self, ControllerCap, DelegationToken};
    use iota_identity::multicontroller::Action;

    /// A token has already been borrowed.
    const ETokenAlreadyBorrowed: u64 = 0;
    /// The received token doesn't grant access to the specified sub-entity.
    const EInvalidTokenToSubEntity: u64 = 1;
    /// Trying to return a token that has never been borrowed to begin with.
    const ENothingToReturn: u64 = 2;
    /// The returned token doesn't match the borrowed token.
    const ETokenReturnMismatch: u64 = 3;
    /// The provided entity doesn't match the one defined in this action.
    const EEntityMismatch: u64 = 4;

    /// An action that let its executor borrow either a `ControllerCap`
    /// or a `DelegationToken` from the executing entity in order to
    /// access another entity `sub_entity`.
    public struct AccessSubEntity has drop, store {
        /// The entity which has control over `sub_entity`.
        entity: ID,
        /// The entity we want to access by using `entity`'s access token.
        sub_entity: ID,
        /// Borrowed `entity`'s token.
        borrowed_token: Option<ID>,
    }

    /// Creates a proposal to access the sub-entity `sub_entity`.
    public fun new(entity: ID, sub_entity: ID): AccessSubEntity {
        AccessSubEntity {
            entity,
            sub_entity,
            borrowed_token: option::none(),
        }
    }

    /// Borrows from `entity` a `ControllerCap` granting access to `sub_entity`.
    public fun borrow_controller_cap(
        action: &mut Action<AccessSubEntity>,
        entity: &mut UID,
        recv: Receiving<ControllerCap>,
    ): ControllerCap {
        let config = action.borrow_mut();
        // Make sure no token has been borrowed yet.
        assert!(config.borrowed_token.is_none(), ETokenAlreadyBorrowed);
        // Make sure provided entity matches action's one.
        assert!(config.entity == entity.to_inner(), EEntityMismatch);
        // Receive the token from the executing entity.
        let token = controller::receive(entity, recv);
        // Make sure the received token grants access to sub_entity.
        assert!(token.controller_of() == config.sub_entity, EInvalidTokenToSubEntity);
        // Enforce borrowing only once.
        config.borrowed_token = option::some(token.id().to_inner());

        token
    }

    /// Borrows from `entity` a `DelegationToken` granting access to `sub_entity`.
    public fun borrow_delegation_token(
        action: &mut Action<AccessSubEntity>,
        entity: &mut UID,
        recv: Receiving<DelegationToken>,
    ): DelegationToken {
        let config = action.borrow_mut();
        // Make sure no token has been borrowed yet.
        assert!(config.borrowed_token.is_none(), ETokenAlreadyBorrowed);
        // Make sure provided entity matches action's one.
        assert!(config.entity == entity.to_inner(), EEntityMismatch);
        // Receive the token from the executing entity.
        let token = transfer::public_receive(entity, recv);
        // Make sure the received token grants access to sub_entity.
        assert!(token.controller_of() == config.sub_entity, EInvalidTokenToSubEntity);
        // Enforce borrowing only once.
        config.borrowed_token = option::some(token.id());

        token
    }

    /// Returns the borrowed `ControllerCap`.
    public fun put_back_controller_cap(action: Action<AccessSubEntity>, token: ControllerCap) {
        let AccessSubEntity { borrowed_token, entity, .. } = action.unwrap();
        // Make sure a token has been borrowed.
        assert!(borrowed_token.is_some(), ENothingToReturn);
        // Make sure the presented token is the one that had been borrowed.
        assert!(token.id().as_inner() == borrowed_token.borrow(), ETokenReturnMismatch);

        token.transfer(entity.to_address())
    }

    /// Returns the borrowed `DelegationToken`.
    public fun put_back_delegation_token(action: Action<AccessSubEntity>, token: DelegationToken) {
        let AccessSubEntity { borrowed_token, entity, .. } = action.unwrap();
        // Make sure a token has been borrowed.
        assert!(borrowed_token.is_some(), ENothingToReturn);
        // Make sure the presented token is the one that had been borrowed.
        assert!(token.id() == *borrowed_token.borrow(), ETokenReturnMismatch);

        transfer::public_transfer(token, entity.to_address())
    }
}

#[test_only]
module iota_identity::sub_identity_access {
    use iota::clock;
    use iota::test_scenario;
    use iota_identity::access_sub_entity_proposal::{AccessSubEntity, put_back_controller_cap};
    use iota_identity::controller::ControllerCap;
    use iota_identity::identity::{Self, Identity};

    #[test]
    fun controller_of_identity_can_access_sub_identity() {
        let controller = @0x1;
        let mut scenario = test_scenario::begin(controller);
        let clock = clock::create_for_testing(scenario.ctx());

        // We create an Identity called `identity_a` owned by `controller`.
        let identity_a = identity::new(option::some(b"DID"), &clock, scenario.ctx());

        scenario.next_tx(controller);

        // We create an Identity called `identity_b` owned by `identity_a`.
        let identity_b = identity::new_with_controller(
            option::some(b"DID"),
            identity_a.to_address(),
            false,
            &clock,
            scenario.ctx(),
        );

        scenario.next_tx(controller);

        // `controller` accesses `identity_b` through `identity_a`'s token.
        let mut identity_a = scenario.take_shared_by_id<Identity>(identity_a);
        let mut controller_cap = scenario.take_from_sender<ControllerCap>();
        let (controller_token, borrow) = controller_cap.borrow();
        let mut identity_b = scenario.take_shared_by_id<Identity>(identity_b);

        let proposal_id = identity_a.propose_access_to_sub_identity(
            &controller_token,
            &identity_b,
            option::none(),
            scenario.ctx(),
        );
        let mut sub_access_action = identity_a.execute_proposal<AccessSubEntity>(
            &controller_token,
            proposal_id,
            scenario.ctx(),
        );

        // Let's find identity_a's cap ID so that we can craft a Receiving instance.
        let identity_a_cap = scenario.take_from_address<ControllerCap>(identity_a.to_address());
        let recv = test_scenario::receiving_ticket_by_id(identity_a_cap.id().to_inner());
        test_scenario::return_to_address(identity_a.to_address(), identity_a_cap);

        let identity_a_cap = identity_a.borrow_controller_cap_to_sub_identity(
            &mut sub_access_action,
            recv,
        );
        let random_id = object::new(scenario.ctx());
        identity_b.revoke_token(&identity_a_cap, random_id.to_inner());

        // Done! Let's put everything back.
        put_back_controller_cap(sub_access_action, identity_a_cap);
        controller_cap.put_back(controller_token, borrow);
        scenario.return_to_sender(controller_cap);
        test_scenario::return_shared(identity_b);
        test_scenario::return_shared(identity_a);
        clock::destroy_for_testing(clock);
        object::delete(random_id);

        scenario.end();
    }
}
