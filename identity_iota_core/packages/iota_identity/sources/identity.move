// Copyright (c) 2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

module iota_identity::identity {
    use iota::clock::Clock;
    use iota::transfer::Receiving;
    use iota::vec_map::{Self, VecMap};
    use iota_identity::borrow_proposal::{Self, Borrow};
    use iota_identity::config_proposal;
    use iota_identity::controller::{DelegationToken, ControllerCap};
    use iota_identity::controller_proposal::{Self, ControllerExecution};
    use iota_identity::delete_proposal::{Self, Delete};
    use iota_identity::multicontroller::{Self, Multicontroller, Action};
    use iota_identity::transfer_proposal::{Self, Send};
    use iota_identity::update_value_proposal::{Self, UpdateValue};
    use iota_identity::upgrade_proposal::{Self, Upgrade};

    const ENotADidDocument: u64 = 0;
    const EInvalidTimestamp: u64 = 1;
    /// The threshold specified upon document creation was not valid.
    /// Threshold must be greater than or equal to 1.
    const EInvalidThreshold: u64 = 2;
    /// The controller list must contain at least 1 element.
    const EInvalidControllersList: u64 = 3;
    /// There's no upgrade available for this identity.
    const ENoUpgrade: u64 = 4;
    /// Cannot delete identity.
    const ECannotDelete: u64 = 5;
    /// Identity had been deleted.
    const EDeletedIdentity: u64 = 6;

    const PACKAGE_VERSION: u64 = 0;

    // ===== Events ======
    /// Event emitted when an `identity`'s `Proposal` with `ID` `proposal` is created or executed by `controller`.
    public struct ProposalEvent has copy, drop {
        identity: ID,
        controller: ID,
        proposal: ID,
        // Set to `true` if `proposal` has been executed.
        executed: bool,
    }

    /// Event emitted when a `Proposal` has reached the AC threshold and
    /// can now be executed.
    public struct ProposalApproved has copy, drop {
        /// ID of the `Identity` owning the proposal.
        identity: ID,
        /// ID of the created `Proposal`.
        proposal: ID,
    }

    /// On-chain Identity.
    public struct Identity has key {
        id: UID,
        /// Same as stardust `state_metadata`.
        did_doc: Multicontroller<Option<vector<u8>>>,
        /// If this `Identity` has been migrated from a Stardust
        /// AliasOutput, this field must be set with its AliasID.
        legacy_id: Option<ID>,
        /// Timestamp of this Identity's creation.
        created: u64,
        /// Timestamp of this Identity's last update.
        updated: u64,
        /// Package version used by this object.
        version: u64,
        /// Flag to verify if this Identity has been deleted.
        /// Once an Identity has been deleted it CANNOT be activated again.
        deleted: bool,
        /// Set when the DID Document of this Identity has been deleted.
        /// Once a DID Document has been deleted it CANNOT be activated again.
        deleted_did: bool,
    }

    /// Creates an `Identity` with a single controller.
    public fun new(doc: Option<vector<u8>>, clock: &Clock, ctx: &mut TxContext): ID {
        new_with_controller(doc, ctx.sender(), false, clock, ctx)
    }

    /// Creates an identity specifying its `created` timestamp.
    /// Should only be used for migration!
    public(package) fun new_with_migration_data(
        doc: Option<vector<u8>>,
        creation_timestamp: u64,
        legacy_id: ID,
        clock: &Clock,
        ctx: &mut TxContext,
    ): ID {
        let now = clock.timestamp_ms();
        assert!(now >= creation_timestamp, EInvalidTimestamp);
        let id = object::new(ctx);
        let identity_id = id.to_inner();
        let identity = Identity {
            id,
            did_doc: multicontroller::new_with_controller(
                doc,
                ctx.sender(),
                false,
                identity_id,
                ctx,
            ),
            legacy_id: option::some(legacy_id),
            created: creation_timestamp,
            updated: now,
            version: PACKAGE_VERSION,
            deleted: false,
            deleted_did: false,
        };
        let id = object::id(&identity);
        transfer::share_object(identity);

        id
    }

    /// Creates a new `Identity` wrapping DID DOC `doc` and controller by
    /// a single address `controller`.
    public fun new_with_controller(
        doc: Option<vector<u8>>,
        controller: address,
        can_delegate: bool,
        clock: &Clock,
        ctx: &mut TxContext,
    ): ID {
        let now = clock.timestamp_ms();
        let id = object::new(ctx);
        let identity_id = id.to_inner();

        let identity = Identity {
            id,
            did_doc: multicontroller::new_with_controller(
                doc,
                controller,
                can_delegate,
                identity_id,
                ctx,
            ),
            legacy_id: option::none(),
            created: now,
            updated: now,
            version: PACKAGE_VERSION,
            deleted: false,
            deleted_did: false,
        };
        let id = object::id(&identity);
        transfer::share_object(identity);

        id
    }

    /// Creates an [`Identity`] controlled by multiple controllers.
    /// The `weights` vectors is used to create a vector of `ControllerCap`s `controller_caps`,
    /// where `controller_caps[i].weight = weights[i]` for all `i`s in `[0, weights.length())`.
    public fun new_with_controllers(
        doc: Option<vector<u8>>,
        controllers: VecMap<address, u64>,
        controllers_that_can_delegate: VecMap<address, u64>,
        threshold: u64,
        clock: &Clock,
        ctx: &mut TxContext,
    ): ID {
        assert!(threshold >= 1, EInvalidThreshold);
        assert!(controllers.size() > 0, EInvalidControllersList);
        if (doc.is_some()) {
            assert!(is_did_output(doc.borrow()), ENotADidDocument);
        };

        let now = clock.timestamp_ms();
        let id = object::new(ctx);
        let identity_id = id.to_inner();
        let identity = Identity {
            id,
            did_doc: multicontroller::new_with_controllers(
                doc,
                controllers,
                controllers_that_can_delegate,
                threshold,
                identity_id,
                ctx,
            ),
            legacy_id: option::none(),
            created: now,
            updated: now,
            version: PACKAGE_VERSION,
            deleted: false,
            deleted_did: false,
        };
        let id = object::id(&identity);

        transfer::share_object(identity);
        id
    }

    /// Returns a reference to the `UID` of an `Identity`.
    public fun id(self: &Identity): &UID {
        &self.id
    }

    /// Returns a reference to the optional legacy ID of this `Identity`.
    /// Only `Identity`s that had been migrated from Stardust AliasOutputs
    /// will have `legacy_id` set.
    public fun legacy_id(self: &Identity): &Option<ID> {
        &self.legacy_id
    }

    /// Returns the unsigned amount of milliseconds
    /// that passed from the UNIX epoch to the creation of this `Identity`.
    public fun created(self: &Identity): u64 {
        self.created
    }

    /// Returns the unsigned amount of milliseconds
    /// that passed from the UNIX epoch to the last update on this `Identity`.
    public fun updated(self: &Identity): u64 {
        self.updated
    }

    /// Returns the value of the flag `deleted`.
    public fun deleted(self: &Identity): bool {
        self.deleted
    }

    /// Returns the value of the flag `deleted_did`.
    public fun deleted_did(self: &Identity): bool {
        self.deleted_did
    }

    /// Returns this `Identity`'s threshold.
    public fun threshold(self: &Identity): u64 {
        self.did_doc.threshold()
    }

    /// Approve an `Identity`'s `Proposal`.
    public fun approve_proposal<T: store>(
        self: &mut Identity,
        cap: &DelegationToken,
        proposal_id: ID,
    ) {
        self.did_doc.approve_proposal<_, T>(cap, proposal_id);
        // If proposal is ready to be executed send an event.
        if (self.did_doc.is_proposal_approved<_, T>(proposal_id)) {
            iota::event::emit(ProposalApproved {
                identity: self.id().to_inner(),
                proposal: proposal_id,
            })
        }
    }

    /// Proposes the deletion of this `Identity`.
    public fun propose_deletion(
        self: &mut Identity,
        cap: &DelegationToken,
        expiration: Option<u64>,
        clock: &Clock,
        ctx: &mut TxContext,
    ): Option<ID> {
        assert!(!self.deleted, EDeletedIdentity);

        let proposal_id = self
            .did_doc
            .create_proposal(
                cap,
                delete_proposal::new(),
                expiration,
                ctx,
            );
        let is_approved = self.did_doc.is_proposal_approved<_, Delete>(proposal_id);

        if (is_approved) {
            self.execute_deletion(cap, proposal_id, clock, ctx);
            option::none()
        } else {
            emit_proposal_event(self.id().to_inner(), cap.id(), proposal_id, false);
            option::some(proposal_id)
        }
    }

    /// Executes a proposal to delete this `Identity`'s DID document.
    public fun execute_deletion(
        self: &mut Identity,
        cap: &DelegationToken,
        proposal_id: ID,
        clock: &Clock,
        ctx: &mut TxContext,
    ) {
        assert!(!self.deleted, EDeletedIdentity);
        let _ = self
            .execute_proposal<Delete>(
                cap,
                proposal_id,
                ctx,
            )
            .unwrap();
        self.deleted = true;
        self.did_doc.set_controlled_value(option::none());
        self.updated = clock.timestamp_ms();

        emit_proposal_event(self.id().to_inner(), cap.id(), proposal_id, true);
    }

    /// Creates a new `ControllerExecution` proposal.
    public fun propose_controller_execution(
        self: &mut Identity,
        cap: &DelegationToken,
        controller_cap_id: ID,
        expiration: Option<u64>,
        ctx: &mut TxContext,
    ): ID {
        assert!(!self.deleted, EDeletedIdentity);
        let identity_address = self.id().to_address();
        let proposal_id = self
            .did_doc
            .create_proposal(
                cap,
                controller_proposal::new(controller_cap_id, identity_address),
                expiration,
                ctx,
            );

        emit_proposal_event(self.id().to_inner(), cap.id(), proposal_id, false);
        proposal_id
    }

    /// Borrow the identity-owned controller cap specified in `ControllerExecution`.
    /// The borrowed cap must be put back by calling `controller_proposal::put_back`.
    public fun borrow_controller_cap(
        self: &mut Identity,
        action: &mut Action<ControllerExecution>,
        receiving: Receiving<ControllerCap>,
    ): ControllerCap {
        controller_proposal::receive(action, &mut self.id, receiving)
    }

    /// Proposes to upgrade this `Identity` to this package's version.
    public fun propose_upgrade(
        self: &mut Identity,
        cap: &DelegationToken,
        expiration: Option<u64>,
        ctx: &mut TxContext,
    ): Option<ID> {
        assert!(!self.deleted, EDeletedIdentity);
        assert!(self.version < PACKAGE_VERSION, ENoUpgrade);
        let proposal_id = self
            .did_doc
            .create_proposal(
                cap,
                upgrade_proposal::new(),
                expiration,
                ctx,
            );
        let is_approved = self.did_doc.is_proposal_approved<_, Upgrade>(proposal_id);
        if (is_approved) {
            self.execute_upgrade(cap, proposal_id, ctx);
            option::none()
        } else {
            emit_proposal_event(self.id().to_inner(), cap.id(), proposal_id, false);
            option::some(proposal_id)
        }
    }

    /// Consumes a `Proposal<Upgrade>` that migrates `Identity` to this
    /// package's version.
    public fun execute_upgrade(
        self: &mut Identity,
        cap: &DelegationToken,
        proposal_id: ID,
        ctx: &mut TxContext,
    ) {
        assert!(!self.deleted, EDeletedIdentity);
        self.execute_proposal<Upgrade>(cap, proposal_id, ctx).unwrap();
        self.migrate();
        emit_proposal_event(self.id().to_inner(), cap.id(), proposal_id, true);
    }

    /// Migrates this `Identity` to this package's version.
    fun migrate(self: &mut Identity) {
        // ADD migration logic when needed!
        self.version = PACKAGE_VERSION;
    }

    /// Proposes an update to the DID Document contained in this `Identity`.
    /// This function can update the DID Document right away if `cap` has
    /// enough voting power.
    public fun propose_update(
        self: &mut Identity,
        cap: &DelegationToken,
        updated_doc: Option<vector<u8>>,
        expiration: Option<u64>,
        clock: &Clock,
        ctx: &mut TxContext,
    ): Option<ID> {
        assert!(!self.deleted && !self.deleted_did, EDeletedIdentity);
        if (updated_doc.is_some()) {
            let doc = updated_doc.borrow();
            assert!(doc.is_empty() || is_did_output(doc), ENotADidDocument);
        };
        let proposal_id = update_value_proposal::propose_update(
            &mut self.did_doc,
            cap,
            updated_doc,
            expiration,
            ctx,
        );

        let is_approved = self
            .did_doc
            .is_proposal_approved<_, update_value_proposal::UpdateValue<Option<vector<u8>>>>(
                proposal_id,
            );
        if (is_approved) {
            self.execute_update(cap, proposal_id, clock, ctx);
            option::none()
        } else {
            emit_proposal_event(self.id().to_inner(), cap.id(), proposal_id, false);
            option::some(proposal_id)
        }
    }

    /// Executes a proposal to update the DID Document contained in this `Identity`.
    public fun execute_update(
        self: &mut Identity,
        cap: &DelegationToken,
        proposal_id: ID,
        clock: &Clock,
        ctx: &mut TxContext,
    ) {
        assert!(!self.deleted && !self.deleted_did, EDeletedIdentity);
        let updated_did_value = self
            .execute_proposal<UpdateValue<Option<vector<u8>>>>(cap, proposal_id, ctx)
            .unpack_action()
            .into_inner();

        if (updated_did_value.is_none()) {
            self.deleted_did = true;
        };

        self.did_doc.set_controlled_value(updated_did_value);

        self.updated = clock.timestamp_ms();
        emit_proposal_event(self.id().to_inner(), cap.id(), proposal_id, true);
    }

    /// Proposes to update this `Identity`'s AC.
    /// This operation might be carried out right away if `cap`
    /// has enough voting power.
    public fun propose_config_change(
        self: &mut Identity,
        cap: &DelegationToken,
        expiration: Option<u64>,
        threshold: Option<u64>,
        controllers_to_add: VecMap<address, u64>,
        controllers_to_remove: vector<ID>,
        controllers_to_update: VecMap<ID, u64>,
        ctx: &mut TxContext,
    ): Option<ID> {
        assert!(!self.deleted, EDeletedIdentity);
        let proposal_id = config_proposal::propose_modify(
            &mut self.did_doc,
            cap,
            expiration,
            threshold,
            controllers_to_add,
            controllers_to_remove,
            controllers_to_update,
            ctx,
        );

        let is_approved = self
            .did_doc
            .is_proposal_approved<_, config_proposal::Modify>(proposal_id);
        if (is_approved) {
            self.execute_config_change(cap, proposal_id, ctx);
            option::none()
        } else {
            emit_proposal_event(self.id().to_inner(), cap.id(), proposal_id, false);
            option::some(proposal_id)
        }
    }

    /// Execute a proposal to change this `Identity`'s AC.
    public fun execute_config_change(
        self: &mut Identity,
        cap: &DelegationToken,
        proposal_id: ID,
        ctx: &mut TxContext,
    ) {
        assert!(!self.deleted, EDeletedIdentity);
        config_proposal::execute_modify(
            &mut self.did_doc,
            cap,
            proposal_id,
            ctx,
        );
        emit_proposal_event(self.id().to_inner(), cap.id(), proposal_id, true);
    }

    /// Proposes the transfer of a set of objects owned by this `Identity`.
    public fun propose_send(
        self: &mut Identity,
        cap: &DelegationToken,
        expiration: Option<u64>,
        objects: vector<ID>,
        recipients: vector<address>,
        ctx: &mut TxContext,
    ): ID {
        assert!(!self.deleted, EDeletedIdentity);
        let proposal_id = transfer_proposal::propose_send(
            &mut self.did_doc,
            cap,
            expiration,
            objects,
            recipients,
            ctx,
        );
        emit_proposal_event(self.id().to_inner(), cap.id(), proposal_id, false);
        proposal_id
    }

    /// Sends one object among the one specified in a `Send` proposal.
    public fun execute_send<T: key + store>(
        self: &mut Identity,
        send_action: &mut Action<Send>,
        receiving: Receiving<T>,
    ) {
        transfer_proposal::send(send_action, &mut self.id, receiving);
    }

    /// Requests the borrowing of a set of assets
    /// in order to use them in a transaction. Borrowed assets must be returned.
    public fun propose_borrow(
        self: &mut Identity,
        cap: &DelegationToken,
        expiration: Option<u64>,
        objects: vector<ID>,
        ctx: &mut TxContext,
    ): ID {
        assert!(!self.deleted, EDeletedIdentity);
        let identity_address = self.id().to_address();
        let proposal_id = borrow_proposal::propose_borrow(
            &mut self.did_doc,
            cap,
            expiration,
            objects,
            identity_address,
            ctx,
        );
        emit_proposal_event(self.id().to_inner(), cap.id(), proposal_id, false);
        proposal_id
    }

    /// Takes one of the borrowed assets.
    public fun execute_borrow<T: key + store>(
        self: &mut Identity,
        borrow_action: &mut Action<Borrow>,
        receiving: Receiving<T>,
    ): T {
        borrow_proposal::borrow(borrow_action, &mut self.id, receiving)
    }

    /// Simplified version of `Identity::propose_config_change` that allows
    /// to add a new controller.
    public fun propose_new_controller(
        self: &mut Identity,
        cap: &DelegationToken,
        expiration: Option<u64>,
        new_controller_addr: address,
        voting_power: u64,
        ctx: &mut TxContext,
    ): Option<ID> {
        assert!(!self.deleted, EDeletedIdentity);
        let mut new_controllers = vec_map::empty();
        new_controllers.insert(new_controller_addr, voting_power);

        self.propose_config_change(
            cap,
            expiration,
            option::none(),
            new_controllers,
            vector[],
            vec_map::empty(),
            ctx,
        )
    }

    /// Executes an `Identity`'s proposal.
    public fun execute_proposal<T: store>(
        self: &mut Identity,
        cap: &DelegationToken,
        proposal_id: ID,
        ctx: &mut TxContext,
    ): Action<T> {
        assert!(!self.deleted, EDeletedIdentity);
        emit_proposal_event(self.id().to_inner(), cap.id(), proposal_id, true);
        self.did_doc.execute_proposal(cap, proposal_id, ctx)
    }

    /// Deletes an `Identity`'s proposal. Proposals can only be deleted if they have no votes, if they are expired,
    /// or if the identity is deleted.
    public fun delete_proposal<T: store + drop>(
        self: &mut Identity,
        cap: &DelegationToken,
        proposal_id: ID,
        ctx: &mut TxContext,
    ) {
        if (self.deleted) {
            self.did_doc.force_delete_proposal<_, T>(proposal_id);
        } else {
            self.did_doc.delete_proposal<_, T>(cap, proposal_id, ctx);
        }
    }

    /// revoke the `DelegationToken` with `ID` `deny_id`. Only controllers can perform this operation.
    public fun revoke_token(self: &mut Identity, cap: &ControllerCap, deny_id: ID) {
        self.did_doc.revoke_token(cap, deny_id);
    }

    /// Un-revoke a `DelegationToken`.
    public fun unrevoke_token(self: &mut Identity, cap: &ControllerCap, token_id: ID) {
        self.did_doc.unrevoke_token(cap, token_id);
    }

    /// Destroys a `ControllerCap`. Can only be used after a controller has been removed from
    /// the controller committee OR if `Identity`'s `deleted` flag is set.
    public fun destroy_controller_cap(self: &mut Identity, cap: ControllerCap) {
        if (self.deleted) {
            self.did_doc.remove_and_destroy_controller(cap);
        } else {
            self.did_doc.destroy_controller_cap(cap);
        }
    }

    /// Destroys a `DelegationToken`.
    public fun destroy_delegation_token(self: &mut Identity, token: DelegationToken) {
        self.did_doc.destroy_delegation_token(token);
    }

    /// Deletes this Identity.
    /// Calls to this method will succeed only if
    /// the `Identity` has no controllers left and its `deleted` flag had been
    /// set to `true`.
    public fun delete(self: Identity) {
        assert!(self.deleted && self.did_doc.controllers().is_empty(), ECannotDelete);
        let Identity {
            id,
            did_doc,
            ..,
        } = self;
        object::delete(id);
        did_doc.delete();
    }

    /// Checks if `data` is a state metadata representing a DID.
    /// i.e. starts with the bytes b"DID".
    public(package) fun is_did_output(data: &vector<u8>): bool {
        data[0] == 0x44 &&      // b'D'
            data[1] == 0x49 &&  // b'I'
            data[2] == 0x44 // b'D'
    }

    public(package) fun did_doc(self: &Identity): &Multicontroller<Option<vector<u8>>> {
        &self.did_doc
    }

    #[test_only]
    public(package) fun to_address(self: &Identity): address {
        self.id().to_inner().id_to_address()
    }

    public(package) fun emit_proposal_event(
        identity: ID,
        controller: ID,
        proposal: ID,
        executed: bool,
    ) {
        iota::event::emit(ProposalEvent {
            identity,
            controller,
            proposal,
            executed,
        })
    }
}

#[test_only]
module iota_identity::identity_tests {
    use iota::clock;
    use iota::test_scenario;
    use iota::vec_map;
    use iota_identity::config_proposal::Modify;
    use iota_identity::controller::ControllerCap;
    use iota_identity::identity::{
        new,
        ENotADidDocument,
        Identity,
        new_with_controllers,
        EDeletedIdentity
    };
    use iota_identity::multicontroller::{EExpiredProposal, EThresholdNotReached};

    #[test]
    fun adding_a_controller_works() {
        let controller1 = @0x1;
        let controller2 = @0x2;
        let mut scenario = test_scenario::begin(controller1);
        let clock = clock::create_for_testing(scenario.ctx());

        // Create a DID document with no funds and 1 controller with a weight of 1 and a threshold of 1.
        // Share the document and send the controller capability to `controller1`.
        let _identity_id = new(option::some(b"DID"), &clock, scenario.ctx());

        scenario.next_tx(controller1);

        // Create a request to add a second controller.
        let mut identity = scenario.take_shared<Identity>();
        let mut controller1_cap = scenario.take_from_address<ControllerCap>(controller1);
        let (token, borrow) = controller1_cap.borrow();
        // This is carried out immediately.
        identity.propose_new_controller(&token, option::none(), controller2, 1, scenario.ctx());
        controller1_cap.put_back(token, borrow);

        scenario.next_tx(controller2);

        let mut controller2_cap = scenario.take_from_address<ControllerCap>(controller2);
        let (token, borrow) = controller2_cap.borrow();

        identity.did_doc().assert_is_member(&token);
        controller2_cap.put_back(token, borrow);
        // Cleanup
        test_scenario::return_to_address(controller1, controller1_cap);
        test_scenario::return_to_address(controller2, controller2_cap);
        test_scenario::return_shared(identity);

        let _ = scenario.end();
        clock::destroy_for_testing(clock);
    }

    #[test]
    fun removing_a_controller_works() {
        let controller1 = @0x1;
        let controller2 = @0x2;
        let controller3 = @0x3;
        let mut scenario = test_scenario::begin(controller1);
        let clock = clock::create_for_testing(scenario.ctx());

        let mut controllers = vec_map::empty();
        controllers.insert(controller1, 1);
        controllers.insert(controller2, 1);
        controllers.insert(controller3, 1);

        // Create an identity shared by `controller1`, `controller2`, `controller3`.
        let _identity_id = new_with_controllers(
            option::some(b"DID"),
            controllers,
            vec_map::empty(),
            2,
            &clock,
            scenario.ctx(),
        );

        scenario.next_tx(controller1);

        // `controller1` creates a request to remove `controller3`.
        let mut identity = scenario.take_shared<Identity>();
        let mut controller1_cap = scenario.take_from_address<ControllerCap>(controller1);
        let controller3_cap = scenario.take_from_address<ControllerCap>(controller3);

        let (token, borrow) = controller1_cap.borrow();
        let proposal_id = identity
            .propose_config_change(
                &token,
                option::none(),
                option::none(),
                vec_map::empty(),
                vector[controller3_cap.id().to_inner()],
                vec_map::empty(),
                scenario.ctx(),
            )
            .destroy_some();
        controller1_cap.put_back(token, borrow);

        scenario.next_tx(controller2);

        // `controller2` also approves the removal of `controller3`.
        let mut controller2_cap = scenario.take_from_address<ControllerCap>(controller2);
        let (token, borrow) = controller2_cap.borrow();
        identity.approve_proposal<Modify>(&token, proposal_id);
        controller2_cap.put_back(token, borrow);

        scenario.next_tx(controller2);

        // `controller3` is removed.
        let (token, borrow) = controller2_cap.borrow();
        identity.execute_config_change(&token, proposal_id, scenario.ctx());
        controller2_cap.put_back(token, borrow);
        assert!(!identity.did_doc().controllers().contains(&controller3_cap.id().to_inner()), 0);

        // cleanup.
        test_scenario::return_to_address(controller1, controller1_cap);
        test_scenario::return_to_address(controller2, controller2_cap);
        test_scenario::return_to_address(controller3, controller3_cap);
        test_scenario::return_shared(identity);

        let _ = scenario.end();
        clock::destroy_for_testing(clock);
    }

    #[test, expected_failure(abort_code = EThresholdNotReached)]
    fun test_controller_addition_fails_when_threshold_not_met() {
        let controller_a = @0x1;
        let controller_b = @0x2;
        let controller_c = @0x3;

        // The controller that is not part of the ACL.
        let controller_d = @0x4;

        let mut scenario = test_scenario::begin(controller_a);
        let clock = clock::create_for_testing(scenario.ctx());

        let mut controllers = vec_map::empty();
        controllers.insert(controller_a, 10);
        controllers.insert(controller_b, 5);
        controllers.insert(controller_c, 5);

        // === First transaction ===
        // Controller A can execute config changes
        {
            let _ = new_with_controllers(
                option::some(b"DID"),
                controllers,
                vec_map::empty(),
                10,
                &clock,
                scenario.ctx(),
            );
            scenario.next_tx(controller_a);

            // Controller A alone should be able to do anything.
            let mut identity = scenario.take_shared<Identity>();
            let mut controller_a_cap = scenario.take_from_address<ControllerCap>(controller_a);
            let (token, borrow) = controller_a_cap.borrow();

            // Create a request to add a new controller. This is carried out immediately as controller_a has enough voting power
            identity.propose_new_controller(
                &token,
                option::none(),
                controller_d,
                1,
                scenario.ctx(),
            );
            controller_a_cap.put_back(token, borrow);

            scenario.next_tx(controller_d);

            let mut controller_d_cap = scenario.take_from_address<ControllerCap>(controller_d);
            let (token, borrow) = controller_d_cap.borrow();

            identity.did_doc().assert_is_member(&token);
            controller_d_cap.put_back(token, borrow);

            test_scenario::return_shared(identity);
            test_scenario::return_to_address(controller_a, controller_a_cap);
            test_scenario::return_to_address(controller_d, controller_d_cap);
        };

        // Controller B alone should not be able to make changes.
        {
            let _ = new_with_controllers(
                option::some(b"DID"),
                controllers,
                vec_map::empty(),
                10,
                &clock,
                scenario.ctx(),
            );
            scenario.next_tx(controller_a);

            let mut identity = scenario.take_shared<Identity>();
            let mut controller_b_cap = scenario.take_from_address<ControllerCap>(controller_b);
            let (token, borrow) = controller_b_cap.borrow();

            let proposal_id = identity
                .propose_new_controller(&token, option::none(), controller_d, 1, scenario.ctx())
                .destroy_some();

            scenario.next_tx(controller_b);
            identity.execute_config_change(&token, proposal_id, scenario.ctx());
            controller_b_cap.put_back(token, borrow);
            scenario.next_tx(controller_d);

            let controller_d_cap = scenario.take_from_address<ControllerCap>(controller_d);
            assert!(
                !identity.did_doc().controllers().contains(&controller_d_cap.id().to_inner()),
                0,
            );

            test_scenario::return_to_address(controller_b, controller_b_cap);
            test_scenario::return_to_address(controller_d, controller_d_cap);
            test_scenario::return_shared(identity);
        };
        let _ = scenario.end();
        clock::destroy_for_testing(clock);
    }

    #[test]
    fun test_controller_addition_works_when_threshold_met() {
        let controller_a = @0x1;
        let controller_b = @0x2;
        let controller_c = @0x3;

        // The controller that is not part of the ACL.
        let controller_d = @0x4;

        let mut scenario = test_scenario::begin(controller_b);
        let clock = clock::create_for_testing(scenario.ctx());

        let mut controllers = vec_map::empty();
        controllers.insert(controller_a, 10);
        controllers.insert(controller_b, 5);
        controllers.insert(controller_c, 5);

        // === First transaction ===
        // Controller B & C can execute config changes
        let _ = new_with_controllers(
            option::some(b"DID"),
            controllers,
            vec_map::empty(),
            10,
            &clock,
            scenario.ctx(),
        );
        scenario.next_tx(controller_b);

        let mut identity = scenario.take_shared<Identity>();
        let mut controller_b_cap = scenario.take_from_address<ControllerCap>(controller_b);
        let (token, borrow) = controller_b_cap.borrow();

        // Create a request to add a new controller.
        let proposal_id = identity
            .propose_new_controller(&token, option::none(), controller_d, 10, scenario.ctx())
            .destroy_some();
        controller_b_cap.put_back(token, borrow);

        scenario.next_tx(controller_b);
        let mut controller_c_cap = scenario.take_from_address<ControllerCap>(controller_c);
        let (token, borrow) = controller_c_cap.borrow();
        identity.approve_proposal<Modify>(&token, proposal_id);

        scenario.next_tx(controller_a);
        identity.execute_config_change(&token, proposal_id, scenario.ctx());
        controller_c_cap.put_back(token, borrow);

        scenario.next_tx(controller_d);

        let mut controller_d_cap = scenario.take_from_address<ControllerCap>(controller_d);
        let (token, borrow) = controller_d_cap.borrow();
        identity.did_doc().assert_is_member(&token);
        controller_d_cap.put_back(token, borrow);

        test_scenario::return_shared(identity);
        test_scenario::return_to_address(controller_b, controller_b_cap);
        test_scenario::return_to_address(controller_c, controller_c_cap);
        test_scenario::return_to_address(controller_d, controller_d_cap);

        let _ = scenario.end();
        clock::destroy_for_testing(clock);
    }

    #[test]
    fun check_identity_can_own_another_identity() {
        let controller_a = @0x1;
        let mut scenario = test_scenario::begin(controller_a);
        let clock = clock::create_for_testing(scenario.ctx());

        let _ = new(option::some(b"DID"), &clock, scenario.ctx());

        scenario.next_tx(controller_a);
        let first_identity = scenario.take_shared<Identity>();

        let mut controllers = vec_map::empty();
        controllers.insert(first_identity.to_address(), 10);

        // Create a second identity.
        let _ = new_with_controllers(
            option::some(b"DID"),
            controllers,
            vec_map::empty(),
            10,
            &clock,
            scenario.ctx(),
        );

        scenario.next_tx(first_identity.to_address());
        let mut first_identity_cap = scenario.take_from_address<
            ControllerCap,
        >(first_identity.to_address());
        let (token, borrow) = first_identity_cap.borrow();

        let mut second_identity = scenario.take_shared<Identity>();

        assert!(
            second_identity.did_doc().controllers().contains(&first_identity_cap.id().to_inner()),
            0,
        );

        second_identity
            .propose_new_controller(&token, option::none(), controller_a, 10, scenario.ctx())
            .destroy_none();
        first_identity_cap.put_back(token, borrow);

        scenario.next_tx(controller_a);
        let mut controller_a_cap = scenario.take_from_address<ControllerCap>(controller_a);
        let (token, borrow) = controller_a_cap.borrow();

        second_identity.did_doc().assert_is_member(&token);
        controller_a_cap.put_back(token, borrow);

        test_scenario::return_shared(second_identity);
        test_scenario::return_to_address(controller_a, controller_a_cap);
        test_scenario::return_to_address(first_identity.to_address(), first_identity_cap);
        test_scenario::return_shared(first_identity);

        let _ = scenario.end();
        clock::destroy_for_testing(clock);
    }

    #[test, expected_failure(abort_code = ENotADidDocument)]
    fun test_update_proposal_cannot_propose_non_did_doc() {
        let controller = @0x1;
        let mut scenario = test_scenario::begin(controller);
        let clock = clock::create_for_testing(scenario.ctx());

        let _ = new(option::some(b"DID"), &clock, scenario.ctx());

        scenario.next_tx(controller);

        // Propose a change for updating the did document
        let mut identity = scenario.take_shared<Identity>();
        let mut cap = scenario.take_from_address<ControllerCap>(controller);
        let (token, borrow) = cap.borrow();

        let _proposal_id = identity.propose_update(
            &token,
            option::some(b"NOT DID"),
            option::none(),
            &clock,
            scenario.ctx(),
        );
        cap.put_back(token, borrow);

        test_scenario::return_to_address(controller, cap);
        test_scenario::return_shared(identity);

        scenario.end();
        clock::destroy_for_testing(clock);
    }

    #[test, expected_failure(abort_code = EExpiredProposal)]
    fun expired_proposals_cannot_be_executed() {
        let controller_a = @0x1;
        let controller_b = @0x2;
        let new_controller = @0x3;
        let mut scenario = test_scenario::begin(controller_a);
        let expiration_epoch = scenario.ctx().epoch();
        let clock = clock::create_for_testing(scenario.ctx());

        let mut controllers = vec_map::empty();
        controllers.insert(controller_a, 1);
        controllers.insert(controller_b, 1);

        let _ = new_with_controllers(
            option::some(b"DID"),
            controllers,
            vec_map::empty(),
            2,
            &clock,
            scenario.ctx(),
        );

        scenario.next_tx(controller_a);

        let mut identity = scenario.take_shared<Identity>();
        let mut cap = scenario.take_from_address<ControllerCap>(controller_a);
        let (token, borrow) = cap.borrow();
        let proposal_id = identity
            .propose_new_controller(
                &token,
                option::some(expiration_epoch),
                new_controller,
                1,
                scenario.ctx(),
            )
            .destroy_some();
        cap.put_back(token, borrow);

        scenario.next_tx(controller_b);
        let mut cap_b = scenario.take_from_address<ControllerCap>(controller_b);
        let (token, borrow) = cap_b.borrow();
        identity.approve_proposal<Modify>(&token, proposal_id);
        cap_b.put_back(token, borrow);

        scenario.later_epoch(100, controller_a);
        // this should fail!
        let (token, borrow) = cap.borrow();
        identity.execute_config_change(&token, proposal_id, scenario.ctx());
        cap.put_back(token, borrow);

        test_scenario::return_to_address(controller_a, cap);
        test_scenario::return_to_address(controller_b, cap_b);
        test_scenario::return_shared(identity);

        scenario.end();
        clock::destroy_for_testing(clock);
    }

    #[test]
    fun identity_can_be_deleted() {
        let controller = @0x1;
        let mut scenario = test_scenario::begin(controller);
        let clock = clock::create_for_testing(scenario.ctx());

        let _ = new(option::some(b"DID"), &clock, scenario.ctx());

        scenario.next_tx(controller);

        let mut identity = scenario.take_shared<Identity>();
        let mut cap = scenario.take_from_address<ControllerCap>(controller);
        let (token, borrow) = cap.borrow();
        identity.propose_deletion(&token, option::none(), &clock, scenario.ctx());
        cap.put_back(token, borrow);

        scenario.next_tx(controller);
        identity.destroy_controller_cap(cap);

        assert!(identity.deleted());
        identity.delete();

        scenario.end();
        clock::destroy_for_testing(clock);
    }

    #[test, expected_failure(abort_code = EDeletedIdentity)]
    fun updating_did_with_none_deletes_it() {
        let controller = @0x1;
        let mut scenario = test_scenario::begin(controller);
        let clock = clock::create_for_testing(scenario.ctx());

        let _ = new(option::some(b"DID"), &clock, scenario.ctx());

        scenario.next_tx(controller);

        let mut identity = scenario.take_shared<Identity>();
        let mut cap = scenario.take_from_address<ControllerCap>(controller);
        let (token, borrow) = cap.borrow();
        identity.propose_update(&token, option::none(), option::none(), &clock, scenario.ctx());

        assert!(identity.deleted_did());

        scenario.next_tx(controller);

        // This should fail
        identity.propose_update(
            &token,
            option::some(b"DID"),
            option::none(),
            &clock,
            scenario.ctx(),
        );

        cap.put_back(token, borrow);
        test_scenario::return_to_address(controller, cap);
        test_scenario::return_shared(identity);

        scenario.end();
        clock::destroy_for_testing(clock);
    }
}
