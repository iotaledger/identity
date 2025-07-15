// Copyright (c) 2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

module iota_identity::migration {
    use iota::clock::Clock;
    use iota::coin;
    use iota::iota::IOTA;
    use iota_identity::identity;
    use iota_identity::migration_registry::MigrationRegistry;
    use stardust::alias::Alias;
    use stardust::alias_output::AliasOutput;

    const ENotADidOutput: u64 = 1;

    #[allow(lint(share_owned))]
    public fun migrate_alias(
        alias: Alias,
        migration_registry: &mut MigrationRegistry,
        creation_timestamp: u64,
        clock: &Clock,
        ctx: &mut TxContext,
    ): address {
        // Extract needed data from `alias`.
        let alias_id = object::id(&alias);
        let mut state_metadata = *alias.state_metadata();
        // `alias` is not needed anymore, destroy it.
        alias.destroy();

        // Check if `state_metadata` contains a DID document.
        assert!(
            state_metadata.is_some() && identity::is_did_output(state_metadata.borrow()),
            ENotADidOutput,
        );

        let identity_id = identity::new_with_migration_data(
            option::some(state_metadata.extract()),
            creation_timestamp,
            alias_id,
            clock,
            ctx,
        );

        // Add a migration record.
        migration_registry.add(alias_id, identity_id);

        identity_id.to_address()
    }

    /// Creates a new `Identity` from an Iota 1.0 legacy `AliasOutput` containing a DID Document.
    public fun migrate_alias_output(
        alias_output: AliasOutput<IOTA>,
        migration_registry: &mut MigrationRegistry,
        creation_timestamp: u64,
        clock: &Clock,
        ctx: &mut TxContext,
    ) {
        // Extract required data from output.
        let (iota, native_tokens, alias_data) = alias_output.extract_assets();

        let identity_addr = migrate_alias(
            alias_data,
            migration_registry,
            creation_timestamp,
            clock,
            ctx,
        );

        let coin = coin::from_balance(iota, ctx);
        transfer::public_transfer(coin, identity_addr);
        transfer::public_transfer(native_tokens, identity_addr);
    }
}

#[test_only]
module iota_identity::migration_tests {
    use iota::bag;
    use iota::balance;
    use iota::clock;
    use iota::iota::IOTA;
    use iota::test_scenario;
    use iota_identity::controller::ControllerCap;
    use iota_identity::identity::Identity;
    use iota_identity::migration::migrate_alias_output;
    use iota_identity::migration_registry::{MigrationRegistry, init_testing};
    use stardust::alias::{Self, Alias};
    use stardust::alias_output::{Self, AliasOutput};

    fun create_did_alias(ctx: &mut TxContext): Alias {
        let sender = ctx.sender();
        alias::create_for_testing(
            sender,
            1,
            option::some(b"DID"),
            option::some(sender),
            option::none(),
            option::none(),
            option::none(),
            ctx,
        )
    }

    fun create_empty_did_output(ctx: &mut TxContext): (AliasOutput<IOTA>, ID) {
        let mut alias_output = alias_output::create_for_testing(
            balance::zero(),
            bag::new(ctx),
            ctx,
        );
        let alias = create_did_alias(ctx);
        let alias_id = object::id(&alias);
        alias_output.attach_alias(alias);

        (alias_output, alias_id)
    }

    #[test]
    fun test_migration_of_legacy_did_output() {
        let controller_a = @0x1;
        let mut scenario = test_scenario::begin(controller_a);
        let clock = clock::create_for_testing(scenario.ctx());

        let (did_output, alias_id) = create_empty_did_output(scenario.ctx());

        init_testing(scenario.ctx());

        scenario.next_tx(controller_a);
        let mut registry = scenario.take_shared<MigrationRegistry>();

        migrate_alias_output(
            did_output,
            &mut registry,
            clock.timestamp_ms(),
            &clock,
            scenario.ctx(),
        );

        scenario.next_tx(controller_a);
        let identity = scenario.take_shared<Identity>();
        let mut controller_a_cap = scenario.take_from_address<ControllerCap>(controller_a);
        let (token, borrow) = controller_a_cap.borrow();

        // Assert correct binding in migration registry
        assert!(registry.lookup(alias_id) == identity.id().to_inner(), 0);
        // Assert correct backward-binding in Identity
        assert!(*identity.legacy_id().borrow() == alias_id, 0);

        // Assert the sender is controller
        identity.did_doc().assert_is_member(&token);
        controller_a_cap.put_back(token, borrow);

        // assert the metadata is b"DID"
        let did = identity.did_doc().value().borrow();
        assert!(did == &b"DID", 0);

        test_scenario::return_to_address(controller_a, controller_a_cap);
        test_scenario::return_shared(registry);
        test_scenario::return_shared(identity);
        let _ = scenario.end();
        clock::destroy_for_testing(clock);
    }
}
