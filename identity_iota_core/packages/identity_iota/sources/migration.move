module identity_iota::migration {
    use identity_iota::{migration_registry::MigrationRegistry, identity};
    use stardust::{alias::Alias, alias_output::{AliasOutput, extract_assets}};
    use iota::coin;

    const ENotADidOutput: u64 = 1;

    public fun migrate_alias(
        alias: Alias,
        migration_registry: &mut MigrationRegistry,
        ctx: &mut TxContext,
    ): address {
        let (
            alias_id,
            _,
            _,
            mut state_metadata,
            _,
            _,
            _,
            _,
        ) = alias.destructure();
        // Check if `state_metadata` contains a DID document.
        assert!(state_metadata.is_some() && identity::is_did_output(state_metadata.borrow()), ENotADidOutput);
        let legacy_id = alias_id.to_inner();
        // Destroy alias.
        object::delete(alias_id);

        let identity = identity::new(state_metadata.extract(), ctx);
        let identity_addr = identity.id().to_address();

        // Add a migration record.
        migration_registry.add(legacy_id, identity.id().to_inner());
        transfer::public_share_object(identity);

        identity_addr
    }

    /// Creates a new `Document` from an Iota 1.0 legacy `AliasOutput`.
    public fun migrate_alias_output(alias_output: AliasOutput, migration_registry: &mut MigrationRegistry, ctx: &mut TxContext) {
        // Extract required data from output.
        let (iota, native_tokens, alias_data) = extract_assets(alias_output);

        let doc_addr = migrate_alias(alias_data, migration_registry, ctx);

        let coin = coin::from_balance(iota, ctx);
        transfer::public_transfer(coin, doc_addr);
        transfer::public_transfer(native_tokens, doc_addr);
    }
}


#[test_only]
module identity_iota::migration_tests {
    use iota::test_scenario;
    use stardust::alias_output::{create_empty_for_testing, AliasOutput, attach_alias};
    use identity_iota::identity::{Identity};
    use identity_iota::migration::migrate_alias_output;
    use stardust::alias::{Alias, create_with_state_metadata_for_testing};
    use identity_iota::migration_registry::{MigrationRegistry, init_testing};
    use identity_iota::multicontroller::ControllerCap;

    #[test]
    fun test_migration_of_legacy_did_output() {
        let controller_a = @0x1;
        let mut scenario = test_scenario::begin(controller_a);

        let alias_output = create_empty_for_testing(scenario.ctx());
        transfer::public_transfer(alias_output, controller_a);

        scenario.next_tx(controller_a);
        let mut alias_output = scenario.take_from_sender<AliasOutput>();

        scenario.next_tx(controller_a);

        let alias: Alias = create_with_state_metadata_for_testing(
            option::none(),
            1,
            b"DID",
            option::none(),
            option::none(),
            option::none(),
            option::none(),
            scenario.ctx()
        );

        let alias_id = object::id(&alias);
        alias_output.attach_alias(alias);

        init_testing(scenario.ctx());

        scenario.next_tx(controller_a);
        let mut registry = scenario.take_shared<MigrationRegistry>();

        migrate_alias_output(alias_output, &mut registry, scenario.ctx());

        scenario.next_tx(controller_a);
        let identity = scenario.take_shared<Identity>();
        let controller_a_cap = scenario.take_from_address<ControllerCap>(controller_a);

        // Assert correct binding in migration regitry
        assert!(registry.lookup(alias_id) == identity.id().to_inner(), 0);

        // Assert the sender is controller
        identity.did_doc().assert_is_member(&controller_a_cap);

        // assert the metadata is b"DID"
        let did = identity.did_doc().value();
        assert!(did == b"DID", 0);

        test_scenario::return_to_address(controller_a, controller_a_cap);
        test_scenario::return_shared(registry);
        test_scenario::return_shared(identity);
        let _ = scenario.end();
    }
}
