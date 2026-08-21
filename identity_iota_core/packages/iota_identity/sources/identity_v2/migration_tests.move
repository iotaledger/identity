#[test_only]
module iota_identity::aa_migration_tests;

use iota::authenticator_function::{Self, AuthenticatorFunctionRefV1};
use iota::clock::{Self, Clock};
use iota::test_scenario;
use iota::vec_map;
use iota_identity::aa_migration_registry::{Self, AAMigrationRegistry};
use iota_identity::controller::ControllerCap;
use iota_identity::identity::{Self, Identity};
use iota_identity::identity_v2::IdentityV2;
use std::ascii;

const CONTROLLER_A: address = @0x1;
const CONTROLLER_B: address = @0x2;
const CONTROLLER_C: address = @0x3;

// Creates an identity with 3 controllers threshold is 2:
//    - Controller A: address 0x1, weight 1;
//    - Controller B: address 0x2, weight 1;
//    - Controller C: address 0x3, weight 2;
/// Creates an identity with 3 controllers threshold is 2:
///    - Controller A: address 0x1, weight 1;
///    - Controller B: address 0x2, weight 1;
///    - Controller C: address 0x3, weight 2;
    identity::new_with_controllers(
        option::some(b"DID"),
        vec_map::from_keys_values(
            vector[CONTROLLER_A, CONTROLLER_B, CONTROLLER_C],
            vector[1, 1, 2],
        ),
        vec_map::empty(),
        2,
        clock,
        ctx,
    );
}

fun auth_fn_ref(): AuthenticatorFunctionRefV1<IdentityV2> {
    authenticator_function::create_auth_function_ref_v1_for_testing(
        @0x0,
        ascii::string(b"identity_v2"),
        ascii::string(b"authenticate_v1"),
    )
}

#[test]
fun migrate_identity_with_multiple_controllers() {
    let mut scenario = test_scenario::begin(@identity_team);
    let clock = clock::create_for_testing(scenario.ctx());
    aa_migration_registry::new(scenario.ctx());

    scenario.next_tx(CONTROLLER_A);
    let mut migration_registry = scenario.take_shared<AAMigrationRegistry>();

    make_identity(&clock, scenario.ctx());
    scenario.next_tx(CONTROLLER_A);

    let mut identity = scenario.take_shared<Identity>();
    let legacy_id = identity.id().to_inner();
    let mut controller_a_cap = scenario.take_from_sender<ControllerCap>();

    identity.propose_or_approve_aa_migration(&mut controller_a_cap, scenario.ctx());
    scenario.next_tx(CONTROLLER_B);

    let controller_b_cap = scenario.take_from_sender<ControllerCap>();
    identity.execute_aa_migration(
        controller_b_cap,
        &mut migration_registry,
        auth_fn_ref(),
        scenario.ctx(),
    );
    scenario.next_tx(CONTROLLER_C);

    let controller_c_cap = scenario.take_from_sender<ControllerCap>();
    migration_registry.delete_controller_cap(controller_c_cap);
    scenario.next_tx(CONTROLLER_A);

    migration_registry.delete_controller_cap(controller_a_cap);
    let identity_v2 = scenario.take_shared<IdentityV2>();
    let config = identity_v2.borrow_config();

    assert!(config.borrow_controller(CONTROLLER_A).weight() == 1, 0);
    assert!(config.borrow_controller(CONTROLLER_B).weight() == 1, 0);
    assert!(config.controllers().length() == 2, 0);
    assert!(identity_v2.legacy_id() == option::some(legacy_id), 0);

    test_scenario::return_shared(identity_v2);
    test_scenario::return_shared(migration_registry);
    clock.destroy_for_testing();

    scenario.end();
}

#[test, expected_failure(abort_code = identity::EThresholdNotReached)]
fun migrate_requires_enough_votes() {
    let mut scenario = test_scenario::begin(@identity_team);
    let clock = clock::create_for_testing(scenario.ctx());
    aa_migration_registry::new(scenario.ctx());

    scenario.next_tx(CONTROLLER_A);
    let mut migration_registry = scenario.take_shared<AAMigrationRegistry>();

    make_identity(&clock, scenario.ctx());
    scenario.next_tx(CONTROLLER_A);

    let identity = scenario.take_shared<Identity>();
    let controller_a_cap = scenario.take_from_sender<ControllerCap>();

    identity.execute_aa_migration(controller_a_cap, &mut migration_registry, auth_fn_ref(), scenario.ctx());

    scenario.end();

    clock.destroy_for_testing();
    test_scenario::return_shared(migration_registry);
}