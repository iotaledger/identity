// Copyright (c) 2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

module iota_identity::migration_registry;

use iota::dynamic_field as field;
use iota::event;
use iota::transfer::share_object;

const BEACON_BYTES: vector<u8> = b"identity.rs_pkg";

/// One time witness needed to construct a singleton `MigrationRegistry`.
public struct MIGRATION_REGISTRY has drop {}

/// Event type that is fired upon creation of a `MigrationRegistry`.
public struct MigrationRegistryCreated has copy, drop {
    id: ID,
    beacon: vector<u8>,
}

/// Object that tracks migrated alias outputs to their corresponding object IDs.
public struct MigrationRegistry has key {
    id: UID,
}

/// Creates a singleton instance of `MigrationRegistry` when publishing this package.
fun init(_otw: MIGRATION_REGISTRY, ctx: &mut TxContext) {
    let id = object::new(ctx);
    let registry_id = id.to_inner();
    let registry = MigrationRegistry {
        id,
    };
    share_object(registry);
    // Signal the creation of a migration registry.
    event::emit(MigrationRegistryCreated { id: registry_id, beacon: BEACON_BYTES });
}

/// Checks whether the given alias ID exists in the migration registry.
public fun exists(self: &MigrationRegistry, alias_id: ID): bool {
    field::exists_(&self.id, alias_id)
}

/// Lookup an alias ID into the migration registry.
public fun lookup(self: &MigrationRegistry, alias_id: ID): ID {
    *field::borrow<ID, ID>(&self.id, alias_id)
}

/// Adds a new Alias ID -> Object ID binding to the regitry.
public(package) fun add(self: &mut MigrationRegistry, alias_id: ID, identity_id: ID) {
    field::add(&mut self.id, alias_id, identity_id);
}

#[test_only]
public fun init_testing(ctx: &mut TxContext) {
    init(MIGRATION_REGISTRY {}, ctx);
}
