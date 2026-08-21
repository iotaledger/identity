module iota_identity::aa_migration_registry;

use iota::table::{Self, Table};
use iota_identity::controller::ControllerCap;

#[error(code = 0)]
const ESenderNotIdentityTeam: vector<u8> =
    b"Only the identity team can create the migration registry";
#[error(code = 1)]
const EIdentityNotMigrated: vector<u8> = b"Referenced identity has not been migrated";

public struct AAMigrationRegistry has key {
    id: UID,
    migrated_identities: Table<ID, ID>,
}

public fun new(ctx: &mut TxContext) {
    assert!(ctx.sender() == @identity_team, ESenderNotIdentityTeam);
    let registry = AAMigrationRegistry {
        id: object::new(ctx),
        migrated_identities: table::new(ctx),
    };

    transfer::share_object(registry);
}

public fun get(self: &AAMigrationRegistry, old_id: ID): Option<ID> {
    if (self.migrated_identities.contains(old_id)) {
        option::some(*self.migrated_identities.borrow(old_id))
    } else {
        option::none()
    }
}

public fun delete_controller_cap(self: &AAMigrationRegistry, cap: ControllerCap) {
    assert!(self.migrated_identities.contains(cap.controller_of()), EIdentityNotMigrated);
    cap.delete_controller_cap();
}

public(package) fun insert(self: &mut AAMigrationRegistry, old_id: ID, new_id: ID) {
    self.migrated_identities.add(old_id, new_id);
}
