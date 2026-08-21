module iota_identity::aa_migration;

public struct AAMigrationProposal has store, drop {
    controllers: vector<address>,
    weights: vector<u64>,
}

public fun new(): AAMigrationProposal {
    AAMigrationProposal {
        controllers: vector::empty(),
        weights: vector::empty(),
    }
}

public fun insert_controller(self: &mut AAMigrationProposal, addr: address, weight: u64) {
    if (self.controllers.contains(&addr)) {
        let (_, index) = self.controllers.index_of(&addr);
        let curr_weight = self.weights[index];
        *self.weights.borrow_mut(index) = curr_weight.max(weight);
    } else {
        self.controllers.push_back(addr);
        self.weights.push_back(weight);
    }
}

public fun controllers(self: &AAMigrationProposal): vector<address> {
    self.controllers
}

public fun weights(self: &AAMigrationProposal): vector<u64> {
    self.weights
}