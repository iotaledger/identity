module iota_identity::transaction;

use iota::table::Table;

#[error(code = 0)]
const EAlreadyApproved: vector<u8> = b"Transaction already approved by this approver";
#[error(code = 1)]
const ENotAnApprover: vector<u8> = b"Address is not an approver for this transaction";

public struct Transaction has store, drop {
    digest: vector<u8>,
    approvers: vector<address>,
}

public fun digest(self: &Transaction): vector<u8> {
    self.digest
}

public fun approvers(self: &Transaction): vector<address> {
    self.approvers
}

public fun add_approver(self: &mut Transaction, approver: address) {
    assert!(!self.approvers.contains(&approver), EAlreadyApproved);
    self.approvers.push_back(approver);
}

public fun remove_approver(self: &mut Transaction, approver: address) {
    let idx = self.approvers.find_index!(|addr| *addr == approver);
    assert!(idx.is_some(), ENotAnApprover);

    self.approvers.swap_remove(idx.destroy_some());
}

public struct Transactions has store {
    transactions: Table<vector<u8>, Transaction>,
}

public fun new(ctx: &mut TxContext): Transactions {
    Transactions {
        transactions: iota::table::new(ctx),
    }
}

public fun contains(self: &Transactions, digest: &vector<u8>): bool {
    self.transactions.contains(*digest)
}

public fun borrow(self: &Transactions, digest: &vector<u8>): &Transaction {
    self.transactions.borrow(*digest)
}

public fun borrow_mut(self: &mut Transactions, digest: &vector<u8>): &mut Transaction {
    self.transactions.borrow_mut(*digest)
}

public fun insert(self: &mut Transactions, digest: vector<u8>) {
    self.transactions.add(digest, Transaction { digest, approvers: vector::empty() });
}