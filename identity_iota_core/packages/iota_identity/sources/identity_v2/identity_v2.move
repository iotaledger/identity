// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

module iota_identity::identity_v2;

use iota::account::create_account_v1;
use iota::authenticator_function::AuthenticatorFunctionRefV1;
use iota::bcs;
use iota::clock::Clock;
use iota::dynamic_field as df;
use iota::ecdsa_k1::secp256k1_verify;
use iota::ecdsa_r1::secp256r1_verify;
use iota::ed25519::ed25519_verify;
use iota::hash::blake2b256;
use iota::object::id_from_bytes;
use iota::ptb_call_arg::CallArg;
use iota::ptb_command::{Command, ProgrammableMoveCall};
use iota::table::{Self, Table};
use iota_identity::identity_config::{Self as config, IdentityConfig, Controller};
use iota_identity::transaction::{Self, Transactions};

#[error(code = 0)]
const ESenderNotIdentity: vector<u8> = b"Sender must be the identity itself";
#[error(code = 1)]
const EDeletedDidDocument: vector<u8> = b"DID Document has been deleted";
#[error(code = 2)]
const EInvalidAuthenticatorFunction: vector<u8> = b"Invalid authenticator function";
#[error(code = 3)]
const EInsufficientApprovals: vector<u8> = b"Insufficient approvals for this transaction";
#[error(code = 4)]
const EInvalidControllerSignature: vector<u8> = b"Invalid controller signature";
#[error(code = 5)]
const EUnsupportedKeyType: vector<u8> = b"Unsupported key type";
#[error(code = 6)]
const ETransactionDigestMismatch: vector<u8> = b"Transaction digest mismatch";
#[error(code = 7)]
const EInsufficientPermissions: vector<u8> = b"Controller does not have sufficient permissions";
#[error(code = 8)]
const ENotASubIdentity: vector<u8> =
    b"The provided identity is not a sub-identity of this identity";
#[error(code = 9)]
const ELastCommandNotProposalRemoval: vector<u8> = b"The last command is not a call to remove_tx";
#[error(code = 10)]
const EMissingTxReceiptRemoval: vector<u8> =
    b"A TxExecutionReceipt was used for authentication but it was not removed";

public struct IdentityV2 has key {
    id: UID,
}

/// Creates a new Identity with the given DID Document.
/// The sender of the trasaction will become the single controller of the Identity
/// with a weight of 1, all permisssions, and the threshold will be set to 1, meaning that the controller
/// alone can update the DID Document in the future.
public fun new(
    did_document: vector<u8>,
    auth_fn: AuthenticatorFunctionRefV1<IdentityV2>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    new_with_config(
        did_document,
        vector[ctx.sender()],
        vector[1],
        vector[std::u64::max_value!()],
        1,
        auth_fn,
        clock,
        ctx,
    )
}

/// Creates a new Identity with the given DID Document and configuration of controllers, weights and threshold.
public fun new_with_config(
    did_document: vector<u8>,
    controllers: vector<address>,
    weights: vector<u64>,
    permissions: vector<u64>,
    threshold: u64,
    auth_fn: AuthenticatorFunctionRefV1<IdentityV2>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let now = clock.timestamp_ms();
    let config = config::new(controllers, weights, permissions, threshold);
    let did_document = DidDocument {
        document: did_document,
        created: now,
        updated: now,
        deleted: false,
    };

    new_from_parts(did_document, config, option::none(), auth_fn, ctx);
}

public(package) fun new_from_parts(
    document: DidDocument,
    config: IdentityConfig,
    legacy_id: Option<ID>,
    auth_fn: AuthenticatorFunctionRefV1<IdentityV2>,
    ctx: &mut TxContext,
): ID {
    // Ensure that the provided authenticator function is the one defined in this module.
    validate_auth_fn(&auth_fn);

    let id = object::new(ctx);
    let mut identity = IdentityV2 { id };
    let receipts_table: Table<vector<u8>, address> = table::new(ctx);

    df::add(&mut identity.id, ConfigKey {}, config);
    df::add(&mut identity.id, DidDocumentKey {}, document);
    df::add(&mut identity.id, TransactionsKey {}, transaction::new(ctx));
    df::add(
        &mut identity.id,
        TxExecutionReceiptsKey {},
        receipts_table,
    );

    if (legacy_id.is_some()) {
        df::add(&mut identity.id, LegacyIdKey {}, legacy_id.destroy_some());
    };

    let identity_id = identity.id.to_inner();
    create_account_v1(identity, auth_fn);
    identity_id
}

/// Proposes a transaction for approval by the controllers of this Identity.
public fun propose_tx(self: &mut IdentityV2, tx_digest: vector<u8>, ctx: &mut TxContext) {
    self.check_controller_permissions(ctx.sender(), config::can_propose_tx!());

    let transactions: &mut Transactions = df::borrow_mut(&mut self.id, TransactionsKey {});
    transactions.insert(tx_digest);

    let tx = transactions.borrow_mut(&tx_digest);
    tx.add_approver(ctx.sender());
}

/// Approves a transaction by the sender if it is a controller of this Identity.
public fun approve_tx(self: &mut IdentityV2, tx_digest: vector<u8>, ctx: &mut TxContext) {
    self.check_controller_permissions(ctx.sender(), config::can_approve_tx!());

    let transactions: &mut Transactions = df::borrow_mut(&mut self.id, TransactionsKey {});
    assert!(transactions.contains(&tx_digest), ETransactionDigestMismatch);

    let tx = transactions.borrow_mut(&tx_digest);
    tx.add_approver(ctx.sender());
}

public fun remove_tx(self: &mut IdentityV2, ctx: &mut TxContext) {
    // This ensures that only the identity itself can update its DID Document,
    // hence an authenticator function must have been called successfully before this function is executed.
    assert!(ctx.sender() == self.account_address(), ESenderNotIdentity);

    let transactions: &mut Transactions = df::borrow_mut(&mut self.id, TransactionsKey {});
    transactions.remove(*ctx.digest());
}

public fun id(self: &IdentityV2): ID {
    self.id.to_inner()
}

public fun borrow_uid(self: &IdentityV2): &UID {
    &self.id
}

public fun account_address(self: &IdentityV2): address {
    self.id.to_address()
}

/// Returns the DID Document of this Identity.
public fun did_document(self: &IdentityV2): DidDocument {
    *df::borrow(&self.id, DidDocumentKey {})
}

/// Returns the Identity's configuration.
public fun borrow_config(self: &IdentityV2): &IdentityConfig {
    df::borrow(&self.id, ConfigKey {})
}

/// Updates the DID Document of this Identity.
public fun update_did_document(
    self: &mut IdentityV2,
    document: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    // This ensures that only the identity itself can update its DID Document,
    // hence an authenticator function must have been called successfully before this function is executed.
    assert!(ctx.sender() == self.account_address(), ESenderNotIdentity);

    // TODO: validate the new DID Document (e.g., check the magic bytes, the encoding bytes,
    // and that it contains a JSON object).

    // Update DID Document and its timestamps.
    let now = clock.timestamp_ms();
    let document_meta = self.borrow_did_document_mut();

    // Ensure that the DID Document has not been deleted.
    assert!(!document_meta.deleted, EDeletedDidDocument);

    document_meta.document = document;
    document_meta.updated = now;
}

public fun deactivate_did_document(self: &mut IdentityV2, clock: &Clock, ctx: &mut TxContext) {
    // This ensures that only the identity itself can update its DID Document,
    // hence an authenticator function must have been called successfully before this function is executed.
    assert!(ctx.sender() == self.account_address(), ESenderNotIdentity);

    let now = clock.timestamp_ms();
    let document_meta = self.borrow_did_document_mut();

    // Ensure that the DID Document has not been deleted.
    assert!(!document_meta.deleted, EDeletedDidDocument);

    document_meta.document = vector::empty();
    document_meta.updated = now;
}

public fun delete_did_document(self: &mut IdentityV2, clock: &Clock, ctx: &mut TxContext) {
    // This ensures that only the identity itself can update its DID Document,
    // hence an authenticator function must have been called successfully before this function is executed.
    assert!(ctx.sender() == self.account_address(), ESenderNotIdentity);

    let now = clock.timestamp_ms();
    let document_meta = self.borrow_did_document_mut();

    // Ensure that the DID Document has not been deleted already.
    assert!(!document_meta.deleted, EDeletedDidDocument);

    document_meta.document = vector::empty();
    document_meta.updated = now;
    document_meta.deleted = true;
}

/// Add a new controller to this Identity.
public fun add_controller(
    self: &mut IdentityV2,
    controller: address,
    weight: u64,
    permissions: u64,
    ctx: &mut TxContext,
) {
    // This ensures that only the identity itself can update its controltransactions_lers,
    // hence an authenticator function must have been called successfully before this function is executed.
    assert!(ctx.sender() == self.account_address(), ESenderNotIdentity);

    let config: &mut IdentityConfig = df::borrow_mut(&mut self.id, ConfigKey {});
    config.add_controller(controller, weight, permissions);
}

/// Update the weight and permissions of an existing controller of this Identity.
public fun update_controller(
    self: &mut IdentityV2,
    addr: address,
    weight: u64,
    permissions: u64,
    ctx: &mut TxContext,
) {
    // This ensures that only the identity itself can update its controllers,
    // hence an authenticator function must have been called successfully before this function is executed.
    assert!(ctx.sender() == self.account_address(), ESenderNotIdentity);

    let config: &mut IdentityConfig = df::borrow_mut(&mut self.id, ConfigKey {});
    let controller = config.borrow_controller_mut(addr);
    controller.set_weight(weight);
    controller.set_permissions(permissions);
}

/// Remove a controller from this Identity.
public fun remove_controller(self: &mut IdentityV2, controller: address, ctx: &mut TxContext) {
    // This ensures that only the identity itself can update its controllers,
    // hence an authenticator function must have been called successfully before this function is executed.
    assert!(ctx.sender() == self.account_address(), ESenderNotIdentity);

    let config: &mut IdentityConfig = df::borrow_mut(&mut self.id, ConfigKey {});
    config.remove_controller(controller);
}

/// Update the approval threshold of this Identity.
public fun update_threshold(self: &mut IdentityV2, new_threshold: u64, ctx: &mut TxContext) {
    // This ensures that only the identity itself can update its threshold,
    // hence an authenticator function must have been called successfully before this function is executed.
    assert!(ctx.sender() == self.account_address(), ESenderNotIdentity);

    let config: &mut IdentityConfig = df::borrow_mut(&mut self.id, ConfigKey {});
    config.set_threshold(new_threshold);
}

/// Adds a transaction execution receipt to the sub-identity `sub_identity` for the transaction with digest `tx_digest`.
public fun add_tx_execution_receipt(
    self: &IdentityV2,
    sub_identity: &mut IdentityV2,
    tx_digest: vector<u8>,
    ctx: &mut TxContext,
) {
    // This ensures that only the identity itself can add a transaction execution receipt,
    // hence an authenticator function must have been called successfully before this function is executed.
    assert!(ctx.sender() == self.account_address(), ESenderNotIdentity);

    let sub_identity_config: &IdentityConfig = df::borrow(&sub_identity.id, ConfigKey {});
    assert!(sub_identity_config.contains(self.account_address()), ENotASubIdentity);

    let receipts_table: &mut Table<vector<u8>, address> = df::borrow_mut(
        &mut sub_identity.id,
        TxExecutionReceiptsKey {},
    );
    receipts_table.add(tx_digest, self.account_address());
}

public fun remove_tx_execution_receipt(self: &mut IdentityV2, ctx: &mut TxContext) {
    // This ensures that only the sub-identity itself can add a transaction execution receipt,
    // hence an authenticator function must have been called successfully before this function is executed.
    assert!(ctx.sender() == self.account_address(), ESenderNotIdentity);
    let receipts_table: &mut Table<vector<u8>, address> = df::borrow_mut(
        &mut self.id,
        TxExecutionReceiptsKey {},
    );
    receipts_table.remove(*ctx.digest());
}

public fun legacy_id(self: &IdentityV2): Option<ID> {
    if (df::exists_with_type<_, ID>(&self.id, LegacyIdKey {})) {
        option::some(*df::borrow(&self.id, LegacyIdKey {}))
    } else {
        option::none()
    }
}

fun borrow_did_document_mut(self: &mut IdentityV2): &mut DidDocument {
    df::borrow_mut(&mut self.id, DidDocumentKey {})
}

fun check_controller_permissions(
    identity: &IdentityV2,
    controller: address,
    required_permissions: u64,
) {
    let config: &IdentityConfig = df::borrow(&identity.id, ConfigKey {});
    let controller_info = config.borrow_controller(controller);
    assert!(
        (controller_info.permissions() & required_permissions) == required_permissions,
        EInsufficientPermissions,
    );
}

public struct DidDocument has copy, drop, store {
    document: vector<u8>,
    created: u64,
    updated: u64,
    deleted: bool,
}

public(package) fun new_did_document(
    document: vector<u8>,
    created: u64,
    updated: u64,
    deleted: bool,
): DidDocument {
    DidDocument {
        document,
        created,
        updated,
        deleted,
    }
}

public struct ConfigKey has copy, drop, store {}

public struct DidDocumentKey has copy, drop, store {}

public struct LegacyIdKey has copy, drop, store {}

public struct TransactionsKey has copy, drop, store {}

public struct TxExecutionReceiptsKey has copy, drop, store {}

#[authenticator]
public fun authenticate_v1(
    identity: &IdentityV2,
    controller_sig: Option<vector<u8>>,
    controller_pk: Option<vector<u8>>,
    auth_ctx: &AuthContext,
    ctx: &TxContext,
) {
    // This ensures that only the identity itself can update its DID Document,
    // hence an authenticator function must have been called successfully before this function is executed.
    assert!(ctx.sender() == identity.account_address(), ESenderNotIdentity);
    let config: &IdentityConfig = df::borrow(&identity.id, ConfigKey {});
    let transactions: &Transactions = df::borrow(&identity.id, TransactionsKey {});
    let mut has_authenticated_through_receipt = false;
    // Extract the invoking controller from the provided authentication parameters and validate the authenticity of the invocation.
    let controller = if (controller_sig.is_some() && controller_pk.is_some()) {
        let controller_sig = controller_sig.destroy_some();
        let controller_pk = controller_pk.destroy_some();
        validate_controller_signature(&controller_pk, &controller_sig, config, ctx.digest())
    } else {
        has_authenticated_through_receipt = true;
        let receipt_table = df::borrow(&identity.id, TxExecutionReceiptsKey {});
        check_for_receipt(receipt_table, config, ctx.digest())
    };

    identity.check_controller_permissions(controller.addr(), config::can_execute_tx!());

    // Count the total approvals for this transaction.
    let mut largest_weight = controller.weight();
    let mut approvals = controller.weight();
    let mut comulative_permissions = controller.permissions();
    let has_proposed_tx = transactions.contains(ctx.digest());
    if (has_proposed_tx) {
        let tx = transactions.borrow(ctx.digest());
        tx.approvers().do_ref!(|addr| {
            if (addr != controller.addr()) {
                let controller = config.borrow_controller(*addr);
                approvals = approvals + controller.weight();
                comulative_permissions = comulative_permissions | controller.permissions();

                if (controller.weight() > largest_weight) {
                    largest_weight = controller.weight();
                }
            }
        });
    };
    assert!(approvals >= config.threshold(), EInsufficientApprovals);

    validate_commands(
        auth_ctx.tx_inputs(),
        auth_ctx.tx_commands(),
        config,
        comulative_permissions,
        largest_weight,
    );

    if (has_proposed_tx) {
        ensure_proposal_removal(auth_ctx.tx_commands());
    };
    if (has_authenticated_through_receipt) {
        ensure_receipt_removal(auth_ctx.tx_commands());
    };
}

fun ensure_proposal_removal(commands: &vector<Command>) {
    let cmd = commands.borrow(commands.length() - 1);
    let move_call = cmd.as_move_call().destroy_some();

    assert!(move_call_is(&move_call, b"remove_tx"), ELastCommandNotProposalRemoval);
}

fun ensure_receipt_removal(commands: &vector<Command>) {
    let cmd = commands.borrow(commands.length() - 2);
    let move_call = cmd.as_move_call().destroy_some();

    assert!(move_call_is(&move_call, b"remove_tx_execution_receipt"), EMissingTxReceiptRemoval);
}

fun validate_auth_fn(auth_fn: &AuthenticatorFunctionRefV1<IdentityV2>) {
    assert!(
        auth_fn.package() == identity_v2_pkg_id()
      && auth_fn.module_name().as_bytes() == b"identity_v2"
      && auth_fn.function_name().as_bytes() == b"authenticate_v1",
        EInvalidAuthenticatorFunction,
    )
}

fun check_for_receipt(
    receipts_table: &Table<vector<u8>, address>,
    config: &IdentityConfig,
    digest: &vector<u8>,
): &Controller {
    let controller_address = *receipts_table.borrow(*digest);
    let controller = config.borrow_controller(controller_address);

    controller
}

fun validate_controller_signature(
    controller_pk: &vector<u8>,
    controller_sig: &vector<u8>,
    config: &IdentityConfig,
    digest: &vector<u8>,
): &Controller {
    let mut pk_bytes = *controller_pk;
    match (controller_pk[0]) {
        0 => {
            let mut pk_tag_removed = *controller_pk;
            pk_tag_removed.remove(0);
            pk_bytes = pk_tag_removed;
            assert!(
                ed25519_verify(controller_sig, &pk_tag_removed, digest),
                EInvalidControllerSignature,
            );
        },
        1 => {
            assert!(
                secp256r1_verify(controller_sig, controller_pk, digest, 0),
                EInvalidControllerSignature,
            );
        },
        2 => {
            assert!(
                secp256k1_verify(controller_sig, controller_pk, digest, 0),
                EInvalidControllerSignature,
            );
        },
        _ => {
            assert!(false, EUnsupportedKeyType);
        },
    };
    let controller_address = id_from_bytes(blake2b256(&pk_bytes)).to_address();
    config.borrow_controller(controller_address)
}

fun validate_commands(
    inputs: &vector<CallArg>,
    commands: &vector<Command>,
    config: &IdentityConfig,
    permissions: u64,
    weight: u64,
) {
    // If an admin controller approved this transaction, we skip the validation.
    if (permissions & config::admin!() != 0) {
        return
    };

    commands.do_ref!(|cmd| {
        if (cmd.is_move_call()) {
            let move_call = cmd.as_move_call().destroy_some();
            if (move_call_is(&move_call, b"update_did_document")) {
                assert_permissions(permissions, config::can_update_did!());
            } else if (move_call_is(&move_call, b"deactivate_did_document")) {
                assert_permissions(permissions, config::can_deactivate_did!());
            } else if (move_call_is(&move_call, b"delete_did_document")) {
                assert_permissions(permissions, config::can_delete_did!());
            } else if (move_call_is(&move_call, b"add_controller")) {
                validate_add_controller_call(&move_call, inputs, permissions, weight);
            } else if (move_call_is(&move_call, b"update_controller")) {
                validate_update_controller_call(&move_call, inputs, config, permissions, weight);
            } else if (move_call_is(&move_call, b"remove_controller")) {
                validate_remove_controller_call(&move_call, inputs, config, permissions, weight);
            } else if (move_call_is(&move_call, b"update_threshold")) {
                assert_permissions(permissions, config::can_update_threshold!());
            } else {}
        } else if (cmd.is_transfer_objects()) {
            let _transfer = cmd.as_transfer_objects().destroy_some();
            assert_permissions(permissions, config::can_transfer_asset!());
            // TODO: perform additional validations.
        }
    });
}

fun validate_add_controller_call(
    move_call: &ProgrammableMoveCall,
    inputs: &vector<CallArg>,
    approvers_permissions: u64,
    approvers_weight: u64,
) {
    assert_permissions(approvers_permissions, config::can_add_controller!());

    let input = inputs[move_call.arguments()[2].input_index().destroy_some() as u64];
    let proposed_weight = bcs::new(input.as_pure_data().destroy_some()).peel_u64();
    let input = inputs[move_call.arguments()[3].input_index().destroy_some() as u64];
    let proposed_permissions = bcs::new(input.as_pure_data().destroy_some()).peel_u64();

    assert!(proposed_weight <= approvers_weight, EInsufficientPermissions); // No inflation above approvers.
    assert_permissions_update(0, proposed_permissions, approvers_permissions);
}

fun validate_update_controller_call(
    move_call: &ProgrammableMoveCall,
    inputs: &vector<CallArg>,
    config: &IdentityConfig,
    approvers_permissions: u64,
    approvers_weight: u64,
) {
    assert_permissions(approvers_permissions, config::can_update_controller!());

    let input = inputs[move_call.arguments()[1].input_index().destroy_some() as u64];
    let target_controller_addr = bcs::new(input.as_pure_data().destroy_some()).peel_address();
    let input = inputs[move_call.arguments()[2].input_index().destroy_some() as u64];
    let new_weight = bcs::new(input.as_pure_data().destroy_some()).peel_u64();
    let input = inputs[move_call.arguments()[3].input_index().destroy_some() as u64];
    let new_permissions = bcs::new(input.as_pure_data().destroy_some()).peel_u64();
    let controller = config.borrow_controller(target_controller_addr);

    assert!(new_weight <= approvers_weight, EInsufficientPermissions); // No inflaction above approvers.
    assert!(controller.weight() <= approvers_weight, EInsufficientPermissions); // No updates to controllers with higher weight than approvers.
    assert_permissions_update(controller.permissions(), new_permissions, approvers_permissions);
}

fun validate_remove_controller_call(
    move_call: &ProgrammableMoveCall,
    inputs: &vector<CallArg>,
    config: &IdentityConfig,
    approvers_permissions: u64,
    approvers_weight: u64,
) {
    assert_permissions(approvers_permissions, config::can_remove_controller!());
    let input = inputs[move_call.arguments()[1].input_index().destroy_some() as u64];
    let target_controller_addr = bcs::new(input.as_pure_data().destroy_some()).peel_address();
    let target_controller = config.borrow_controller(target_controller_addr);
    assert!(target_controller.weight() <= approvers_weight, EInsufficientPermissions);
    assert_permissions_update(target_controller.permissions(), 0, approvers_permissions);
}

fun move_call_is(cmd: &ProgrammableMoveCall, function: vector<u8>): bool {
    *cmd.package() == identity_v2_pkg_id() 
        && cmd.module_name().as_bytes() == b"identity_v2"
        && cmd.function().as_bytes() == function
}

fun assert_permissions(permissions: u64, required_permissions: u64) {
    assert!((permissions & required_permissions) == required_permissions, EInsufficientPermissions);
}

fun assert_permissions_update(
    current_permissions: u64,
    new_permissions: u64,
    approver_permissions: u64,
) {
    assert!(
        config::is_subset_of(current_permissions ^ new_permissions, approver_permissions),
        EInsufficientPermissions,
    );
}

fun identity_v2_pkg_id(): ID {
    let type_name = std::type_name::get<IdentityV2>();
    iota::address::from_ascii_bytes(type_name.get_address().as_bytes()).to_id()
}
