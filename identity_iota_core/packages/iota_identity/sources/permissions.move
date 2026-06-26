module iota_identity::permissions;

/// Permission that enables a controller's delegate to create proposals.
const CAN_CREATE_PROPOSAL: u32 = 0x1;
/// Permission that enables a controller's delegate to approve proposals.
const CAN_APPROVE_PROPOSAL: u32 = 0x1 << 1;
/// Permission that enables a controller's delegate to execute proposals.
const CAN_EXECUTE_PROPOSAL: u32 = 0x1 << 2;
/// Permission that enables a controller's delegate to delete proposals.
const CAN_DELETE_PROPOSAL: u32 = 0x1 << 3;
/// Permission that enables a controller's delegate to remove a proposal's approval.
const CAN_REMOVE_APPROVAL: u32 = 0x1 << 4;
const ALL_PERMISSIONS: u32 = 0xFFFFFFFF;

public fun can_create_proposal(): u32 { CAN_CREATE_PROPOSAL }

public fun can_approve_proposal(): u32 { CAN_APPROVE_PROPOSAL }

public fun can_execute_proposal(): u32 { CAN_EXECUTE_PROPOSAL }

public fun can_delete_proposal(): u32 { CAN_DELETE_PROPOSAL }

public fun can_remove_approval(): u32 { CAN_REMOVE_APPROVAL }

public fun all(): u32 { ALL_PERMISSIONS }

/// Negate a permission
public fun not(permission: u32): u32 {
    permission ^ all()
}
