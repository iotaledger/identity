import { DelegationToken } from "~identity_wasm";

/**
 * Permissions of a {@link DelegationToken}.
 */
export enum DelegatePermissions {
    /** No permissions. */
    None = 0,
    /** Delegate can create new proposals. */
    CreateProposal = 1,
    /** Delegate can approve existing proposals. */
    ApproveProposal = 1 << 1,
    /** Delegate can execute proposals. */
    ExecuteProposal = 1 << 2,
    /** Delegate can delete proposals. */
    DeleteProposal = 1 << 3,
    /** Delegate can remove its controller's approval. */
    RemoveApproval = 1 << 4,
    /** All permissions. */
    All = 0xffffffff,
}
