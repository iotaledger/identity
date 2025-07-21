// Copyright 2021-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { Transaction, TransactionBuilder } from "@iota/iota-interaction-ts/transaction_internal";
import {
    AccessSubIdentity,
    Borrow,
    ConfigChange,
    ControllerExecution,
    ControllerToken,
    OnChainIdentity,
    SendAction,
    UpdateDid,
} from "~identity_wasm";

export type Action = UpdateDid | SendAction | ConfigChange | Borrow | ControllerExecution;
export type ProposalOutput<A extends Action> = A extends UpdateDid ? void
    : A extends SendAction ? void
    : A extends ConfigChange ? void
    : A extends Borrow ? void
    : A extends ControllerExecution ? void
    : never;
export type ProposalResult<A extends Action> = ProposalOutput<A> | Proposal<A>;

export type ApproveProposal = Transaction<void>;
export type ExecuteProposal<A extends Action> = Transaction<ProposalOutput<A>>;
export type CreateProposal<A extends Action> = Transaction<ProposalResult<A>>;
export interface Proposal<A extends Action> {
    id: string;
    get action(): A;
    votes: bigint;
    voters: Set<string>;
    expirationEpoch?: bigint;
    approve: (
        identity: OnChainIdentity,
        controllerToken: ControllerToken,
    ) => TransactionBuilder<ApproveProposal>;
    intoTx: (identity: OnChainIdentity, controllerToken: ControllerToken) => TransactionBuilder<ExecuteProposal<A>>;
}

export type SubAccessFn<Tx extends Transaction<unknown>> = (
    subIdentity: OnChainIdentity,
    token: ControllerToken,
) => Promise<Tx>;

// Augment Identity to properly support accessSubIdentity
declare module "~identity_wasm" {
    interface OnChainIdentity {
        /**
         * Performs an operation on Identity `subIdentity`, owned by this Identity.
         * # Params
         * @param controllerToken Transaction sender's token granting access to this Identity. 
         * @param subIdentity The sub-Identity to access.
         * @param subFn Closure describing the operation to be performed on `subIdentity`.
         * # Notes
         * `subFn` cannot make use of `this` reference. 
         */
        accessSubIdentity<Tx extends Transaction<unknown>>(
            controllerToken: ControllerToken,
            subIdentity: OnChainIdentity,
            subFn?: SubAccessFn<Tx>,
            expiration?: bigint,
        ): TransactionBuilder<Transaction<AccessSubIdentityProposal | Awaited<ReturnType<Tx["apply"]>>>>;
    }

    interface AccessSubIdentityProposal {
        /** Returns an executable transaction that consumes this proposal. */
        intoTx<Tx extends Transaction<unknown>>(
            identity: OnChainIdentity,
            identityToken: ControllerToken,
            subIdentity: OnChainIdentity,
            subAccessFn: SubAccessFn<Tx>
        ): TransactionBuilder<Tx>;
    }
}
