// Copyright 2021-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { Transaction, TransactionBuilder } from "@iota/iota-interaction-ts/transaction_internal";
import { Borrow, ConfigChange, ControllerToken, OnChainIdentity, SendAction, UpdateDid } from "~identity_wasm";

export type Action = UpdateDid | SendAction | ConfigChange | Borrow;
export type ProposalOutput<A extends Action> = A extends UpdateDid ? void
    : A extends SendAction ? void
    : A extends ConfigChange ? void
    : A extends Borrow ? void
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
    intoTx: (controllerToken: ControllerToken) => TransactionBuilder<ExecuteProposal<A>>;
}
