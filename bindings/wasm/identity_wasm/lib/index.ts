// Copyright 2021-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import "./append_functions.js";

export * from "./jose";
export * from "./jwk_storage";
export * from "./key_id_storage";

export * from "~identity_wasm";

export * from "./controller";
export * from "./proposal";

export * from "@iota/iota-interaction-ts/transaction_internal";

// keep this export last to override the original `Resolver` from `identity_wasm` in the exports
export { Resolver } from "./resolver";

export * from "./jwk_storage_pq.js";
export * from "./pq_verifier.js";
