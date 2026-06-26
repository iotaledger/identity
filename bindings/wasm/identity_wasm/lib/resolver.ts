// Copyright 2021-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { CoreDocument, IToCoreDocument, Resolver as ResolverInner } from "~identity_wasm";

// `Resolver` type below acts the same as the "normal" resolver from `~identity_wasm`
// with the difference being that the `Resolver` here allows to pass generic type params to
// the constructor to specify the types expected to be returned by the `resolve` function.

/**
 * Convenience type for resolving DID documents from different DID methods.
 *
 * DID documents resolved with `resolve` will have the type specified as generic type parameter T.
 * With the default being `CoreDocument | IToCoreDocument`.
 *
 * Also provides methods for resolving DID Documents associated with
 * verifiable {@link identity_wasm/node/identity_wasm.Credential | Credential}s
 * and {@link identity_wasm/node/identity_wasm.Presentation | Presentation}s.
 *
 * # Configuration
 *
 * The resolver will only be able to resolve DID documents for methods it has been configured for in the constructor.
 */
export class Resolver<T extends (CoreDocument | IToCoreDocument)> extends ResolverInner {
    /**
     * Fetches the DID Document of the given DID.
     *
     * ### Errors
     *
     * Errors if the resolver has not been configured to handle the method
     * corresponding to the given DID or the resolution process itself fails.
     * @param {string} did
     * @returns {Promise<T>}
     */
    async resolve(did: string): Promise<T> {
        return super.resolve(did) as unknown as T;
    }
}
