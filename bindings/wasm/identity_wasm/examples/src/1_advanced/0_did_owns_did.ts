// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { IotaDocument } from "@iota/identity-wasm/node";
import { IotaClient } from "@iota/iota-sdk/client";
import { getFundedClient, getMemstorage, NETWORK_URL } from "../util";

/** Demonstrate how an IOTA Identity can own another IOTA Identity. */
export async function didOwnsDid(): Promise<void> {
    Error.stackTraceLimit = Infinity;
    // create new client to connect to IOTA network
    const iotaClient = new IotaClient({ url: NETWORK_URL });
    const network = await iotaClient.getChainIdentifier();

    // create new client that offers identity related functions
    const storage = getMemstorage();
    const identityClient = await getFundedClient(storage);

    const { output: identity } = await identityClient
        .createIdentity(new IotaDocument(network))
        .finish()
        .buildAndExecute(identityClient);
    const identityDid = identity.didDocument().id();

    console.log(`Created Identity \`${identityDid}\``);

    // create another identity owned by the previous one.
    const { output: subIdentity } = await identityClient
        .createIdentity(new IotaDocument(network))
        .controller(identity.id(), 1n)
        .finish()
        .buildAndExecute(identityClient);
    const subIdentityDid = subIdentity.didDocument().id();

    console.log(`Created Identity \`${subIdentityDid}\` owned by Identity \`${identityDid}\``);

    // controllers of `identity` can access `subIdentity` in `identity`'s stead.
    const identityToken = await identity.getControllerToken(identityClient);
    if (!identityToken) {
        throw new Error(
            `address \`${identityClient.senderAddress()}\` has no control over Identity \`${identityDid}\``,
        );
    }
    const { output } = await identity
        .accessSubIdentity(
            identityToken,
            subIdentity,
            async (identity, token) => identity.deactivateDid(token).transaction,
        )
        .buildAndExecute(identityClient);

    console.assert(subIdentity.didDocument().metadata().deactivated, "Whooops, sub identity wasn't updated");
}
