// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { IotaClient } from "@iota/iota-sdk/client";
import { createDocumentForNetwork, getFundedClient, getMemstorage, NETWORK_URL, TEST_GAS_BUDGET } from "../util";

/** Demonstrates how to delete a DID of an identity. */
export async function deleteIdentityDID() {
    // create new clients and create new account
    const iotaClient = new IotaClient({ url: NETWORK_URL });
    const network = await iotaClient.getChainIdentifier();
    const storage = getMemstorage();
    const identityClient = await getFundedClient(storage);
    const [unpublished] = await createDocumentForNetwork(storage, network);

    // create new identity for this account and publish document for it
    const { output: identity } = await identityClient
        .createIdentity(unpublished)
        .finish()
        .buildAndExecute(identityClient);
    const did = identity.didDocument().id();

    // Resolve the latest state of the document.
    // Technically this is equivalent to the document above.
    const resolved = await identityClient.resolveDid(did);
    console.log("Resolved DID document:", JSON.stringify(resolved, null, 2));

    const controllerToken = await identity.getControllerToken(identityClient);

    // delete the DID.
    await identity
        .deleteDid(controllerToken!)
        .withGasBudget(TEST_GAS_BUDGET)
        .buildAndExecute(identityClient);

    // After an Identity's DID has been deleted, the document will be
    // empty and inactive. Identity.hasDeletedDid must return `true`.
    const is_deleted = identity.didDocument().metadata().deactivated()
        && identity.hasDeletedDid();
    if (!is_deleted) {
        throw new Error("failed to delete DID Document");
    }

    // Resolving a deleted DID must throw an error.
    try {
        let deactivated = await identityClient.resolveDid(did);
    } catch (_) {
        console.log(`DID ${did} was successfully deleted!`);
    }

    // Trying to update a deleted DID must fail!
    try {
        await identity
            .updateDidDocument(resolved, controllerToken!)
            .withGasBudget(TEST_GAS_BUDGET)
            .buildAndExecute(identityClient);
    } catch (_) {
        console.log("A deleted DID cannot be updated!");
    }
}
