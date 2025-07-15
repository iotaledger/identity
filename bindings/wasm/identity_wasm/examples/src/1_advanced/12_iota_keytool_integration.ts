// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
    IdentityClient,
    IdentityClientReadOnly,
    IotaDocument,
    JwkKeytoolStore,
    JwsAlgorithm,
    KeyIdKeytoolStore,
    KeytoolStorage,
    MethodScope,
    Storage,
} from "@iota/identity-wasm/node";
import { IotaClient } from "@iota/iota-sdk/client";
import { IOTA_IDENTITY_PKG_ID, NETWORK_URL, requestFunds } from "../util";

export async function iotaKeytoolIntegration() {
    // For starter we access the local IOTA Keytool executable to create a new keypair.
    const keytool = new KeytoolStorage();
    // We generate a new Ed25519 key handled by the keytool, that we will use to interact with the ledger
    // throughout this example.
    const [pk, alias] = keytool.generateKey("ed25519");
    const address = pk.toIotaAddress();
    console.log(`Created new address ${address} with alias ${alias}!`);

    // Let's request some funds for our new address.
    await requestFunds(address);

    // Let's use the newly generated key to build the signer that will power our identity client.
    const iotaClient = new IotaClient({ url: NETWORK_URL });
    const readOnlyClient = await IdentityClientReadOnly.createWithPkgId(iotaClient, IOTA_IDENTITY_PKG_ID);
    const signer = keytool.signer(address);
    // A signer that relies on IOTA Keytool may also be built with:
    // const signer = new KeytoolSigner(address);
    const identityClient = await IdentityClient.create(readOnlyClient, signer);

    // Let's create a new DID Document, with a verification method
    // that has its secret key stored in the Keytool.

    // Firstly, we create a storage instance from our Keytool.
    const storage = new Storage(new JwkKeytoolStore(keytool), new KeyIdKeytoolStore(keytool));
    // Then we start building our DID Document.
    const didDocument = new IotaDocument(identityClient.network());
    const _vmFragment = await didDocument.generateMethod(
        storage,
        "secp256r1",
        JwsAlgorithm.ES256,
        null,
        MethodScope.VerificationMethod(),
    );

    // Let's publish our new DID Document.
    let publishedDidDocument = await identityClient
        .publishDidDocument(didDocument, identityClient.senderAddress())
        .buildAndExecute(identityClient)
        .then(res => res.output);

    console.log(`Here is our published DID document: ${JSON.stringify(publishedDidDocument, null, 2)}`);
}
