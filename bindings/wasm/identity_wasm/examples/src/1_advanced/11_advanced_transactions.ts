// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { IdentityClient, IotaDocument } from "@iota/identity-wasm/node";
import { IotaClient } from "@iota/iota-sdk/client";
import { TransactionDataBuilder } from "@iota/iota-sdk/transactions";
import { getFundedClient, getMemstorage, NETWORK_URL } from "../util";

/**
 * This example demonstrates:
 * 1. A user - Alice - can build a transaction that is sponsored by another user - Bob;
 * 2. Deconstruct the transaction into its parts, to execute it manually through the SDK's IotaClient;
 * 3. Apply the transaction's off-chain effects, from its on-chain ones.
 */
export async function advancedTransaction(): Promise<void> {
    const aliceStorage = getMemstorage();
    const aliceClient = await getFundedClient(aliceStorage);

    const bobStorage = getMemstorage();
    const bobClient = await getFundedClient(bobStorage);

    const [txDataBcs, signatures, tx] = await aliceClient
        .createIdentity(new IotaDocument(aliceClient.network()))
        .finish()
        .withSender(aliceClient.senderAddress())
        .withSponsor(aliceClient.readOnly(), (tx_data: TransactionDataBuilder) => bobSponsorFn(tx_data, bobClient))
        .then(txBuilder => txBuilder.build(aliceClient));

    // create new client to connect to IOTA network
    const iotaClient = new IotaClient({ url: NETWORK_URL });
    const tx_response = await iotaClient.executeTransactionBlock({
        transactionBlock: txDataBcs,
        signature: signatures,
        options: { showEffects: true },
    });
    await iotaClient.waitForTransaction({ digest: tx_response.digest });

    const identity = await tx.apply(tx_response.effects!, aliceClient);

    console.log(`Alice successfully created Identity ${identity.id()}! Thanks for the gas Bob!`);
}

async function bobSponsorFn(tx_data: TransactionDataBuilder, client: IdentityClient): Promise<string> {
    const coin = await client.iotaClient().getCoins({ owner: client.senderAddress(), coinType: "0x2::iota::IOTA" })
        .then(res => res.data[0]);
    tx_data.gasData.owner = client.senderAddress();
    tx_data.gasData.price = 1000;
    tx_data.gasData.budget = 50000000;
    tx_data.gasData.payment = [{ version: coin.version, objectId: coin.coinObjectId, digest: coin.digest }];

    return await client.signer().sign(tx_data.build());
}
