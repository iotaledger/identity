import { TransactionBuilder } from "@iota/identity-wasm/node";
import { IotaClient } from "@iota/iota-sdk/client";
import { Argument } from "@iota/iota-sdk/transactions";
import { createDocumentForNetwork, getFundedClient, getMemstorage, NETWORK_URL, SendZeroCoinTx } from "../util";

async function testIdentityBorrow(): Promise<void> {
    // create new client to connect to IOTA network
    const iotaClient = new IotaClient({ url: NETWORK_URL });
    const network = await iotaClient.getChainIdentifier();

    // create new client that offers identity related functions
    const storage = getMemstorage();
    const identityClient = await getFundedClient(storage);

    // create new unpublished document
    const [unpublished] = await createDocumentForNetwork(storage, network);

    const { output: identity } = await identityClient
        .createIdentity(unpublished)
        .finish()
        .buildAndExecute(identityClient);
    // Get this address's auth token over identity.
    const controllerToken = await identity.getControllerToken(identityClient);

    // Give identity an empty coin.
    const { output: coinId } = await new TransactionBuilder(new SendZeroCoinTx(identity.id()))
        .buildAndExecute(identityClient);

    console.log(`identity ${identity.id()} now owns the coin ${coinId}`);

    // Borrow identity's coin in a transaction. This one doesn't do anything meaningful
    // but demonstrate that borrowing works.
    const { output } = await identity
        .borrowAssets(
            controllerToken!,
            [coinId],
            (ptb, objs) => {
                // Let's get the tx's argument corresponding to the coin we borrowed.
                const [coinArg, _] = objs.get(coinId) ?? [undefined, undefined];
                // Let's call a function that uses it as its argument.
                ptb.commands.push({
                    $kind: "MoveCall",
                    MoveCall: {
                        package: "0x2",
                        module: "coin",
                        function: "value",
                        typeArguments: ["0x2::iota::IOTA"],
                        arguments: [coinArg!],
                    },
                });
            },
        )
        .buildAndExecute(identityClient);

    if (output != undefined) {
        throw new Error("Transaction failed!");
    }
}

// Only verifies that no uncaught exceptions are thrown, including syntax errors etc.
describe("Test node examples", function() {
    it("Identity Borrow Asset Proposal", async () => {
        await testIdentityBorrow();
    });
});
