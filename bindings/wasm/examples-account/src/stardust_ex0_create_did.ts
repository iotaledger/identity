// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
    StardustDocument,
    StardustIdentityClient,
} from '../../node';

import {IAliasOutput, SingleNodeClient, IndexerPluginClient, IRent, INodeInfo} from '@iota/iota.js';


import {
    Bech32Helper,
    Ed25519Address,
    Ed25519Seed,
    ED25519_ADDRESS_TYPE,
    IUTXOInput,
    IOutputsResponse,
    ITransactionEssence,
    serializeOutput,
    ISignatureUnlock,
    SIGNATURE_UNLOCK_TYPE,
    ED25519_SIGNATURE_TYPE,
    TRANSACTION_ESSENCE_TYPE,
    ITransactionPayload,
    TRANSACTION_PAYLOAD_TYPE,
    IBlock,
    DEFAULT_PROTOCOL_VERSION,
    TransactionHelper,
    AddressTypes
} from "@iota/iota.js";
import { Converter, WriteStream } from "@iota/util.js";
// import { NeonPowProvider } from "@iota/pow-neon.js";
import { Bip32Path, Blake2b, Ed25519 } from "@iota/crypto.js";
import { randomBytes } from "node:crypto";
import fetch from "node-fetch";

process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0";
const EXPLORER = "https://explorer.alphanet.iotaledger.net/alphanet";
const API_ENDPOINT = "https://api.alphanet.iotaledger.net/";
const FAUCET = "https://faucet.alphanet.iotaledger.net/api/enqueue";

// In this example we set up a hot wallet, fund it with tokens from the faucet and let it mint an NFT to our address.
export async function run() {
    // LocalPoW is extremely slow and only runs in 1 thread...
    // const client = new SingleNodeClient(API_ENDPOINT, {powProvider: new LocalPowProvider()});
    // Neon localPoW is blazingly fast, but you need rust toolchain to build
    const client = new SingleNodeClient(API_ENDPOINT); // const client = new SingleNodeClient(API_ENDPOINT, {powProvider: new NeonPowProvider()});
    const didClient = new StardustIdentityClient(client);
    const protocolInfo = await client.protocolInfo();
    const network: string = protocolInfo.bech32Hrp;

    // Now it's time to set up an account for this demo which we are going to use to mint nft and send it to the target address.
    console.log("Sender Address:");
    const [walletAddressHex, walletAddressBech32, walletKeyPair] = await setUpHotWallet(network, true);

    // Fetch outputId with funds to be used as input
    const indexerPluginClient = new IndexerPluginClient(client);

    const document = new StardustDocument(network);
    const aliasOutput: IAliasOutput = await didClient.newDidOutput(ED25519_ADDRESS_TYPE, walletAddressHex, document);
    console.log("AliasOutput", JSON.stringify(aliasOutput, null, 4));

    // Indexer returns outputIds of matching outputs. We are only interested in the first one coming from the faucet.
    const outputId = await fetchAndWaitForBasicOutput(walletAddressBech32, indexerPluginClient);
    console.log("OutputId: ", outputId);

    // Fetch the output itself
    const resp = await client.output(outputId);
    const consumedOutput = resp.output;
    console.log("To be consumed output: ", consumedOutput);

    // Prepare inputs to the tx
    const input:IUTXOInput = TransactionHelper.inputFromOutputId(outputId);
    console.log("Input: ", input);

    // // Calculate required storage
    // const rentStructure: IRent = await didClient.getRentStructure();
    // let requiredStorageDeposit = TransactionHelper.getStorageDeposit(aliasOutput, rentStructure);
    // console.log("Required Storage Deposit of the NFT output: ", requiredStorageDeposit);
    //
    // // Prepare Tx essence
    // // We are going to mint the NFT to an address the user defined in the beginning
    // // We could put only requiredStorageDepoist into the nft output, but hey, we have free tokens so top it up with all we have.
    // // nftOutput.amount = requiredStorageDeposit.toString()
    // aliasOutput.amount = consumedOutput.amount;
    //
    // InputsCommitment calculation
    const inputsCommitmentHasher = new Blake2b(Blake2b.SIZE_256); // blake2b hasher
    // Step 1: sort inputs lexicographically basedon serialized bytes
    //       -> we have only 1 input, no need to
    // Step 2: Loop over list of inputs (the actual output objects they reference).
    //   SubStep 2a: Calculate hash of serialized output
    const outputHasher = new Blake2b(Blake2b.SIZE_256);
    const w = new WriteStream();
    serializeOutput(w, consumedOutput);
    const consumedOutputBytes = w.finalBytes();
    outputHasher.update(consumedOutputBytes);
    const outputHash = outputHasher.final();

    // SubStep 2b: add each output hash to buffer
    inputsCommitmentHasher.update(outputHash);

    // Step 3: Calculate Sum from buffer
    const inputsCommitment = Converter.bytesToHex(inputsCommitmentHasher.final(), true);

    // Creating Transaction Essence
    const txEssence: ITransactionEssence = {
        type: TRANSACTION_ESSENCE_TYPE,
        networkId: protocolInfo.networkId,
        inputs: [input],
        outputs: [aliasOutput],
        inputsCommitment:  inputsCommitment,
    };

    // Calculating Transaction Essence Hash (to be signed in signature unlocks)
    const essenceHash = TransactionHelper.getTransactionEssenceHash(txEssence);

    // We unlock only one output, so there will be one unlock with signature
    let unlock: ISignatureUnlock = {
        type: SIGNATURE_UNLOCK_TYPE,
        signature: {
            type: ED25519_SIGNATURE_TYPE,
            publicKey: Converter.bytesToHex(walletKeyPair.publicKey, true),
            signature: Converter.bytesToHex(Ed25519.sign(walletKeyPair.privateKey, essenceHash), true)
        }
    };

    // Constructing Transaction Payload
    const txPayload : ITransactionPayload = {
        type: TRANSACTION_PAYLOAD_TYPE,
        essence: txEssence,
        unlocks: [unlock]
    };

    // Getting parents for the block
    let parentsResponse = await client.tips();
    let parents = parentsResponse.tips;

    // Constructing block that holds the transaction
    let block: IBlock = {
        protocolVersion: DEFAULT_PROTOCOL_VERSION,
        parents: parents,
        payload: txPayload,
        nonce: "0"
    };

    // LocalPoW is so slow and simpe threaded that it may happen that by the time you push the msg to the node,
    // it is alsready below max depth (parents), or will need to be promoted...
    // alternatively, connect to a node with remotePoW enabled
    const blockId = await client.blockSubmit(block);
    // TODO: retryUntilIncluded...

    console.log("Submitted blockId is: ", blockId);
    console.log("Check out the transaction at ", EXPLORER+"/block/"+blockId);
}

run()
    .then(() => console.log("Done"))
    .catch(err => console.error(err));

async function setUpHotWallet(hrp: string, fund: boolean = false) {
    // Generate a random seed
    const walletEd25519Seed = new Ed25519Seed(randomBytes(32));

    // For Shimmer we use Coin Type 4219
    const path = new Bip32Path("m/44'/4219'/0'/0'/0'");

    // Construct wallet from seed
    const walletSeed = walletEd25519Seed.generateSeedFromPath(path);
    let walletKeyPair = walletSeed.keyPair();

    console.log("\tSeed", Converter.bytesToHex(walletSeed.toBytes()));

    // Get the address for the path seed which is actually the Blake2b.sum256 of the public key
    // display it in both Ed25519 and Bech 32 format
    const walletEd25519Address = new Ed25519Address(walletKeyPair.publicKey);
    const walletAddress = walletEd25519Address.toAddress();
    const walletAddressHex = Converter.bytesToHex(walletAddress, true);

    let walletAddressBech32 = Bech32Helper.toBech32(ED25519_ADDRESS_TYPE, walletAddress, hrp);
    console.log("\tAddress Ed25519", walletAddressHex);
    console.log("\tAddress Bech32", walletAddressBech32);

    // We also top up the address by asking funds from the faucet.
    if (fund) {
        await requestFundsFromFaucet(walletAddressBech32);
    }

    return [walletAddressHex, walletAddressBech32, walletKeyPair] as const;
}

// Requests frunds from the faucet via API
async function requestFundsFromFaucet(addressBech32: string) {
    const requestObj = JSON.stringify({ address: addressBech32 });
    let errorMessage, data;
    try {
        const response = await fetch(FAUCET, {
            method: "POST",
            headers: {
                Accept: "application/json",
                "Content-Type": "application/json",
            },
            body: requestObj,
        });
        if (response.status === 202) {
            errorMessage = "OK";
        } else if (response.status === 429) {
            errorMessage = "too many requests, please try again later.";
        } else {
            data = await response.json();
            // @ts-ignore
            errorMessage = data.error.message;
        }
    } catch (error) {
        errorMessage = error;
    }

    if (errorMessage != "OK") {
        throw new Error(`failed to get funds from faucet: ${errorMessage}`);
    }
}

async function fetchAndWaitForBasicOutput(addressBech32: string, client: IndexerPluginClient): Promise<string> {
    let outputsResponse: IOutputsResponse = { ledgerIndex: 0, cursor: "", pageSize: "", items: [] };
    let maxTries = 10;
    let tries = 0;
    while (outputsResponse.items.length == 0) {
        if (tries > maxTries){ break; }
        tries++;
        console.log("\tTry #",tries,": fetching basic output for address ", addressBech32);
        outputsResponse = await client.outputs({
            addressBech32: addressBech32,
            hasStorageReturnCondition: false,
            hasExpirationCondition: false,
            hasTimelockCondition: false,
            hasNativeTokens: false,
        });
        if (outputsResponse.items.length == 0) {
            console.log("\tDidn't find any, retrying soon...");
            await new Promise(f => setTimeout(f, 1000));
        }
    }
    if (tries > maxTries) {
        throw new Error("Didn't find any outputs for address");
    }
    return outputsResponse.items[0];
}
