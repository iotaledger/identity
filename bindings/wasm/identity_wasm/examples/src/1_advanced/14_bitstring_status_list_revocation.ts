// Copyright 2020-2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
    BitstringStatusListCredential,
    BitstringStatusListEntry,
    CredentialV2,
    EdDSAJwsVerifier,
    FailFast,
    IrlResolver,
    JwsSignatureOptions,
    JwtCredentialValidationOptions,
    JwtCredentialValidator,
    JwtVcV2,
    Status,
    StatusCheck,
    StatusV2,
} from "@iota/identity-wasm/node";
import { IotaClient } from "@iota/iota-sdk/client";
import { OnChainNotarization, State } from "@iota/notarization/node";
import { createDocumentForNetwork, getFundedClient, getMemstorage, getNotarizationClient, NETWORK_URL } from "../util";

export async function bitstringStatusListRevocation() {
    // Create new client to connect to IOTA network.
    const iotaClient = new IotaClient({ url: NETWORK_URL });
    const network = await iotaClient.getChainIdentifier();

    // Create an identity for the issuer with one verification method `key-1`, and publish DID document for it.
    const issuerStorage = getMemstorage();
    const issuerClient = await getFundedClient(issuerStorage);
    const [unpublishedIssuerDocument, issuerFragment] = await createDocumentForNetwork(issuerStorage, network);
    const { output: issuerIdentity } = await issuerClient
        .createIdentity(unpublishedIssuerDocument)
        .finish()
        .buildAndExecute(issuerClient);
    let issuerDocument = issuerIdentity.didDocument();

    // create holder account, create identity, and publish DID document for it.
    const aliceStorage = getMemstorage();
    const aliceClient = await getFundedClient(aliceStorage);
    const [unpublishedAliceDocument, aliceFragment] = await createDocumentForNetwork(aliceStorage, network);
    const { output: aliceIdentity } = await aliceClient
        .createIdentity(unpublishedAliceDocument)
        .finish()
        .buildAndExecute(aliceClient);
    const aliceDocument = aliceIdentity.didDocument();

    // Issuer creates a BitstringStatusListCredential to revoke the VCs she issues.
    let statusListCredential = new BitstringStatusListCredential({
        issuer: issuerDocument.id().toString(),
        statusPurposes: ["revocation"],
    });
    console.log(`New BitstringStatusListCredential: ${JSON.stringify(statusListCredential, null, 2)}`);
    // Issuer signs the BitstringStatusListCredential and notarizes it on-chain.
    let statusListCredentialJwt = await issuerDocument.createCredentialV2Jwt(
        issuerStorage,
        issuerFragment,
        statusListCredential.toCredential(),
        new JwsSignatureOptions(),
    );
    const notarizationClient = await getNotarizationClient(issuerClient.signer());
    let notarizedBitstringStatusListCredential: OnChainNotarization = await notarizationClient.createDynamic()
        .withStringState(statusListCredentialJwt.toString())
        .finish()
        .buildAndExecute(notarizationClient)
        .then(res => res.output);
    let credentialIrl = notarizedBitstringStatusListCredential.iotaResourceLocatorBuilder(notarizationClient.network())
        .data();
    console.log(`BitstringStatusListCredential has been notarized at: ${credentialIrl}`);

    // Issuer now creates a credential for Alice, using BitstringStatusList to revoke it at any point in time.
    const entry = new BitstringStatusListEntry({
        statusListCredential: credentialIrl,
        statusListIndex: 42,
        statusPurpose: "revocation",
    });
    const unsignedVc = new CredentialV2({
        id: "https://example.edu/credentials/3732",
        type: "UniversityDegreeCredential",
        issuer: issuerDocument.id(),
        credentialSubject: {
            id: aliceDocument.id(),
            name: "Alice",
            degreeName: "Bachelor of Science and Arts",
            degreeType: "BachelorDegree",
            GPA: "4.0",
        },
        credentialStatus: entry as unknown as StatusV2,
    });
    const aliceVcJwt = await issuerDocument.createCredentialV2Jwt(
        issuerStorage,
        issuerFragment,
        unsignedVc,
        new JwsSignatureOptions(),
    );

    // Validate the credential using the issuer's DID Document.
    let jwtCredentialValidator = new JwtCredentialValidator(new EdDSAJwsVerifier());
    jwtCredentialValidator.validateV2(
        aliceVcJwt,
        issuerDocument,
        new JwtCredentialValidationOptions({ status: StatusCheck.SkipAll }),
        FailFast.FirstError,
    );
    let status = statusListCredential.getEntryStatus(entry.statusListIndex, entry.statusPurpose);
    console.assert(status.valid, "ooops credential is actually invalid");
    console.log("Credential is valid!");

    console.log("Issuer revokes credential...");
    statusListCredential.setEntryStatus(entry, true);
    statusListCredentialJwt = await issuerDocument.createCredentialV2Jwt(
        issuerStorage,
        issuerFragment,
        statusListCredential.toCredential(),
        new JwsSignatureOptions(),
    );
    await notarizationClient
        .updateState(State.fromString(statusListCredentialJwt.toString()), notarizedBitstringStatusListCredential.id)
        .buildAndExecute(notarizationClient);

    // Now if a verifier resolves the status list and attempt to validate Alice's credential against
    // it, the validation will fail as the credential has been revoked.
    const irlResolver = new IrlResolver({ customNetworks: [{ chainId: network, endpoint: NETWORK_URL }] });
    const resolvedStatusListJwt = await irlResolver.resolve(credentialIrl).then(value => new JwtVcV2(value));
    // First the verifier validates the status list credential itself.
    const decodedStatusListCredential = jwtCredentialValidator.validateV2(
        resolvedStatusListJwt,
        issuerDocument,
        new JwtCredentialValidationOptions({ status: StatusCheck.SkipAll }), // We'll check it manually.
        FailFast.FirstError,
    ).intoCredential();
    statusListCredential = BitstringStatusListCredential.fromCredential(decodedStatusListCredential);
    // Now we verify the status of Alice's credential against it.
    status = statusListCredential.getEntryStatus(entry.statusListIndex, entry.statusPurpose);
    console.assert(!status.valid, "ooops credential is actually valid");

    console.log("Alice credential has been revoked!");
}
