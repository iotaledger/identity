// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
    Credential,
    EdDSAJwsVerifier,
    FailFast,
    JwsSignatureOptions,
    JwtCredentialValidationOptions,
    JwtCredentialValidator,
} from "@iota/identity-wasm/node";
import { IotaClient } from "@iota/iota-sdk/client";
import { createDocumentForNetwork, getFundedClient, getMemstorage, NETWORK_URL } from "../util";

/**
 * This example shows how to create a Verifiable Credential and validate it.
 * In this example, Alice takes the role of the subject, while we also have an issuer.
 * The issuer signs a UniversityDegreeCredential type verifiable credential with Alice's name and DID.
 * This Verifiable Credential can be verified by anyone, allowing Alice to take control of it and share it with whomever they please.
 */
export async function createVC() {
    // create new client to connect to IOTA network
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
    const issuerDocument = issuerIdentity.didDocument();

    // Create an identity for the holder, and publish DID document for it, in this case also the subject.
    const aliceStorage = getMemstorage();
    const aliceClient = await getFundedClient(aliceStorage);
    const [unpublishedAliceDocument] = await createDocumentForNetwork(aliceStorage, network);
    const { output: aliceIdentity } = await aliceClient
        .createIdentity(unpublishedAliceDocument)
        .finish()
        .buildAndExecute(aliceClient);
    const aliceDocument = aliceIdentity.didDocument();

    // Create a credential subject indicating the degree earned by Alice, linked to their DID.
    const subject = {
        id: aliceDocument.id(),
        name: "Alice",
        degreeName: "Bachelor of Science and Arts",
        degreeType: "BachelorDegree",
        GPA: "4.0",
    };

    // Create an unsigned `UniversityDegree` credential for Alice
    const unsignedVc = new Credential({
        id: "https://example.edu/credentials/3732",
        type: "UniversityDegreeCredential",
        issuer: issuerDocument.id(),
        credentialSubject: subject,
    });

    // Create signed JWT credential.
    const credentialJwt = await issuerDocument.createCredentialJwt(
        issuerStorage,
        issuerFragment,
        unsignedVc,
        new JwsSignatureOptions(),
    );
    console.log(`Credential JWT > ${credentialJwt.toString()}`);

    // Before sending this credential to the holder the issuer wants to validate that some properties
    // of the credential satisfy their expectations.

    // Validate the credential's signature, the credential's semantic structure,
    // check that the issuance date is not in the future and that the expiration date is not in the past.
    // Note that the validation returns an object containing the decoded credential.
    const decoded_credential = new JwtCredentialValidator(new EdDSAJwsVerifier()).validate(
        credentialJwt,
        issuerDocument,
        new JwtCredentialValidationOptions(),
        FailFast.FirstError,
    );

    // Since `validate` did not throw any errors we know that the credential was successfully validated.
    console.log(`VC successfully validated`);

    // The issuer is now sure that the credential they are about to issue satisfies their expectations.
    // Note that the credential is NOT published to the IOTA Tangle. It is sent and stored off-chain.
    console.log(`Issued credential: ${JSON.stringify(decoded_credential.intoCredential(), null, 2)}`);
}
