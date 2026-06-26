// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
    Credential,
    EdDSAJwsVerifier,
    FailFast,
    JwsSignatureOptions,
    JwtCredentialValidationOptions,
    JwtCredentialValidator,
    StatusCheck,
    StatusList2021,
    StatusList2021Credential,
    StatusList2021CredentialBuilder,
    StatusList2021Entry,
    StatusPurpose,
} from "@iota/identity-wasm/node";
import { IotaClient } from "@iota/iota-sdk/client";
import { createDocumentForNetwork, getFundedClient, getMemstorage, NETWORK_URL } from "../util";

export async function statusList2021() {
    // ===========================================================================
    // Create a Verifiable Credential.
    // ===========================================================================

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

    // Create a new empty status list. No credentials have been revoked yet.
    const statusList = new StatusList2021();

    // Create a status list credential so that the status list can be stored anywhere.
    // The issuer makes this credential available on `http://example.com/credential/status`.
    // For the purposes of this example, the credential will be used directly without fetching.
    const statusListCredential = new StatusList2021CredentialBuilder(statusList)
        .purpose(StatusPurpose.Revocation)
        .subjectId("http://example.com/credential/status")
        .issuer(issuerDocument.id().toString())
        .build();
    const statusListCredentialJSON = statusListCredential.toJSON();
    console.log("Status list credential > " + statusListCredential);

    // Create a credential subject indicating the degree earned by Alice, linked to their DID.
    const subject = {
        id: aliceDocument.id(),
        name: "Alice",
        degreeName: "Bachelor of Science and Arts",
        degreeType: "BachelorDegree",
        GPA: "4.0",
    };

    // Create an unsigned `UniversityDegree` credential for Alice.
    // The issuer also chooses a unique `StatusList2021` index to be able to revoke it later.
    const CREDENTIAL_INDEX = 5;
    const status = new StatusList2021Entry(statusListCredential.id(), statusListCredential.purpose(), CREDENTIAL_INDEX)
        .toStatus();
    const credential = new Credential({
        id: "https://example.edu/credentials/3732",
        type: "UniversityDegreeCredential",
        credentialStatus: status,
        issuer: issuerDocument.id(),
        credentialSubject: subject,
    });

    // Create signed JWT credential.
    const credentialJwt = await issuerDocument.createCredentialJwt(
        issuerStorage,
        issuerFragment,
        credential,
        new JwsSignatureOptions(),
    );
    console.log(`Credential JWT > ${credentialJwt.toString()}`);

    // Validate the credential using the issuer's DID Document.
    const validationOptions = new JwtCredentialValidationOptions({ status: StatusCheck.SkipUnsupported });
    // The validator has no way of retrieving the status list to check for the
    // revocation of the credential. Let's skip that pass and perform the operation manually.
    let jwtCredentialValidator = new JwtCredentialValidator(new EdDSAJwsVerifier());

    try {
        jwtCredentialValidator.validate(
            credentialJwt,
            issuerDocument,
            validationOptions,
            FailFast.FirstError,
        );
        // Check manually for revocation
        JwtCredentialValidator.checkStatusWithStatusList2021(
            credential,
            statusListCredential,
            StatusCheck.Strict,
        );
    } catch (e) {
        // This line shouldn't be called as the credential is valid and unrevoked
        console.log("Something went wrong: " + e);
    }

    // ===========================================================================
    // Revocation of the Verifiable Credential.
    // ===========================================================================

    // At a later time, the issuer university found out that Alice cheated in her final exam.
    // The issuer will revoke Alice's credential.

    // The issuer retrieves the status list credential.
    const refetchedStatusListCredential = new StatusList2021Credential(new Credential(statusListCredentialJSON as any));

    // Update the status list credential.
    // This revokes the credential's unique index.
    refetchedStatusListCredential.setCredentialStatus(credential, CREDENTIAL_INDEX, true);

    // Credential verification now fails.
    try {
        jwtCredentialValidator.validate(
            credentialJwt,
            issuerDocument,
            validationOptions,
            FailFast.FirstError,
        );
        /// Since the credential has been revoked, this validation step will throw an error.
        JwtCredentialValidator.checkStatusWithStatusList2021(
            credential,
            refetchedStatusListCredential,
            StatusCheck.Strict,
        );
        // In case the revocation failed for some reason we will hit this point
        console.log("Revocation Failed!");
    } catch (e) {
        /// The credential has been revoked.
        console.log("The credential has been successfully revoked.");
    }
}
