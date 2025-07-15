// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
    Credential,
    FailFast,
    IdentityClientReadOnly,
    IJwsVerifier,
    IotaDocument,
    Jwk,
    JwsAlgorithm,
    JwsSignatureOptions,
    JwtCredentialValidationOptions,
    JwtCredentialValidator,
    Resolver,
    RevocationBitmap,
    Service,
    VerificationMethod,
    verifyEd25519,
} from "@iota/identity-wasm/node";
import { IotaClient } from "@iota/iota-sdk/client";
import {
    createDocumentForNetwork,
    getFundedClient,
    getMemstorage,
    IOTA_IDENTITY_PKG_ID,
    NETWORK_URL,
    TEST_GAS_BUDGET,
} from "../util";

/**
 * This example shows how to revoke a verifiable credential.
 * It demonstrates two methods for revocation. The first uses a revocation bitmap of type `RevocationBitmap2022`,
 * while the second method simply removes the verification method (public key) that signed the credential
 * from the DID Document of the issuer.
 *
 * Note: make sure `API_ENDPOINT` and `FAUCET_ENDPOINT` are set to the correct network endpoints.
 */
export async function revokeVC() {
    // ===========================================================================
    // Create a Verifiable Credential.
    // ===========================================================================

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

    // Create a new empty revocation bitmap. No credential is revoked yet.
    const revocationBitmap = new RevocationBitmap();

    // Add the revocation bitmap to the DID Document of the issuer as a service.
    const serviceId = issuerDocument.id().join("#my-revocation-service");
    const service: Service = revocationBitmap.toService(serviceId);
    issuerDocument.insertService(service);

    const issuerIdentityToken = await issuerIdentity.getControllerToken(issuerClient);

    // Publish the updated document.
    await issuerIdentity
        .updateDidDocument(issuerDocument, issuerIdentityToken!)
        .withGasBudget(TEST_GAS_BUDGET)
        .buildAndExecute(issuerClient);

    // Create a credential subject indicating the degree earned by Alice, linked to their DID.
    const subject = {
        id: aliceDocument.id(),
        name: "Alice",
        degreeName: "Bachelor of Science and Arts",
        degreeType: "BachelorDegree",
        GPA: "4.0",
    };

    // Create an unsigned `UniversityDegree` credential for Alice.
    // The issuer also chooses a unique `RevocationBitmap` index to be able to revoke it later.
    const CREDENTIAL_INDEX = 5;
    const unsignedVc = new Credential({
        id: "https://example.edu/credentials/3732",
        type: "UniversityDegreeCredential",
        credentialStatus: {
            id: issuerDocument.id() + "#my-revocation-service",
            type: RevocationBitmap.type(),
            revocationBitmapIndex: CREDENTIAL_INDEX.toString(),
        },
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

    // Validate the credential using the issuer's DID Document.
    let jwtCredentialValidator = new JwtCredentialValidator(new Ed25519JwsVerifier());
    jwtCredentialValidator.validate(
        credentialJwt,
        issuerDocument,
        new JwtCredentialValidationOptions(),
        FailFast.FirstError,
    );

    // ===========================================================================
    // Revocation of the Verifiable Credential.
    // ===========================================================================

    // Update the RevocationBitmap service in the issuer's DID Document.
    // This revokes the credential's unique index.
    issuerDocument.revokeCredentials("my-revocation-service", CREDENTIAL_INDEX);

    // Publish the changes.
    await issuerIdentity
        .updateDidDocument(issuerDocument, issuerIdentityToken!)
        .withGasBudget(TEST_GAS_BUDGET)
        .buildAndExecute(issuerClient);

    // Credential verification now fails.
    try {
        jwtCredentialValidator.validate(
            credentialJwt,
            issuerDocument,
            new JwtCredentialValidationOptions(),
            FailFast.FirstError,
        );
        console.log("Revocation Failed!");
    } catch (e) {
        console.log(`Error during validation: ${e}`);
    }

    // ===========================================================================
    // Alternative revocation of the Verifiable Credential.
    // ===========================================================================

    // By removing the verification method, that signed the credential, from the issuer's DID document,
    // we effectively revoke the credential, as it will no longer be possible to validate the signature.
    let originalMethod = issuerDocument.resolveMethod(
        `#${issuerFragment}`,
    ) as VerificationMethod;
    await issuerDocument.purgeMethod(issuerStorage, originalMethod.id());

    // Publish the changes.
    await issuerIdentity
        .updateDidDocument(issuerDocument, issuerIdentityToken!)
        .withGasBudget(TEST_GAS_BUDGET)
        .buildAndExecute(issuerClient);

    issuerDocument = issuerIdentity.didDocument();

    // We expect the verifiable credential to be revoked.
    const resolver = new Resolver<IotaDocument>({
        client: await IdentityClientReadOnly.createWithPkgId(iotaClient, IOTA_IDENTITY_PKG_ID),
    });
    try {
        // Resolve the issuer's updated DID Document to ensure the key was revoked successfully.
        const resolvedIssuerDoc = await resolver.resolve(
            issuerDocument.id().toString(),
        );
        jwtCredentialValidator.validate(
            credentialJwt,
            resolvedIssuerDoc,
            new JwtCredentialValidationOptions(),
            FailFast.FirstError,
        );

        // `jwtCredentialValidator.validate` will throw an error, hence this will not be reached.
        console.log("Revocation failed!");
    } catch (e) {
        console.log(`Error during validation: ${e}`);
        console.log(`Credential successfully revoked!`);
    }
}

// A custom JWS Verifier capabale of verifying EdDSA signatures with curve Ed25519.
class Ed25519JwsVerifier implements IJwsVerifier {
    verify(alg: JwsAlgorithm, signingInput: Uint8Array, decodedSignature: Uint8Array, publicKey: Jwk) {
        switch (alg) {
            case JwsAlgorithm.EdDSA:
                // This verifies that the curve is Ed25519 so we don't need to check ourselves.
                return verifyEd25519(alg, signingInput, decodedSignature, publicKey);
            default:
                throw new Error(`unsupported jws algorithm ${alg}`);
        }
    }
}
