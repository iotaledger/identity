// Copyright 2024 Fondazione Links
// SPDX-License-Identifier: Apache-2.0

import {
    CoreDID,
    Credential,
    Duration,
    FailFast,
    IotaDocument,
    IotaIdentityClient,
    JwkPqMemStore,
    JwsAlgorithm,
    JwsSignatureOptions,
    JwsVerificationOptions,
    Jwt,
    PQJwsVerifier,
    JwtCredentialValidationOptions,
    JwtCredentialValidator,
    JwtPresentationOptions,
    JwtPresentationValidationOptions,
    JwtPresentationValidator,
    KeyIdMemStore,
    MethodScope,
    Presentation,
    Resolver,
    Storage,
    SubjectHolderRelationship,
    Timestamp,
} from "@iota/identity-wasm/node";
import { Address, AliasOutput, Client, MnemonicSecretManager, SecretManager, SecretManagerType, Utils } from "@iota/sdk-wasm/node";
import { API_ENDPOINT, ensureAddressHasFunds } from "../util";

async function createPQDid(client: Client, secretManager: SecretManagerType, storage: Storage): Promise<{
    address: Address;
    document: IotaDocument;
    fragment: string;
}> {
    const didClient = new IotaIdentityClient(client);
    const networkHrp: string = await didClient.getNetworkHrp();

    const secretManagerInstance = new SecretManager(secretManager);
    const walletAddressBech32 = (await secretManagerInstance.generateEd25519Addresses({
        accountIndex: 0,
        range: {
            start: 0,
            end: 1,
        },
        bech32Hrp: networkHrp,
    }))[0];

    console.log("Wallet address Bech32:", walletAddressBech32);

    await ensureAddressHasFunds(client, walletAddressBech32);

    const address: Address = Utils.parseBech32Address(walletAddressBech32);

    // Create a new DID document with a placeholder DID.
    // The DID will be derived from the Alias Id of the Alias Output after publishing.
    const document = new IotaDocument(networkHrp);
    
    // Create a new method with PQ algorithm.
    const fragment = await document.generateMethodPQC(
        storage,
        JwkPqMemStore.mldsaKeyType(),
        JwsAlgorithm.MLDSA44,
        "#0",
        MethodScope.VerificationMethod(),
    );

    // Construct an Alias Output containing the DID document, with the wallet address
    // set as both the state controller and governor.
    const aliasOutput: AliasOutput = await didClient.newDidOutput(address, document);

    // Publish the Alias Output and get the published DID document.
    const published = await didClient.publishDidOutput(secretManager, aliasOutput);

    return { address, document: published, fragment };
}

/**
 * This example shows how to create a PQ Verifiable Presentation and validate it
 */
export async function pq() {
    // ===========================================================================
    // Step 1: Create identities for the issuer and the holder.
    // ===========================================================================

    const client = new Client({
        primaryNode: API_ENDPOINT,
        localPow: true,
    });
    const didClient = new IotaIdentityClient(client);

    // Creates a new wallet and identity (see "0_create_did" example).
    const issuerSecretManager: MnemonicSecretManager = {
        mnemonic: Utils.generateMnemonic(),
    };
    const issuerStorage: Storage = new Storage(
        new JwkPqMemStore(),
        new KeyIdMemStore(),
    );
    let { document: issuerDocument, fragment: issuerFragment } = await createPQDid(
        client,
        issuerSecretManager,
        issuerStorage,
    );

    // Create an identity for the holder, in this case also the subject.
    const aliceSecretManager: MnemonicSecretManager = {
        mnemonic: Utils.generateMnemonic(),
    };
    const aliceStorage: Storage = new Storage(
        new JwkPqMemStore(),
        new KeyIdMemStore(),
    );
    let { document: aliceDocument, fragment: aliceFragment } = await createPQDid(
        client,
        aliceSecretManager,
        aliceStorage,
    );
 
    // ===========================================================================
    // Step 2: Issuer creates and signs a Verifiable Credential.
    // ===========================================================================

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
    
    // Create a Credential JWT with the issuer's PQ verification method.
    const credentialJwt = await issuerDocument.createCredentialJwtPqc(
        issuerStorage,
        issuerFragment,
        unsignedVc,
        new JwsSignatureOptions(),
    );

    const res = new JwtCredentialValidator(new PQJwsVerifier()).validate(
        credentialJwt,
        issuerDocument,
        new JwtCredentialValidationOptions(),
        FailFast.FirstError,
    );
    console.log("credentialjwt validation", res.intoCredential());

    // ===========================================================================
    // Step 3: Issuer sends the Verifiable Credential to the holder.
    // ===========================================================================

    // The credential is then serialized to JSON and transmitted to the holder in a secure manner.
    // Note that the credential is NOT published to the IOTA Tangle. It is sent and stored off-chain.
    console.log(`Sending credential (as JWT) to the holder`, unsignedVc.toJSON());

    // ===========================================================================
    // Step 4: Verifier sends the holder a challenge and requests a signed Verifiable Presentation.
    // ===========================================================================

    // A unique random challenge generated by the requester per presentation can mitigate replay attacks.
    const nonce = "475a7984-1bb5-4c4c-a56f-822bccd46440";

    // The verifier and holder also agree that the signature should have an expiry date
    // 10 minutes from now.
    const expires = Timestamp.nowUTC().checkedAdd(Duration.minutes(10));

    // ===========================================================================
    // Step 5: Holder creates a verifiable presentation from the issued credential for the verifier to validate.
    // ===========================================================================

    // Create a Verifiable Presentation from the Credential
    const unsignedVp = new Presentation({
        holder: aliceDocument.id(),
        verifiableCredential: [credentialJwt],
    });

    // Create a PQ JWT verifiable presentation using the holder's verification method
    // and include the requested challenge and expiry timestamp.
    const presentationJwt = await aliceDocument.createPresentationJwtPqc(
        aliceStorage,
        aliceFragment,
        unsignedVp,
        new JwsSignatureOptions({ nonce }),
        new JwtPresentationOptions({ expirationDate: expires }),
    );

    // ===========================================================================
    // Step 6: Holder sends a verifiable presentation to the verifier.
    // ===========================================================================
    console.log(
        `Sending presentation (as JWT) to the verifier`,
        unsignedVp.toJSON(),
    );

    // ===========================================================================
    // Step 7: Verifier receives the Verifiable Presentation and verifies it.
    // ===========================================================================

    // The verifier wants the following requirements to be satisfied:
    // - JWT verification of the presentation (including checking the requested challenge to mitigate replay attacks)
    // - JWT verification of the credentials.
    // - The presentation holder must always be the subject, regardless of the presence of the nonTransferable property
    // - The issuance date must not be in the future.

    const jwtPresentationValidationOptions = new JwtPresentationValidationOptions(
        {
            presentationVerifierOptions: new JwsVerificationOptions({ nonce }),
        },
    );

    const resolver = new Resolver({
        client: didClient,
    });
    // Resolve the presentation holder.
    const presentationHolderDID: CoreDID = JwtPresentationValidator.extractHolder(presentationJwt);
    const resolvedHolder = await resolver.resolve(
        presentationHolderDID.toString(),
    );

    // Validate presentation. Note that this doesn't validate the included credentials.
    let decodedPresentation = new JwtPresentationValidator(new PQJwsVerifier()).validate(
        presentationJwt,
        resolvedHolder,
        jwtPresentationValidationOptions,
    );

    // Validate the credentials in the presentation.
    let credentialValidator = new JwtCredentialValidator(new PQJwsVerifier());
    let validationOptions = new JwtCredentialValidationOptions({
        subjectHolderRelationship: [
            presentationHolderDID.toString(),
            SubjectHolderRelationship.AlwaysSubject,
        ],
    });

    let jwtCredentials: Jwt[] = decodedPresentation
        .presentation()
        .verifiableCredential()
        .map((credential) => {
            const jwt = credential.tryIntoJwt();
            if (!jwt) {
                throw new Error("expected a JWT credential");
            } else {
                return jwt;
            }
        });

    // Concurrently resolve the issuers' documents.
    let issuers: string[] = [];
    for (let jwtCredential of jwtCredentials) {
        let issuer = JwtCredentialValidator.extractIssuerFromJwt(jwtCredential);
        issuers.push(issuer.toString());
    }
    let resolvedIssuers = await resolver.resolveMultiple(issuers);

    // Validate the credentials in the presentation.
    for (let i = 0; i < jwtCredentials.length; i++) {
        credentialValidator.validate(
            jwtCredentials[i],
            resolvedIssuers[i],
            validationOptions,
            FailFast.FirstError,
        );
    }

    // Since no errors were thrown we know that the validation was successful.
    console.log(`VP successfully validated`);
}
