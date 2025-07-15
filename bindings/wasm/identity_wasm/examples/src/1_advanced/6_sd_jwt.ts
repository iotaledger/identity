// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
    Credential,
    DecodedJwtCredential,
    EdDSAJwsVerifier,
    FailFast,
    JwsSignatureOptions,
    JwsVerificationOptions,
    JwtCredentialValidationOptions,
    KeyBindingJwtClaims,
    KeyBindingJWTValidationOptions,
    SdJwt,
    SdJwtCredentialValidator,
    SdObjectEncoder,
    Timestamp,
} from "@iota/identity-wasm/node";
import { IotaClient } from "@iota/iota-sdk/client";
import { createDocumentForNetwork, getFundedClient, getMemstorage, NETWORK_URL } from "../util";

/**
 * Demonstrates how to create a selective disclosure verifiable credential and validate it * using the [Selective Disclosure for JWTs (SD-JWT)](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-07.html) specification.
 */
export async function sdJwt() {
    // ===========================================================================
    // Step 1: Create identities for the issuer and the holder.
    // ===========================================================================

    // create new client to connect to IOTA network
    const iotaClient = new IotaClient({ url: NETWORK_URL });
    const network = await iotaClient.getChainIdentifier();

    // Creates a new wallet and identity (see "0_create_did" example).
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
    const [unpublishedAliceDocument, aliceFragment] = await createDocumentForNetwork(aliceStorage, network);
    const { output: aliceIdentity } = await aliceClient
        .createIdentity(unpublishedAliceDocument)
        .finish()
        .buildAndExecute(aliceClient);
    const aliceDocument = aliceIdentity.didDocument();

    // ===========================================================================
    // Step 2: Issuer creates and signs a selectively disclosable JWT verifiable credential.
    // ===========================================================================

    // Create an address credential subject.
    const subject = {
        id: aliceDocument.id(),
        name: "Alice",
        nationalities: ["DE", "US"],
        address: {
            locality: "Maxstadt",
            postal_code: "12344",
            country: "DE",
            street_address: "Weidenstraße 22",
        },
    };

    // Build credential using subject above and issuer.
    const credential = new Credential({
        id: "https://example.com/credentials/3732",
        type: "AddressCredential",
        issuer: issuerDocument.id(),
        credentialSubject: subject,
    });

    // In Order to create an selective disclosure JWT, the plain text JWT
    // claims set must be created first.
    let payload = credential.toJwtClaims();

    // The issuer can make all or subset of the claims selectively disclosable.
    let encoder = new SdObjectEncoder(payload);

    // Make "locality", "postal_code", "street_address"  and the first entry of "nationalities"
    // selectively disclosable while keeping other properties in plain text.
    let disclosures = [
        encoder.conceal("/vc/credentialSubject/address/locality"),
        encoder.conceal("/vc/credentialSubject/address/postal_code"),
        encoder.conceal("/vc/credentialSubject/address/street_address"),
        encoder.conceal("/vc/credentialSubject/nationalities/1"),
    ];

    // Add decoys in the credential top level, nationalities array and address object.
    encoder.addDecoys("/vc/credentialSubject/nationalities", 3);
    encoder.addDecoys("/vc", 4);
    encoder.addDecoys("/vc/credentialSubject/address", 2);

    // Add the `_sd_alg` property.
    encoder.addSdAlgProperty();

    console.log("Claims set with disclosure digests: ");
    console.log(JSON.stringify(encoder.encodeToObject(), null, 2), "\n");

    // Create the signed JWT.
    const encodedPayload = encoder.encodeToString();
    let jws = await issuerDocument.createJws(issuerStorage, issuerFragment, encodedPayload, new JwsSignatureOptions());

    // ===========================================================================
    // Step 3: Issuer sends the JWT and the disclosures to the holder.
    // ===========================================================================

    // One way to send the JWT and the disclosures, is by creating an SD-JWT with all the
    // disclosures.
    const strDisclosures = disclosures.map(disclosure => disclosure.toEncodedString());

    let sdJwt = new SdJwt(jws.toString(), strDisclosures).presentation();

    // ===========================================================================
    // Step 4: Verifier sends the holder a challenge and requests a signed Verifiable Presentation.
    // ===========================================================================

    const VERIFIER_DID = "did:example:verifier";
    // A unique random challenge generated by the requester per presentation can mitigate replay attacks.
    let nonce = "475a7984-1bb5-4c4c-a56f-822bccd46440";

    // ===========================================================================
    // Step 5: Holder creates an SD-JWT to be presented to a verifier.
    // ===========================================================================

    const sdJwtReceived = SdJwt.parse(sdJwt);

    // The holder only wants to present "locality" and "postal_code" but not "street_address" or the "US" nationality.
    const receivedDisclosures = sdJwtReceived.disclosures();
    const toBeDisclosed = [
        receivedDisclosures[0],
        receivedDisclosures[1],
    ];

    // Optionally, the holder can add a Key Binding JWT (KB-JWT). This is dependent on the verifier's policy.
    // Issuing the KB-JWT is done by creating the claims set and setting the header `typ` value
    // with the help of `KeyBindingJwtClaims`.
    const bindingClaims = new KeyBindingJwtClaims(
        sdJwtReceived.jwt(),
        toBeDisclosed,
        nonce,
        VERIFIER_DID,
        Timestamp.nowUTC(),
    );

    // Setting the `typ` in the header is required.
    const options = new JwsSignatureOptions({
        typ: KeyBindingJwtClaims.keyBindingJwtHeaderTyp(),
    });
    const kbJwt = await aliceDocument.createJws(aliceStorage, aliceFragment, bindingClaims.toString(), options);

    // Create the final SD-JWT.
    let sdJwtWithKb = new SdJwt(sdJwtReceived.jwt().toString(), toBeDisclosed, kbJwt.toString());

    // ===========================================================================
    // Step 6: Holder presents the SD-JWT to the verifier.
    // ===========================================================================

    let sdJwtPresentation = sdJwtWithKb.presentation();

    // ===========================================================================
    // Step 7: Verifier receives the SD-JWT and verifies it.
    // ===========================================================================

    const sdJwtObj = SdJwt.parse(sdJwtPresentation);

    // Verify the JWT.
    let validator = new SdJwtCredentialValidator(new EdDSAJwsVerifier());
    let decodedCredential: DecodedJwtCredential = validator.validateCredential(
        sdJwtObj,
        issuerDocument,
        new JwtCredentialValidationOptions(),
        FailFast.FirstError,
    );

    console.log("JWT successfully validated");
    console.log("Decoded credential: \n", decodedCredential.credential());

    // Verify the Key Binding JWT.
    let kbValidationOptions = new KeyBindingJWTValidationOptions(
        {
            aud: VERIFIER_DID,
            nonce: nonce,
            jwsOptions: new JwsVerificationOptions(),
        },
    );
    validator.validateKeyBindingJwt(sdJwtObj, aliceDocument, kbValidationOptions);

    console.log("Key Binding JWT successfully validated");
}
