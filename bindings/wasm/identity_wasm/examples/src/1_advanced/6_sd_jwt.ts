// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
    Credential,
    EdDSAJwsVerifier,
    JwtCredentialValidationOptions,
    KeyBindingJwtBuilder,
    KeyBindingJwtValidationOptions,
    SdJwt,
    SdJwtBuilder,
    SdJwtCredentialValidator,
    SdJwtPresentationBuilder,
    Sha256Hasher,
    StorageSigner,
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
    const issuerVmSigner = await StorageSigner.fromVmFragment(issuerStorage, issuerDocument, issuerFragment);

    // Create an identity for the holder, and publish DID document for it, in this case also the subject.
    const aliceStorage = getMemstorage();
    const aliceClient = await getFundedClient(aliceStorage);
    const [unpublishedAliceDocument, aliceFragment] = await createDocumentForNetwork(aliceStorage, network);
    const { output: aliceIdentity } = await aliceClient
        .createIdentity(unpublishedAliceDocument)
        .finish()
        .buildAndExecute(aliceClient);
    const aliceDocument = aliceIdentity.didDocument();
    const aliceSigner = await StorageSigner.fromVmFragment(aliceStorage, aliceDocument, aliceFragment);

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

    console.log("Plaintext Credential:\n" + JSON.stringify(credential, null, 2));

    // The issuer decides to make the subject address's "locality", "postal_code",
    // and "street_address" properties selectively disclosable.
    // The issuer also requires a Key Binding JWT signed by the holder's key to be
    // presented along with the SD-JWT.
    const issuedSdJwt = await new SdJwtBuilder(credential.toJwtClaims(), new Sha256Hasher())
        .header("kid", `${issuerDocument.id()}#${issuerFragment}`)
        .makeConcealable("/vc/credentialSubject/address/locality")
        .makeConcealable("/vc/credentialSubject/address/postal_code")
        .makeConcealable("/vc/credentialSubject/address/street_address")
        .makeConcealable("/vc/credentialSubject/nationalities/1")
        .addDecoys("/vc/credentialSubject/nationalities", 3)
        .addDecoys("/vc", 4)
        .addDecoys("/vc/credentialSubject/address", 2)
        .requireKeyBinding({ kid: `${aliceDocument.id()}#${aliceFragment}` })
        .finish(issuerVmSigner.asJwsSigner(), "EdDSA");

    // ===========================================================================
    // Step 3: Issuer sends the JWT and the disclosures to the holder.
    // ===========================================================================

    console.log("issued SD-JWT Credential: " + issuedSdJwt);

    // ===========================================================================
    // Step 4: Verifier sends the holder a challenge and requests a signed Verifiable Presentation.
    // ===========================================================================

    const VERIFIER_DID = "did:example:verifier";
    // A unique random challenge generated by the requester per presentation can mitigate replay attacks.
    const nonce = "475a7984-1bb5-4c4c-a56f-822bccd46440";

    // ===========================================================================
    // Step 5: Holder creates an SD-JWT to be presented to a verifier.
    // ===========================================================================

    const sdJwtReceived = SdJwt.parse(issuedSdJwt.toString());

    // The holder only wants to present "locality" and "postal_code" but not "street_address" or the "US" nationality.
    let sdJwtToPresent = new SdJwtPresentationBuilder(sdJwtReceived, new Sha256Hasher())
        .conceal_all()
        .disclose("/vc/credentialSubject/address/locality")
        .disclose("/vc/credentialSubject/address/postal_code")
        .finish()
        .sdJwt;

    let kbJwt = await new KeyBindingJwtBuilder()
        .aud(VERIFIER_DID)
        .iat(Timestamp.nowUTC())
        .nonce(nonce)
        .header("kid", `${aliceDocument.id}#${aliceFragment}`)
        .finish(sdJwtToPresent, "EdDSA", aliceSigner.asJwsSigner());

    sdJwtToPresent.attachKeyBindingJwt(kbJwt);

    // ===========================================================================
    // Step 6: Holder presents the SD-JWT to the verifier.
    // ===========================================================================

    let sdJwtPresentation = sdJwtToPresent.presentation();

    // ===========================================================================
    // Step 7: Verifier receives the SD-JWT and verifies it.
    // ===========================================================================

    const sdJwtToVerify = SdJwt.parse(sdJwtPresentation);

    // Verify the JWT.
    let validator = new SdJwtCredentialValidator(new Sha256Hasher(), new EdDSAJwsVerifier());
    let decodedCredential: Credential = validator.validateCredential(
        sdJwtToVerify,
        issuerDocument,
        new JwtCredentialValidationOptions(),
    );

    console.log("JWT successfully validated");
    console.log("Decoded credential: \n", decodedCredential);

    // Verify the Key Binding JWT.
    let kbValidationOptions = new KeyBindingJwtValidationOptions({
        aud: VERIFIER_DID,
        nonce: nonce,
    });
    validator.validateKeyBindingJwt(sdJwtToVerify, aliceDocument, kbValidationOptions);

    console.log("Key Binding JWT successfully validated");
}
