import {
    Credential,
    Duration,
    FailFast,
    IotaDocument,
    JptCredentialValidationOptions,
    JptCredentialValidator,
    JptCredentialValidatorUtils,
    JptPresentationValidationOptions,
    JptPresentationValidator,
    JptPresentationValidatorUtils,
    JwpCredentialOptions,
    JwpPresentationOptions,
    MethodScope,
    ProofAlgorithm,
    RevocationBitmap,
    RevocationTimeframeStatus,
    SelectiveDisclosurePresentation,
    Status,
    StatusCheck,
    Timestamp,
} from "@iota/identity-wasm/node";
import { IotaClient } from "@iota/iota-sdk/client";
import { createDocumentForNetwork, getFundedClient, getMemstorage, NETWORK_URL, TEST_GAS_BUDGET } from "../util";

export async function zkp_revocation() {
    // create new client to connect to IOTA network
    const iotaClient = new IotaClient({ url: NETWORK_URL });
    const network = await iotaClient.getChainIdentifier();

    // Create an identity for the issuer with one verification method `key-1`, and publish DID document for it.
    const issuerStorage = getMemstorage();
    const issuerClient = await getFundedClient(issuerStorage);
    const unpublishedIssuerDocument = new IotaDocument(network);
    const issuerFragment = await unpublishedIssuerDocument.generateMethodJwp(
        issuerStorage,
        ProofAlgorithm.BLS12381_SHA256,
        undefined,
        MethodScope.VerificationMethod(),
    );
    const revocationBitmap = new RevocationBitmap();
    // add service for revocation
    const serviceId = unpublishedIssuerDocument.id().toUrl().join("#my-revocation-service");
    const service = revocationBitmap.toService(serviceId);
    unpublishedIssuerDocument.insertService(service);
    const { output: issuerIdentity } = await issuerClient
        .createIdentity(unpublishedIssuerDocument)
        .finish()
        .buildAndExecute(issuerClient);
    let issuerDocument = issuerIdentity.didDocument();

    // Create an identity for the holder, and publish DID document for it, in this case also the subject.
    const holderStorage = getMemstorage();
    const holderClient = await getFundedClient(holderStorage);
    const [unpublishedholderDocument] = await createDocumentForNetwork(holderStorage, network);
    const { output: holderIdentity } = await holderClient
        .createIdentity(unpublishedholderDocument)
        .finish()
        .buildAndExecute(holderClient);
    const holderDocument = holderIdentity.didDocument();

    // =========================================================================================
    // Step 1: Create a new RevocationTimeframeStatus containing the current validityTimeframe
    // =======================================================================================

    const timeframeId = issuerDocument.id().toUrl().join("#my-revocation-service");
    let revocationTimeframeStatus = new RevocationTimeframeStatus(
        timeframeId.toString(),
        5,
        Duration.minutes(1),
        Timestamp.nowUTC(),
    );

    // Create a credential subject indicating the degree earned by holder.
    const subject = {
        name: "holder",
        mainCourses: ["Object-oriented Programming", "Mathematics"],
        degree: {
            type: "BachelorDegree",
            name: "Bachelor of Science and Arts",
        },
        GPA: 4.0,
    };

    // Build credential using the above subject and issuer.
    const credential = new Credential({
        id: "https:/example.edu/credentials/3732",
        issuer: issuerDocument.id(),
        type: "UniversityDegreeCredential",
        credentialSubject: subject,
        credentialStatus: revocationTimeframeStatus as any as Status,
    });
    const credentialJpt = await issuerDocument
        .createCredentialJpt(
            credential,
            issuerStorage,
            issuerFragment,
            new JwpCredentialOptions(),
        );
    // Validate the credential's proof using the issuer's DID Document, the credential's semantic structure,
    // that the issuance date is not in the future and that the expiration date is not in the past:
    const decodedJpt = JptCredentialValidator.validate(
        credentialJpt,
        issuerDocument,
        new JptCredentialValidationOptions(),
        FailFast.FirstError,
    );

    console.log("Sending credential (as JPT) to the holder: " + credentialJpt.toString());

    // Holder validates the credential and retrieve the JwpIssued, needed to construct the JwpPresented
    let decodedCredential = JptCredentialValidator.validate(
        credentialJpt,
        issuerDocument,
        new JptCredentialValidationOptions(),
        FailFast.FirstError,
    );

    // ===========================================================================
    // Credential's Status check
    // ===========================================================================
    JptCredentialValidatorUtils.checkTimeframesAndRevocationWithValidityTimeframe2024(
        decodedCredential.credential(),
        issuerDocument,
        undefined,
        StatusCheck.Strict,
    );

    // A unique random challenge generated by the requester per presentation can mitigate replay attacks.
    const challenge = "475a7984-1bb5-4c4c-a56f-822bccd46440";

    const methodId = decodedCredential
        .decodedJwp()
        .getIssuerProtectedHeader()
        .kid!;

    const selectiveDisclosurePresentation = new SelectiveDisclosurePresentation(decodedCredential.decodedJwp());
    selectiveDisclosurePresentation.concealInSubject("mainCourses[1]");
    selectiveDisclosurePresentation.concealInSubject("degree.name");

    // Construct a JPT(JWP in the Presentation form) representing the Selectively Disclosed Verifiable Credential
    const presentationOptions = new JwpPresentationOptions();
    presentationOptions.nonce = challenge;
    const presentationJpt = await issuerDocument
        .createPresentationJpt(
            selectiveDisclosurePresentation,
            methodId,
            presentationOptions,
        );

    console.log("Sending presentation (as JPT) to the verifier: " + presentationJpt.toString());

    // ===========================================================================
    // Step 2: Verifier receives the Presentation and verifies it.
    // ===========================================================================

    const presentationValidationOptions = new JptPresentationValidationOptions({ nonce: challenge });
    const decodedPresentedCredential = JptPresentationValidator.validate(
        presentationJpt,
        issuerDocument,
        presentationValidationOptions,
        FailFast.FirstError,
    );

    JptPresentationValidatorUtils.checkTimeframesWithValidityTimeframe2024(
        decodedPresentedCredential.credential(),
        undefined,
        StatusCheck.Strict,
    );

    console.log("Presented credential successfully validated: " + decodedPresentedCredential.credential());

    // ===========================================================================
    // Step 2b: Waiting for the next validityTimeframe, will result in the Credential timeframe interval NOT valid
    // ===========================================================================

    try {
        const now = new Date();
        const timeInTwoMinutes = new Date(now.setMinutes(now.getMinutes() + 2));
        JptPresentationValidatorUtils.checkTimeframesWithValidityTimeframe2024(
            decodedPresentedCredential.credential(),
            Timestamp.parse(timeInTwoMinutes.toISOString()),
            StatusCheck.Strict,
        );
    } catch (_) {
        console.log("Successfully expired!");
    }

    // ===========================================================================
    // Issuer decides to Revoke Holder's Credential
    // ===========================================================================

    console.log("Issuer decides to revoke the Credential");

    const issuerIdentityToken = await issuerIdentity.getControllerToken(issuerClient);
    // Update the RevocationBitmap service in the issuer's DID Document.
    // This revokes the credential's unique index.
    issuerDocument.revokeCredentials("my-revocation-service", 5);
    await issuerIdentity.updateDidDocument(issuerDocument, issuerIdentityToken!)
        .buildAndExecute(
            issuerClient,
        );
    issuerDocument = issuerIdentity.didDocument();

    // Holder checks if his credential has been revoked by the Issuer
    try {
        JptCredentialValidatorUtils.checkRevocationWithValidityTimeframe2024(
            decodedCredential.credential(),
            issuerDocument,
            StatusCheck.Strict,
        );
    } catch (_) {
        console.log("Credential revoked!");
    }
}
