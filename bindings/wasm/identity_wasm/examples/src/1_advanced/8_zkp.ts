import {
    Credential,
    FailFast,
    IdentityClientReadOnly,
    IotaDID,
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
    SelectiveDisclosurePresentation,
} from "@iota/identity-wasm/node";
import { IotaClient } from "@iota/iota-sdk/client";
import { getFundedClient, getMemstorage, IOTA_IDENTITY_PKG_ID, NETWORK_URL } from "../util";

export async function zkp() {
    // ===========================================================================
    // Step 1: Create identity for the issuer.
    // ===========================================================================

    // create new client to connect to IOTA network
    const iotaClient = new IotaClient({ url: NETWORK_URL });
    const network = await iotaClient.getChainIdentifier();

    // Create an identity for the issuer with one verification method `key-1`, and publish DID document for it.
    const issuerStorage = getMemstorage();
    const issuerClient = await getFundedClient(issuerStorage);
    const unpublishedIssuerDocument = new IotaDocument(network);
    const issuerFragment = await unpublishedIssuerDocument.generateMethodJwp(
        issuerStorage,
        ProofAlgorithm.BBS,
        undefined,
        MethodScope.VerificationMethod(),
    );
    const { output: issuerIdentity } = await issuerClient
        .createIdentity(unpublishedIssuerDocument)
        .finish()
        .buildAndExecute(issuerClient);
    const issuerDocument = issuerIdentity.didDocument();

    // ===========================================================================
    // Step 2: Issuer creates and signs a Verifiable Credential with BBS algorithm.
    // ===========================================================================

    // Create a credential subject indicating the degree earned by Alice.
    const subject = {
        name: "Alice",
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

    // ===========================================================================
    // Step 3: Issuer sends the Verifiable Credential to the holder.
    // ===========================================================================
    console.log("Sending credential (as JPT) to the holder: " + credentialJpt.toString());

    // ============================================================================================
    // Step 4: Holder resolve Issuer's DID, retrieve Issuer's document and validate the Credential
    // ============================================================================================
    const identityClientReadOnly = await IdentityClientReadOnly.createWithPkgId(
        iotaClient,
        IOTA_IDENTITY_PKG_ID,
    );

    // Holder resolves issuer's DID.
    let issuerDid = IotaDID.parse(JptCredentialValidatorUtils.extractIssuerFromIssuedJpt(credentialJpt).toString());
    let issuerDoc = await identityClientReadOnly.resolveDid(issuerDid);

    // Holder validates the credential and retrieve the JwpIssued, needed to construct the JwpPresented
    let decodedCredential = JptCredentialValidator.validate(
        credentialJpt,
        issuerDoc,
        new JptCredentialValidationOptions(),
        FailFast.FirstError,
    );

    // ===========================================================================
    // Step 5: Verifier sends the holder a challenge and requests a Presentation.
    //
    // Please be aware that when we mention "Presentation," we are not alluding to the Verifiable Presentation standard as defined by W3C (https://www.w3.org/TR/vc-data-model/#presentations).
    // Instead, our reference is to a JWP Presentation (https://datatracker.ietf.org/doc/html/draft-ietf-jose-json-web-proof#name-presented-form), which differs from the W3C standard.
    // ===========================================================================

    // A unique random challenge generated by the requester per presentation can mitigate replay attacks.
    const challenge = "475a7984-1bb5-4c4c-a56f-822bccd46440";

    // =========================================================================================================
    // Step 6: Holder engages in the Selective Disclosure of credential's attributes.
    // =========================================================================================================
    const methodId = decodedCredential
        .decodedJwp()
        .getIssuerProtectedHeader()
        .kid!;
    const selectiveDisclosurePresentation = new SelectiveDisclosurePresentation(decodedCredential.decodedJwp());
    selectiveDisclosurePresentation.concealInSubject("mainCourses[1]");
    selectiveDisclosurePresentation.concealInSubject("degree.name");

    // =======================================================================================================================================
    // Step 7: Holder needs Issuer's Public Key to compute the Signature Proof of Knowledge and construct the Presentation
    // JPT.
    // =======================================================================================================================================

    // Construct a JPT(JWP in the Presentation form) representing the Selectively Disclosed Verifiable Credential
    const presentationOptions = new JwpPresentationOptions();
    presentationOptions.nonce = challenge;
    const presentationJpt = await issuerDoc
        .createPresentationJpt(
            selectiveDisclosurePresentation,
            methodId,
            presentationOptions,
        );

    // ===========================================================================
    // Step 8: Holder sends a Presentation JPT to the Verifier.
    // ===========================================================================

    console.log("Sending presentation (as JPT) to the verifier: " + presentationJpt.toString());

    // ===========================================================================
    // Step 9: Verifier receives the Presentation and verifies it.
    // ===========================================================================

    // Verifier resolve Issuer DID
    const issuerDidV = IotaDID.parse(
        JptPresentationValidatorUtils.extractIssuerFromPresentedJpt(presentationJpt).toString(),
    );
    const issuerDocV = await identityClientReadOnly.resolveDid(issuerDidV);

    const presentationValidationOptions = new JptPresentationValidationOptions({ nonce: challenge });
    const decodedPresentedCredential = JptPresentationValidator.validate(
        presentationJpt,
        issuerDocV,
        presentationValidationOptions,
        FailFast.FirstError,
    );

    console.log("Presented credential successfully validated: " + decodedPresentedCredential.credential());
}
