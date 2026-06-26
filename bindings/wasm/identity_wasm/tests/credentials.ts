import * as assert from "assert";
import {
    CoreDocument,
    Credential,
    EdDSAJwsVerifier,
    JwkMemStore,
    JwsAlgorithm,
    JwsSignatureOptions,
    JwsVerificationOptions,
    JwtPresentationOptions,
    JwtPresentationValidationOptions,
    JwtPresentationValidator,
    KeyIdMemStore,
    MethodScope,
    Presentation,
    Storage,
    Timestamp,
    UnknownCredential,
} from "../node";

const credentialFields = {
    context: "https://www.w3.org/2018/credentials/examples/v1",
    id: "https://example.edu/credentials/3732",
    type: "UniversityDegreeCredential",
    credentialSubject: {
        id: "did:example:ebfeb1f712ebc6f1c276e12ec21",
        degree: {
            type: "BachelorDegree",
            name: "Bachelor of Science and Arts",
        },
    },
    issuer: "https://example.edu/issuers/565049",
    issuanceDate: Timestamp.parse("2010-01-01T00:00:00Z"),
    expirationDate: Timestamp.parse("2020-01-01T19:23:24Z"),
    credentialStatus: {
        id: "https://example.edu/status/24",
        type: "CredentialStatusList2017",
    },
    credentialSchema: {
        id: "https://example.org/examples/degree.json",
        type: "JsonSchemaValidator2018",
    },
    refreshService: {
        id: "https://example.edu/refresh/3732",
        type: "ManualRefreshService2018",
    },
    termsOfUse: {
        type: "IssuerPolicy",
        id: "https://example.com/policies/credential/4",
        profile: "https://example.com/profiles/credential",
        prohibition: [
            {
                assigner: "https://example.edu/issuers/14",
                assignee: "AllVerifiers",
                target: "https://example.edu/credentials/3732",
                action: ["Archival"],
            },
        ],
    },
    evidence: {
        id: "https://example.edu/evidence/f2aeec97-fc0d-42bf-8ca7-0548192d4231",
        type: ["DocumentVerification"],
        verifier: "https://example.edu/issuers/14",
        evidenceDocument: "DriversLicense",
        subjectPresence: "Physical",
        documentPresence: "Physical",
        licenseNumber: "123AB4567",
    },
    nonTransferable: true,
    custom1: "asdf",
    custom2: 1234,
};

describe("Credential", function() {
    describe("#new and field getters", function() {
        it("should work", async () => {
            const credential = new Credential(credentialFields);
            assert.deepStrictEqual(credential.context(), [
                Credential.BaseContext(),
                credentialFields.context,
            ]);
            assert.deepStrictEqual(credential.id(), credentialFields.id);
            assert.deepStrictEqual(credential.type(), [
                Credential.BaseType(),
                credentialFields.type,
            ]);
            assert.deepStrictEqual(credential.credentialSubject(), [
                credentialFields.credentialSubject,
            ]);
            assert.deepStrictEqual(credential.issuer(), credentialFields.issuer);
            assert.deepStrictEqual(
                credential.issuanceDate().toRFC3339(),
                credentialFields.issuanceDate.toRFC3339(),
            );
            assert.deepStrictEqual(
                credential.expirationDate()!.toRFC3339(),
                credentialFields.expirationDate.toRFC3339(),
            );
            assert.deepStrictEqual(credential.credentialStatus(), [
                credentialFields.credentialStatus,
            ]);
            assert.deepStrictEqual(credential.credentialSchema(), [
                credentialFields.credentialSchema,
            ]);
            assert.deepStrictEqual(credential.refreshService(), [
                credentialFields.refreshService,
            ]);
            assert.deepStrictEqual(credential.termsOfUse(), [
                credentialFields.termsOfUse,
            ]);
            assert.deepStrictEqual(credential.evidence(), [
                credentialFields.evidence,
            ]);
            assert.deepStrictEqual(
                credential.nonTransferable(),
                credentialFields.nonTransferable,
            );
            const properties = new Map();
            properties.set("custom1", "asdf");
            properties.set("custom2", 1234);
            assert.deepStrictEqual(credential.properties(), properties);
            assert.deepStrictEqual(credential.proof(), undefined);
        });
    });
});

const presentationFields = {
    context: "https://www.w3.org/2018/credentials/examples/v1",
    id: "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
    type: "CredentialManagerPresentation",
    verifiableCredential: [
        "eyJraWQiOiJkaWQ6aW90YTp0c3QxOjB4MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCNrZXktMSIsImFsZyI6IkVkRFNBIn0.eyJpc3MiOiJkaWQ6aW90YTp0c3QxOjB4MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsIm5iZiI6MTY4NzUyMTI2MiwianRpIjoiaHR0cHM6Ly9leGFtcGxlLmVkdS9jcmVkZW50aWFscy8zNzMyIiwic3ViIjoiZGlkOmlvdGE6dHN0MjoweDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJVbml2ZXJzaXR5RGVncmVlQ3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJkZWdyZWUiOnsibmFtZSI6IkJhY2hlbG9yIG9mIFNjaWVuY2UgYW5kIEFydHMiLCJ0eXBlIjoiQmFjaGVsb3JEZWdyZWUifX19fQ.5WmLOTwOBa5Vxuu1cGkGX4wnD6efNulg1tATy-B3_ZsyC8koG1vTpKH4WWoLMkSyQX2F2qw6EyMSjRFJ_dy4Bg",
    ],
    holder: "did:example:1234",
    refreshService: {
        id: "https://example.edu/refresh/3732",
        type: "ManualRefreshService2018",
    },
    termsOfUse: {
        type: "IssuerPolicy",
        id: "https://example.com/policies/credential/4",
        profile: "https://example.com/profiles/credential",
        prohibition: [
            {
                assigner: "https://example.edu/issuers/14",
                assignee: "AllVerifiers",
                target: "https://example.edu/credentials/3732",
                action: ["Archival"],
            },
        ],
    },
    custom1: "asdf",
    custom2: 1234,
};

describe("Presentation", function() {
    describe("#new and field getters", function() {
        it("should work", async () => {
            const presentation = new Presentation(presentationFields);
            assert.deepStrictEqual(presentation.context(), [
                Presentation.BaseContext(),
                presentationFields.context,
            ]);
            assert.deepStrictEqual(presentation.id(), presentationFields.id);
            assert.deepStrictEqual(presentation.type(), [
                Presentation.BaseType(),
                presentationFields.type,
            ]);
            assert.deepStrictEqual(
                presentation.verifiableCredential()[0].tryIntoJwt()!.toString(),
                presentationFields.verifiableCredential[0],
            );
            assert.deepStrictEqual(presentation.holder(), presentationFields.holder);
            assert.deepStrictEqual(presentation.refreshService(), [
                presentationFields.refreshService,
            ]);
            assert.deepStrictEqual(presentation.termsOfUse(), [
                presentationFields.termsOfUse,
            ]);
            const properties = new Map();
            properties.set("custom1", "asdf");
            properties.set("custom2", 1234);
            assert.deepStrictEqual(presentation.properties(), properties);
            assert.deepStrictEqual(presentation.proof(), undefined);
        });
    });
});

describe("Presentation", function() {
    describe("#mixed credentials", function() {
        it("should work", async () => {
            const keystore = new JwkMemStore();
            const keyIdStore = new KeyIdMemStore();
            const storage = new Storage(keystore, keyIdStore);
            const VALID_DID_EXAMPLE = "did:example:123";
            const doc = new CoreDocument({
                id: VALID_DID_EXAMPLE,
            });
            const fragment = "#key-1";
            await doc.generateMethod(
                storage,
                JwkMemStore.ed25519KeyType(),
                JwsAlgorithm.EdDSA,
                fragment,
                MethodScope.VerificationMethod(),
            );

            const subject = {
                id: doc.id(),
                name: "Alice",
                degreeName: "Bachelor of Science and Arts",
                degreeType: "BachelorDegree",
                GPA: "4.0",
            };

            // Create an unsigned `UniversityDegree` credential for Alice
            const unsignedVc = new Credential({
                id: "https://example.edu/credentials/3732",
                type: "UniversityDegreeCredential",
                issuer: doc.id(),
                credentialSubject: subject,
            });

            const credentialJwt = await doc.createCredentialJwt(
                storage,
                fragment,
                unsignedVc,
                new JwsSignatureOptions(),
            );

            const otherCredential = {
                custom: "property",
                other: 5,
                isCredential: true,
            };

            const unsignedVp = new Presentation({
                holder: doc.id(),
                verifiableCredential: [credentialJwt, unsignedVc, otherCredential],
            });

            const myKid = "my-kid";
            const presentationJwt = await doc.createPresentationJwt(
                storage,
                fragment,
                unsignedVp,
                new JwsSignatureOptions({
                    kid: myKid,
                }),
                new JwtPresentationOptions(),
            );

            let issuer = JwtPresentationValidator.extractHolder(presentationJwt);
            assert.deepStrictEqual(issuer.toString(), doc.id().toString());

            const methodId = doc.id().join(fragment);
            const decodedPresentation = new JwtPresentationValidator(new EdDSAJwsVerifier()).validate(
                presentationJwt,
                doc,
                new JwtPresentationValidationOptions({
                    presentationVerifierOptions: new JwsVerificationOptions({
                        methodId: methodId,
                    }),
                }),
            );
            assert.deepStrictEqual(decodedPresentation.protectedHeader().kid(), myKid);

            const credentials: UnknownCredential[] = decodedPresentation
                .presentation()
                .verifiableCredential();

            assert.deepStrictEqual(
                credentials[0].tryIntoJwt()?.toString(),
                credentialJwt.toString(),
            );
            assert.deepStrictEqual(
                credentials[1].tryIntoCredential()?.toJSON(),
                unsignedVc.toJSON(),
            );
            assert.deepStrictEqual(credentials[2].tryIntoRaw()!, otherCredential);
        });
    });
});
