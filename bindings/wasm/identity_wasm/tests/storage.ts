const assert = require("assert");
import {
    CoreDocument,
    Credential,
    DecodedJwtPresentation,
    Duration,
    EdDSAJwsVerifier,
    FailFast,
    IJwsVerifier,
    IotaDocument,
    Jwk,
    JwkMemStore,
    JwsAlgorithm,
    JwsSignatureOptions,
    JwsVerificationOptions,
    Jwt,
    JwtCredentialValidationOptions,
    JwtCredentialValidator,
    JwtPresentationOptions,
    JwtPresentationValidationOptions,
    JwtPresentationValidator,
    KeyIdMemStore,
    MethodDigest,
    MethodScope,
    Presentation,
    StatusCheck,
    Storage,
    SubjectHolderRelationship,
    Timestamp,
    VerificationMethod,
} from "../node";
import { createVerificationMethod } from "./key_id_storage";

describe("#JwkStorageDocument", function() {
    it("storage getters should work", async () => {
        const keystore = new JwkMemStore();
        // Put some data in the keystore
        let genOutput = await keystore.generate(
            JwkMemStore.ed25519KeyType(),
            JwsAlgorithm.EdDSA,
        );
        const keyId = genOutput.keyId();
        assert.ok(genOutput.jwk());
        assert.ok(keyId);

        const keyIdStore = new KeyIdMemStore();
        // Put some data in the keyIdStore
        let vm: VerificationMethod = createVerificationMethod();
        let methodDigest: MethodDigest = new MethodDigest(vm);
        keyIdStore.insertKeyId(methodDigest, keyId);

        // Create new storage
        const storage = new Storage(keystore, keyIdStore);

        // Check that we can retrieve the separate storages and their state is preserved
        const retrievedKeyIdStore = storage.keyIdStorage();
        assert.deepStrictEqual(retrievedKeyIdStore instanceof KeyIdMemStore, true);

        const retrievedKeyId = await retrievedKeyIdStore.getKeyId(methodDigest);
        assert.deepStrictEqual(keyId as string, retrievedKeyId);

        const retrievedKeyStore = storage.keyStorage();
        assert.deepStrictEqual(retrievedKeyStore instanceof JwkMemStore, true);
        assert.deepStrictEqual(
            await retrievedKeyStore.exists(retrievedKeyId),
            true,
        );
    });

    it("The JwkStorageDocument extension should work: CoreDocument", async () => {
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
        // Check that we can resolve the generated method.
        let method = doc.resolveMethod(fragment);
        assert.deepStrictEqual(method instanceof VerificationMethod, true);

        // Check that signing works
        let testString = "test";
        let options = new JwsSignatureOptions({
            customHeaderParameters: {
                testKey: "testValue",
            },
        });
        const jws = await doc.createJws(
            storage,
            fragment,
            testString,
            options,
        );

        // Verify the signature and obtain a decoded token.
        const token = doc.verifyJws(jws, new JwsVerificationOptions(), new EdDSAJwsVerifier());
        assert.deepStrictEqual(testString, token.claims());

        // Verify custom header parameters.
        assert.deepStrictEqual(token.protectedHeader().custom(), { testKey: "testValue" });

        // Check that we can also verify it using a custom verifier
        let customVerifier = new CustomVerifier();
        const tokenFromCustomVerification = doc.verifyJws(
            jws,
            new JwsVerificationOptions(),
            customVerifier,
        );
        assert.deepStrictEqual(
            token.toJSON(),
            tokenFromCustomVerification.toJSON(),
        );
        // Check that customVerifier.verify was indeed called
        assert.deepStrictEqual(customVerifier.verifications(), 1);

        // Check that issuing a credential as a JWT works
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
            issuer: doc.id(),
            issuanceDate: Timestamp.parse("2010-01-01T00:00:00Z"),
        };

        const credential = new Credential(credentialFields);
        // Create the JWT
        const credentialJwt = await doc.createCredentialJwt(
            storage,
            fragment,
            credential,
            new JwsSignatureOptions(),
            { testkey: "test-value" },
        );

        // Check that the credentialJwt can be decoded and verified
        let credentialValidator = new JwtCredentialValidator(new EdDSAJwsVerifier());
        const decoded = credentialValidator
            .validate(
                credentialJwt,
                doc,
                new JwtCredentialValidationOptions(),
                FailFast.FirstError,
            );
        assert.deepStrictEqual(decoded.customClaims(), { testkey: "test-value" });
        assert.deepStrictEqual(decoded.credential().toJSON(), credential.toJSON());

        // Also check using our custom verifier
        let credentialValidatorCustom = new JwtCredentialValidator(customVerifier);
        const credentialRetrievedCustom = credentialValidatorCustom
            .validate(
                credentialJwt,
                doc,
                new JwtCredentialValidationOptions(),
                FailFast.AllErrors,
            )
            .credential();
        // Check that customVerifier.verify was indeed called
        assert.deepStrictEqual(customVerifier.verifications(), 2);
        assert.deepStrictEqual(
            credentialRetrievedCustom.toJSON(),
            credential.toJSON(),
        );

        // Delete the method
        const methodId = (method as VerificationMethod).id();
        await doc.purgeMethod(storage, methodId); // Check that the method can no longer be resolved.
        assert.deepStrictEqual(doc.resolveMethod(fragment), undefined);
        // The storage should now be empty
        assert.deepStrictEqual(
            (storage.keyIdStorage() as KeyIdMemStore).count(),
            0,
        );
        assert.deepStrictEqual((storage.keyStorage() as JwkMemStore).count(), 0);
    });

    it("The JwkStorageDocument extension should work: IotaDocument", async () => {
        const keystore = new JwkMemStore();
        const keyIdStore = new KeyIdMemStore();
        const storage = new Storage(keystore, keyIdStore);
        const networkName = "smr";
        const doc = new IotaDocument(networkName);
        const fragment = "#key-1";
        await doc.generateMethod(
            storage,
            JwkMemStore.ed25519KeyType(),
            JwsAlgorithm.EdDSA,
            fragment,
            MethodScope.VerificationMethod(),
        );
        // Check that we can resolve the generated method.
        let method = doc.resolveMethod(fragment);
        assert.deepStrictEqual(method instanceof VerificationMethod, true);

        // Check that signing works.
        let testString = "test";
        const jws = await doc.createJwt(
            storage,
            fragment,
            testString,
            new JwsSignatureOptions(),
        );

        // Verify the signature and obtain a decoded token.
        const token = doc.verifyJws(jws, new JwsVerificationOptions(), new EdDSAJwsVerifier());
        assert.deepStrictEqual(testString, token.claims());

        // Check that we can also verify it using a custom verifier
        let customVerifier = new CustomVerifier();
        const tokenFromCustomVerification = doc.verifyJws(
            jws,
            new JwsVerificationOptions(),
            customVerifier,
        );
        assert.deepStrictEqual(
            token.toJSON(),
            tokenFromCustomVerification.toJSON(),
        );
        assert.deepStrictEqual(customVerifier.verifications(), 1);

        // Check that issuing a credential as a JWT works
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
            issuer: doc.id(),
            issuanceDate: Timestamp.parse("2010-01-01T00:00:00Z"),
        };

        const credential = new Credential(credentialFields);
        // Create the JWT
        const credentialJwt = await doc.createCredentialJwt(
            storage,
            fragment,
            credential,
            new JwsSignatureOptions(),
            { "test-key": "test-value" },
        );

        // Check that the credentialJwt can be decoded and verified
        let credentialValidator = new JwtCredentialValidator(new EdDSAJwsVerifier());
        const decoded = credentialValidator
            .validate(
                credentialJwt,
                doc,
                new JwtCredentialValidationOptions(),
                FailFast.FirstError,
            );
        assert.deepStrictEqual(decoded.customClaims(), { "test-key": "test-value" });
        assert.deepStrictEqual(decoded.credential().toJSON(), credential.toJSON());

        // Also check using our custom verifier
        let credentialValidatorCustom = new JwtCredentialValidator(customVerifier);
        const credentialRetrievedCustom = credentialValidatorCustom
            .validate(
                credentialJwt,
                doc,
                new JwtCredentialValidationOptions(),
                FailFast.AllErrors,
            )
            .credential();
        // Check that customVerifier.verify was indeed called
        assert.deepStrictEqual(customVerifier.verifications(), 2);
        assert.deepStrictEqual(
            credentialRetrievedCustom.toJSON(),
            credential.toJSON(),
        );

        // Delete the method
        const methodId = (method as VerificationMethod).id();
        await doc.purgeMethod(storage, methodId); // Check that the method can no longer be resolved.
        assert.deepStrictEqual(doc.resolveMethod(fragment), undefined);
        // The storage should now be empty
        assert.deepStrictEqual(
            (storage.keyIdStorage() as KeyIdMemStore).count(),
            0,
        );
        assert.deepStrictEqual((storage.keyStorage() as JwkMemStore).count(), 0);
    });

    it("JwtPresentation should work", async () => {
        const keystore = new JwkMemStore();
        const keyIdStore = new KeyIdMemStore();
        const storage = new Storage(keystore, keyIdStore);
        const issuerDoc = new IotaDocument("tst1");
        const fragment = "#key-1";
        await issuerDoc.generateMethod(
            storage,
            JwkMemStore.ed25519KeyType(),
            JwsAlgorithm.EdDSA,
            fragment,
            MethodScope.VerificationMethod(),
        );

        const holderDoc = new IotaDocument("tst2");
        await holderDoc.generateMethod(
            storage,
            JwkMemStore.ed25519KeyType(),
            JwsAlgorithm.EdDSA,
            fragment,
            MethodScope.VerificationMethod(),
        );

        let customVerifier = new CustomVerifier();
        const credentialFields = {
            context: "https://www.w3.org/2018/credentials/examples/v1",
            id: "https://example.edu/credentials/3732",
            type: "UniversityDegreeCredential",
            credentialSubject: {
                id: holderDoc.id(),
                degree: {
                    type: "BachelorDegree",
                    name: "Bachelor of Science and Arts",
                },
            },
            issuer: issuerDoc.id(),
            issuanceDate: Timestamp.nowUTC(),
        };

        const credential = new Credential(credentialFields);
        const credentialJwt: Jwt = await issuerDoc.createCredentialJwt(
            storage,
            fragment,
            credential,
            new JwsSignatureOptions(),
        );

        const presentation = new Presentation({
            holder: holderDoc.id(),
            verifiableCredential: [
                credentialJwt.toString(),
                credentialJwt.toString(),
            ],
        });

        const expirationDate = Timestamp.nowUTC().checkedAdd(Duration.days(2));
        const audience = "did:test:123";
        const presentationJwt = await holderDoc.createPresentationJwt(
            storage,
            fragment,
            presentation,
            new JwsSignatureOptions(),
            new JwtPresentationOptions({
                expirationDate,
                issuanceDate: Timestamp.nowUTC(),
                audience,
                customClaims: {
                    testKey: "testValue",
                },
            }),
        );

        let validator = new JwtPresentationValidator(customVerifier);
        let decoded: DecodedJwtPresentation = validator.validate(
            presentationJwt,
            holderDoc,
            new JwtPresentationValidationOptions(),
        );

        assert.equal(
            decoded.expirationDate()!.toString(),
            expirationDate!.toString(),
        );
        assert.deepStrictEqual(
            decoded.presentation().toJSON(),
            presentation.toJSON(),
        );
        assert.equal(decoded.audience(), audience);
        assert.deepStrictEqual(decoded.customClaims(), { testKey: "testValue" });

        // check issuance date validation.
        let options = new JwtPresentationValidationOptions({
            latestIssuanceDate: Timestamp.nowUTC().checkedSub(Duration.days(1)),
        });
        assert.throws(() => {
            validator.validate(presentationJwt, holderDoc, options);
        });

        // Check expiration date validation.
        options = new JwtPresentationValidationOptions({
            earliestExpiryDate: Timestamp.nowUTC().checkedAdd(Duration.days(1)),
        });
        validator.validate(presentationJwt, holderDoc, options);

        options = new JwtPresentationValidationOptions({
            earliestExpiryDate: Timestamp.nowUTC().checkedAdd(Duration.days(3)),
        });
        assert.throws(() => {
            validator.validate(presentationJwt, holderDoc, options);
        });

        let holder_did = JwtPresentationValidator.extractHolder(presentationJwt);
        assert.equal(holder_did.toString(), holderDoc.id().toString());
    });

    class CustomVerifier implements IJwsVerifier {
        private _verifications: number;

        constructor() {
            this._verifications = 0;
        }

        public verifications(): number {
            return this._verifications;
        }

        public verify(
            alg: JwsAlgorithm,
            signingInput: Uint8Array,
            decodedSignature: Uint8Array,
            publicKey: Jwk,
        ): void {
            new EdDSAJwsVerifier().verify(alg, signingInput, decodedSignature, publicKey);
            this._verifications += 1;
            return;
        }
    }
});

describe("#OptionParsing", function() {
    it("JwsSignatureOptions can be parsed", () => {
        new JwsSignatureOptions({
            nonce: "nonce",
            attachJwk: true,
            b64: true,
            cty: "type",
            detachedPayload: false,
            kid: "kid",
            typ: "typ",
            url: "https://www.example.com",
        });
    }),
        it("JwsVerificationOptions can be parsed", () => {
            new JwsVerificationOptions({
                nonce: "nonce",
                methodId: "did:iota:0x123",
                methodScope: MethodScope.AssertionMethod(),
            });
        }),
        it("JwtCredentialValidationOptions can be parsed", () => {
            new JwtCredentialValidationOptions({
                // These are equivalent ways of creating a timestamp.
                earliestExpiryDate: new Timestamp(),
                latestIssuanceDate: Timestamp.nowUTC(),
                status: StatusCheck.SkipAll,
                subjectHolderRelationship: ["did:iota:0x123", SubjectHolderRelationship.SubjectOnNonTransferable],
                verifierOptions: new JwsVerificationOptions({
                    nonce: "nonce",
                }),
            });
        });
});

describe("#Documents throw error on concurrent synchronous access", async function() {
    const wait: any = (ms: any) => new Promise(r => setTimeout(r, ms));

    class MyJwkStore extends JwkMemStore {
        constructor() {
            super();
        }

        async generate(keyType: string, algorithm: JwsAlgorithm) {
            await wait(10000);
            return await super.generate(keyType, algorithm);
        }
    }
    it("CoreDocument", async () => {
        const document = new CoreDocument({ id: "did:example:123" });
        const storage = new Storage(new MyJwkStore(), new KeyIdMemStore());
        const insertPromise = document.generateMethod(
            storage,
            JwkMemStore.ed25519KeyType(),
            JwsAlgorithm.EdDSA,
            "#key-1",
            MethodScope.VerificationMethod(),
        );

        const idPromise = wait(10).then((_value: any) => {
            return document.id();
        });

        let resolvedToError = false;
        try {
            await Promise.all([insertPromise, idPromise]);
        } catch (e: any) {
            resolvedToError = true;
            assert.equal(e.name, "TryLockError");
        }
        assert.ok(resolvedToError, "Promise.all did not throw an error");
    });

    it("IotaDocument", async () => {
        const document = new IotaDocument("rms");
        const storage = new Storage(new MyJwkStore(), new KeyIdMemStore());
        const insertPromise = document.generateMethod(
            storage,
            JwkMemStore.ed25519KeyType(),
            JwsAlgorithm.EdDSA,
            "#key-1",
            MethodScope.VerificationMethod(),
        );

        const idPromise = wait(10).then((_value: any) => {
            return document.id();
        });
        let resolvedToError = false;
        try {
            await Promise.all([insertPromise, idPromise]);
        } catch (e: any) {
            resolvedToError = true;
            assert.equal(e.name, "TryLockError");
        }
        assert.ok(resolvedToError, "Promise.all did not throw an error");
    });
});
