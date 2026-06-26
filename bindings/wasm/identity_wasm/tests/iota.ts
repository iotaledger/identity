export {};

const assert = require("assert");
import {
    Duration,
    EdCurve,
    IotaDID,
    IotaDocument,
    Jwk,
    JwkType,
    MethodRelationship,
    MethodScope,
    MethodType,
    Service,
    Timestamp,
    VerificationMethod,
} from "../node";

const aliasIdBytes = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
    24, 25, 26, 27, 28, 29, 30, 31, 32]);
const aliasIdHex = "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
const networkName = "smr";
const JWK = new Jwk({
    "kty": JwkType.Okp,
    "crv": EdCurve.Ed25519,
    "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
});

describe("IotaDID", function() {
    describe("#constructor", function() {
        it("should work", () => {
            const did = new IotaDID(aliasIdBytes, networkName);
            assert.deepStrictEqual(did.toString(), "did:" + IotaDID.METHOD + ":" + networkName + ":" + aliasIdHex);
            assert.deepStrictEqual(did.tag(), aliasIdHex);
            assert.deepStrictEqual(did.method(), IotaDID.METHOD);
            assert.deepStrictEqual(did.network(), networkName);
            assert.deepStrictEqual(did.authority(), IotaDID.METHOD + ":" + networkName + ":" + aliasIdHex);
            assert.deepStrictEqual(did.methodId(), networkName + ":" + aliasIdHex);
            assert.deepStrictEqual(did.scheme(), "did");
        });

        it("toCoreDid should work", () => {
            const did = new IotaDID(aliasIdBytes, networkName);
            const coreDid = did.toCoreDid();
            assert.deepStrictEqual(did.toString(), coreDid.toString());
            assert.deepStrictEqual(
                coreDid.toString(),
                "did" + ":" + IotaDID.METHOD + ":" + networkName + ":" + did.tag(),
            );
        });
    });
    describe("#from_alias_id", function() {
        it("should work", () => {
            const did = IotaDID.fromAliasId(aliasIdHex, networkName);
            assert.deepStrictEqual(did.toString(), "did:" + IotaDID.METHOD + ":" + networkName + ":" + aliasIdHex);
            assert.deepStrictEqual(did.tag(), aliasIdHex);
            assert.deepStrictEqual(did.method(), IotaDID.METHOD);
            assert.deepStrictEqual(did.network(), networkName);
            assert.deepStrictEqual(did.authority(), IotaDID.METHOD + ":" + networkName + ":" + aliasIdHex);
            assert.deepStrictEqual(did.methodId(), networkName + ":" + aliasIdHex);
            assert.deepStrictEqual(did.scheme(), "did");
        });
    });
    describe("#placeholder()", function() {
        it("should be zeroes", () => {
            const expectedTag = "0x0000000000000000000000000000000000000000000000000000000000000000";
            const did = IotaDID.placeholder(networkName);
            assert.deepStrictEqual(did.toString(), "did:" + IotaDID.METHOD + ":" + networkName + ":" + expectedTag);
            assert.deepStrictEqual(did.tag(), expectedTag);
            assert.deepStrictEqual(did.method(), IotaDID.METHOD);
            assert.deepStrictEqual(did.network(), networkName);
            assert.deepStrictEqual(did.authority(), IotaDID.METHOD + ":" + networkName + ":" + expectedTag);
            assert.deepStrictEqual(did.methodId(), networkName + ":" + expectedTag);
            assert.deepStrictEqual(did.scheme(), "did");
        });
    });
});

describe("IotaDocument", function() {
    describe("#constructors", function() {
        it("new should generate a placeholder", () => {
            const doc = new IotaDocument(networkName);
            assert.deepStrictEqual(doc.id().toString(), IotaDID.placeholder(networkName).toString());
        });
        it("newWithId should work", () => {
            const did = new IotaDID(aliasIdBytes, networkName);
            const doc = IotaDocument.newWithId(did);
            assert.deepStrictEqual(doc.id().toString(), did.toString());
        });
    });

    describe("#insert/resolve/removeMethod", function() {
        it("should work", async () => {
            const doc = new IotaDocument(networkName);
            const fragment = "new-method-1";
            const scope = MethodScope.AssertionMethod();
            const method = VerificationMethod.newFromJwk(doc.id(), JWK, fragment);
            // Add.
            doc.insertMethod(method, scope);
            // Resolve.
            const resolved = doc.resolveMethod(fragment, scope)!;
            assert.deepStrictEqual(resolved.id().fragment(), fragment);
            assert.deepStrictEqual(resolved.type().toString(), MethodType.JsonWebKey2020().toString());
            assert.deepStrictEqual(resolved.controller().toString(), doc.id().toString());
            assert.deepStrictEqual(resolved.data().tryPublicKeyJwk().toJSON(), JWK.toJSON());
            assert.deepStrictEqual(resolved.toJSON(), method.toJSON());
            assert.deepStrictEqual(doc.resolveMethod(fragment, MethodScope.VerificationMethod()), undefined);
            // List.
            const list = doc.methods();
            assert.deepStrictEqual(list.length, 1);
            assert.deepStrictEqual(list[0].toJSON(), resolved.toJSON());
            // Remove.
            doc.removeMethod(resolved.id());
            assert.deepStrictEqual(doc.resolveMethod(fragment), undefined);
            assert.deepStrictEqual(doc.resolveMethod(fragment, scope), undefined);
            assert.deepStrictEqual(doc.resolveMethod(fragment, MethodScope.VerificationMethod()), undefined);
            assert.deepStrictEqual(doc.methods().length, 0);
        });
    });
    describe("#attach/detachMethodRelationship", function() {
        it("should work", async () => {
            const doc = new IotaDocument(networkName);
            const fragment = "new-method-1";
            const method = VerificationMethod.newFromJwk(doc.id(), JWK, fragment);

            doc.insertMethod(method, MethodScope.VerificationMethod());
            assert.deepStrictEqual(
                doc.resolveMethod(fragment, MethodScope.VerificationMethod())!.toJSON(),
                method.toJSON(),
            );

            // Attach.
            doc.attachMethodRelationship(method.id(), MethodRelationship.Authentication);
            assert.deepStrictEqual(
                doc.resolveMethod(fragment, MethodScope.VerificationMethod())!.toJSON(),
                method.toJSON(),
            );
            assert.deepStrictEqual(
                doc.resolveMethod(fragment, MethodScope.Authentication())!.toJSON(),
                method.toJSON(),
            );
            assert.deepStrictEqual(doc.resolveMethod(fragment, MethodScope.AssertionMethod()), undefined);
            assert.deepStrictEqual(doc.resolveMethod(fragment, MethodScope.CapabilityInvocation()), undefined);
            assert.deepStrictEqual(doc.resolveMethod(fragment, MethodScope.CapabilityDelegation()), undefined);
            assert.deepStrictEqual(doc.resolveMethod(fragment, MethodScope.KeyAgreement()), undefined);

            // Detach.
            doc.detachMethodRelationship(method.id(), MethodRelationship.Authentication);
            assert.deepStrictEqual(
                doc.resolveMethod(fragment, MethodScope.VerificationMethod())!.toJSON(),
                method.toJSON(),
            );
            assert.deepStrictEqual(doc.resolveMethod(fragment, MethodScope.Authentication()), undefined);
            assert.deepStrictEqual(doc.resolveMethod(fragment, MethodScope.AssertionMethod()), undefined);
            assert.deepStrictEqual(doc.resolveMethod(fragment, MethodScope.CapabilityInvocation()), undefined);
            assert.deepStrictEqual(doc.resolveMethod(fragment, MethodScope.CapabilityDelegation()), undefined);
            assert.deepStrictEqual(doc.resolveMethod(fragment, MethodScope.KeyAgreement()), undefined);
        });
    });
    describe("#insert/resolve/removeService", function() {
        it("should work", async () => {
            const doc = new IotaDocument(networkName);

            // Add.
            const fragment1 = "new-service-1";
            const service = new Service({
                id: doc.id().toUrl().join("#" + fragment1),
                type: ["LinkedDomains", "ExampleType"],
                serviceEndpoint: ["https://example.com/", "https://iota.org/"],
            });
            doc.insertService(service);
            // Resolve.
            const resolved = doc.resolveService(fragment1)!;
            assert.deepStrictEqual(resolved.id().fragment(), fragment1);
            assert.deepStrictEqual(resolved.type(), ["LinkedDomains", "ExampleType"]);
            assert.deepStrictEqual(resolved.serviceEndpoint(), ["https://example.com/", "https://iota.org/"]);
            assert.deepStrictEqual(resolved.toJSON(), service.toJSON());
            // List.
            const list = doc.service();
            assert.deepStrictEqual(list.length, 1);
            assert.deepStrictEqual(list[0].toJSON(), resolved.toJSON());
            // Remove
            const removed = doc.removeService(resolved.id())!;
            assert.deepStrictEqual(removed.toJSON(), resolved.toJSON());
            assert.deepStrictEqual(doc.resolveService(fragment1), undefined);
            assert.deepStrictEqual(doc.service().length, 0);
        });
    });
    describe("#metadata", function() {
        it("should work", () => {
            const doc = new IotaDocument(networkName);
            const previousCreated = doc.metadataCreated()!;
            const previousUpdated = doc.metadataUpdated()!;

            // Created.
            const created = Timestamp.nowUTC().checkedAdd(Duration.seconds(1))!;
            doc.setMetadataCreated(created);
            assert.deepStrictEqual(doc.metadataCreated()!.toRFC3339(), created.toRFC3339());
            assert.deepStrictEqual(doc.metadata().created()!.toRFC3339(), created.toRFC3339());
            assert.notDeepStrictEqual(doc.metadataCreated()!.toRFC3339(), previousCreated.toRFC3339());
            assert.deepStrictEqual(doc.metadataUpdated()!.toRFC3339(), previousUpdated.toRFC3339());
            // Updated.
            const updated = Timestamp.nowUTC().checkedAdd(Duration.seconds(42))!;
            doc.setMetadataUpdated(updated);
            assert.deepStrictEqual(doc.metadataUpdated()!.toRFC3339(), updated.toRFC3339());
            assert.deepStrictEqual(doc.metadata().updated()!.toRFC3339(), updated.toRFC3339());
            assert.notDeepStrictEqual(doc.metadataUpdated()!.toRFC3339(), previousUpdated.toRFC3339());
            assert.deepStrictEqual(doc.metadataCreated()!.toRFC3339(), created.toRFC3339());
            // Deactivated.
            assert.deepStrictEqual(doc.metadataDeactivated(), undefined);
            doc.setMetadataDeactivated(true);
            assert.deepStrictEqual(doc.metadataDeactivated(), true);
            doc.setMetadataDeactivated(false);
            assert.deepStrictEqual(doc.metadataDeactivated(), false);
            doc.setMetadataDeactivated(undefined);
            assert.deepStrictEqual(doc.metadataDeactivated(), undefined);
            // Properties.
            assert.deepStrictEqual(doc.metadata().properties(), new Map());
            const properties = new Map();
            properties.set("custom1", "asdf");
            properties.set("custom2", 1234);
            doc.setMetadataPropertyUnchecked("custom1", "asdf");
            doc.setMetadataPropertyUnchecked("custom2", 1234);
            assert.deepStrictEqual(doc.metadata().properties(), properties);
        });
    });
    describe("#properties", function() {
        it("should work", () => {
            const doc = new IotaDocument(networkName);
            assert.deepStrictEqual(doc.properties(), new Map());

            const properties = new Map();
            properties.set("custom1", "asdf");
            properties.set("custom2", 1234);
            doc.setPropertyUnchecked("custom1", "asdf");
            doc.setPropertyUnchecked("custom2", 1234);
            assert.deepStrictEqual(doc.properties(), properties);
        });
    });
    describe("#callingToCoreDid from Rust does not null out IotaDID", function() {
        it("should work", () => {
            const did = new IotaDID(aliasIdBytes, networkName);
            const method = VerificationMethod.newFromJwk(did, JWK, "#key-0");
            assert.deepStrictEqual(did.toString(), "did:" + IotaDID.METHOD + ":" + networkName + ":" + aliasIdHex);
        });
    });
});
