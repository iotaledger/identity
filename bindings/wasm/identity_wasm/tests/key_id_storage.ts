const assert = require("assert");
import { CoreDID, EdCurve, Jwk, JwkType, KeyIdMemStore, MethodDigest, VerificationMethod } from "../node";

describe("Method digest", () => {
    it("should have consistent hashing", () => {
        let verificationMethodJson = {
            id: "did:example:HHoh9NQC9AUsK15Jyyq53VTujxEUizKDXRXd7zbT1B5u#frag_1",
            controller: "did:example:HHoh9NQC9AUsK15Jyyq53VTujxEUizKDXRXd7zbT1B5u",
            type: "Ed25519VerificationKey2018",
            publicKeyMultibase: "zHHoh9NQC9AUsK15Jyyq53VTujxEUizKDXRXd7zbT1B5u",
        };

        let verificationMethod = VerificationMethod.fromJSON(
            verificationMethodJson,
        );
        let methodDigest = new MethodDigest(verificationMethod);

        let packed = methodDigest.pack();
        // Packed bytes must be consistent between Rust and Wasm, see Rust tests for `MethodDigest`.
        let packedExpected = new Uint8Array([
            0,
            74,
            60,
            10,
            199,
            76,
            205,
            180,
            133,
        ]);
        assert.deepStrictEqual(packed, packedExpected);
    });
});

describe("Key Id Storage", () => {
    it("should work", async () => {
        const KEY_ID = "my-key-id";
        let vm: VerificationMethod = createVerificationMethod();
        let methodDigest: MethodDigest = new MethodDigest(vm);

        let memstore = new KeyIdMemStore();

        // Deletion of non saved key id results in error.
        assert.rejects(memstore.deleteKeyId(methodDigest));

        // Store key id.
        await memstore.insertKeyId(methodDigest, KEY_ID);

        // Double insertion results in error.
        assert.rejects(memstore.insertKeyId(methodDigest, KEY_ID));

        // Restore key id from a `MethodDigest` with the same data but not the same reference.
        let methodDigestClone = MethodDigest.unpack(methodDigest.pack());
        let key_id_restored: string = await memstore.getKeyId(methodDigestClone);

        // Check restored key id.
        assert.equal(KEY_ID, key_id_restored);

        // Delete stored key id.
        await memstore.deleteKeyId(methodDigest);

        // Double deletion results in error.
        assert.rejects(memstore.deleteKeyId(methodDigest));
    });
});

export function createVerificationMethod(): VerificationMethod {
    let id = CoreDID.parse("did:example:abc123");
    const jwk = new Jwk({
        kty: JwkType.Okp,
        crv: EdCurve.Ed25519,
        x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
    });
    const method = VerificationMethod.newFromJwk(id, jwk, "#key-1");
    return method;
}
