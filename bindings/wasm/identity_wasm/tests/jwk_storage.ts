const assert = require("assert");
import { EdCurve, IJwkParams, Jwk, JwkMemStore, JwkOperation, JwkType, JwkUse, JwsAlgorithm } from "../node";

describe("#JwkMemstore", function() {
    it("should work", async () => {
        const testData = Uint8Array.from([0xff, 0xee, 0xdd, 0xcc]);
        const memstore = new JwkMemStore();

        let genOutput = await memstore.generate(JwkMemStore.ed25519KeyType(), JwsAlgorithm.EdDSA);
        const keyId = genOutput.keyId();
        const jwk = genOutput.jwk();
        assert.ok(genOutput.jwk());
        assert.ok(keyId);

        const signature = await memstore.sign(keyId, testData, jwk.toPublic()!);
        // Ed25519 Signature Length = 64.
        assert.deepStrictEqual(signature.length, 64);

        assert.ok(await memstore.exists(keyId));
        assert.ok(!await memstore.exists("non-existent-key-id"));

        assert.doesNotReject(async () => {
            await memstore.delete(keyId);
        });
        assert.rejects(async () => {
            await memstore.delete("non-existent-key-id");
        });

        const jwkParams: IJwkParams = {
            kty: JwkType.Okp,
            use: JwkUse.Signature,
            alg: JwsAlgorithm.EdDSA,
            key_ops: [JwkOperation.Sign, JwkOperation.Verify],
            crv: EdCurve.Ed25519,
            d: "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
            x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        };

        const localJwk = new Jwk(jwkParams);
        assert.ok(await memstore.insert(localJwk));

        const pubLocalJwk = new Jwk({
            ...jwkParams,
            // Null out the private key component
            d: undefined,
        });

        // INVALID: Inserting a JWK without the private key component should fail.
        assert.rejects(async () => {
            await memstore.insert(pubLocalJwk);
        });
    });
});
