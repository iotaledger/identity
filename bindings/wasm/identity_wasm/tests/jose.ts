export {};
const assert = require("assert");
import { EdCurve, IJwkParams, Jwk, JwkOperation, JwkType, JwkUse, JwsAlgorithm } from "../node";

describe("Jwk", function() {
    describe("#constructor and getters", function() {
        it("should work", () => {
            const iJwk: IJwkParams = {
                kty: JwkType.Okp,
                use: JwkUse.Signature,
                alg: JwsAlgorithm.EdDSA,
                key_ops: [JwkOperation.Sign, JwkOperation.Verify],
                crv: EdCurve.Ed25519,
                d: "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
                x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            };
            const jwk = new Jwk(iJwk);

            const paramsOkp = jwk.paramsOkp();
            assert.ok(paramsOkp);
            assert.deepStrictEqual(paramsOkp!.d, iJwk.d);
            assert.deepStrictEqual(paramsOkp!.x, iJwk.x);
            assert.deepStrictEqual(paramsOkp!.crv, iJwk.crv);
            assert.ok(!jwk.isPublic());
            assert.ok(jwk.isPrivate());

            const publicJwk = jwk.toPublic()!;
            assert.ok(publicJwk.isPublic());
            assert.ok(!publicJwk.isPrivate());
        });
    });
});
