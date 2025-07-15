import { sdJwtVc } from "../1_advanced/10_sd_jwt_vc";

// Only verifies that no uncaught exceptions are thrown, including syntax errors etc.
describe("Test node examples", function() {
    it("SD-JWT VC", async () => {
        await sdJwtVc();
    });
});
