import { zkp_revocation } from "../1_advanced/9_zkp_revocation";

// Only verifies that no uncaught exceptions are thrown, including syntax errors etc.
describe("Test node examples", function() {
    it("zkp_revocation", async () => {
        await zkp_revocation();
    });
});
