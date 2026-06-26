import { deactivateIdentity } from "../0_basic/3_deactivate_did";

// Only verifies that no uncaught exceptions are thrown, including syntax errors etc.
describe("Test node examples", function() {
    it("Deactivate identity", async () => {
        await deactivateIdentity();
    });
});
