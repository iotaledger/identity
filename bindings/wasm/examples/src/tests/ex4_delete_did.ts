import { deactivateIdentity } from "../3_deactivate_did";

// Only verifies that no uncaught exceptions are thrown, including syntax errors etc.
describe("Test node examples", function () {
    it("Deactivate Identity", async () => {
        await deactivateIdentity();
    });
})
