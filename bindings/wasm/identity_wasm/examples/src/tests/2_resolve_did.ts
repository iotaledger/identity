import { resolveIdentity } from "../0_basic/2_resolve_did";

// Only verifies that no uncaught exceptions are thrown, including syntax errors etc.
describe("Test node examples", function() {
    it("Resolve Identity", async () => {
        await resolveIdentity();
    });
});
