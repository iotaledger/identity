import { revokeVC } from "../0_basic/7_revoke_vc";

// Only verifies that no uncaught exceptions are thrown, including syntax errors etc.
describe("Test node examples", function() {
    it("Revoke VC", async () => {
        await revokeVC();
    });
});
