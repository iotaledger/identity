import { updateIdentity } from "../0_basic/1_update_did";

// Only verifies that no uncaught exceptions are thrown, including syntax errors etc.
describe("Test node examples", function() {
    it("Update Identity", async () => {
        await updateIdentity();
    });
});
