import { createVC } from "../0_basic/5_create_vc";

// Only verifies that no uncaught exceptions are thrown, including syntax errors etc.
describe("Test node examples", function() {
    it("Create VC", async () => {
        await createVC();
    });
});
