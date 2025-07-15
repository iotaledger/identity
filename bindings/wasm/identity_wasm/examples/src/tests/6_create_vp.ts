import { createVP } from "../0_basic/6_create_vp";

// Only verifies that no uncaught exceptions are thrown, including syntax errors etc.
describe("Test node examples", function() {
    it("Create VP", async () => {
        await createVP();
    });
});
