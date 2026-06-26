import { zkp } from "../1_advanced/8_zkp";

// Only verifies that no uncaught exceptions are thrown, including syntax errors etc.
describe("Test node examples", function() {
    it("zkp", async () => {
        await zkp();
    });
});
