import { sdJwt } from "../1_advanced/6_sd_jwt";

// Only verifies that no uncaught exceptions are thrown, including syntax errors etc.
describe("Test node examples", function() {
    it("Domain Linkage", async () => {
        await sdJwt();
    });
});
