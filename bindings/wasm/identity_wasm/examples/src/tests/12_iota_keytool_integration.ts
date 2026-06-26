import { iotaKeytoolIntegration } from "../1_advanced/12_iota_keytool_integration";

// Only verifies that no uncaught exceptions are thrown, including syntax errors etc.
describe("Test node examples", function() {
    it("IOTA Keytool Integration", async () => {
        await iotaKeytoolIntegration();
    });
});
