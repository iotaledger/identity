import { domainLinkage } from "../1_advanced/5_domain_linkage";

// Only verifies that no uncaught exceptions are thrown, including syntax errors etc.
describe("Test node examples", function() {
    it("Domain Linkage", async () => {
        await domainLinkage();
    });
});
