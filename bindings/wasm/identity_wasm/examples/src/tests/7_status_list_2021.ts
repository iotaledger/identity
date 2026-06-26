import { statusList2021 } from "../1_advanced/7_status_list_2021";

// Only verifies that no uncaught exceptions are thrown, including syntax errors etc.
describe("Test node examples", function() {
    it("StatusList2021", async () => {
        await statusList2021();
    });
});
