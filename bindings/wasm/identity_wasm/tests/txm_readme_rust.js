const assert = require("assert");
const spawn = require("child_process").spawn;

describe("Test TXM", () => {
    before((done) => {
        let process = spawn("txm", ["../../../README.md"]);
        process.stdout.on("data", function(data) {
            console.log(data.toString());
        });
        process.stderr.on("data", function(data) {
            console.log(data.toString());
        });
        process.on("exit", (code) => {
            exitCode = code;
            done();
        });
    });
    it("exit code should be zero", () => {
        assert.equal(exitCode, 0);
    });
});
