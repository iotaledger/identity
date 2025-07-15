const path = require("path");
const fs = require("fs");
const { lintAll } = require("./lints");
const generatePackage = require("./utils/generatePackage");

const artifact = process.argv[2];

const RELEASE_FOLDER = path.join(__dirname, "..", artifact, "node");
const entryFilePathNode = path.join(RELEASE_FOLDER, `${artifact}.js`);
const entryFileNode = fs.readFileSync(entryFilePathNode).toString();
console.log(`[build/node.js] Processing entryFile '${entryFilePathNode}' for artifact '${artifact}'`);

lintAll(entryFileNode);

// Add node-fetch polyfill (https://github.com/seanmonstar/reqwest/issues/910).
let changedFileNode = entryFileNode.replace(
    "let imports = {};",
    `if (!globalThis.fetch) {
    const fetch = require('node-fetch')
    globalThis.Headers = fetch.Headers
    globalThis.Request = fetch.Request
    globalThis.Response = fetch.Response
    globalThis.fetch = fetch
}
let imports = {};`,
);

fs.writeFileSync(
    entryFilePathNode,
    changedFileNode,
);
console.log(
    `[build/node.js] Added node-fetch polyfill to entryFile '${entryFilePathNode}'. Starting generatePackage().`,
);

// Generate `package.json`.
const newPackage = generatePackage({
    main: "index.js",
    types: "index.d.ts",
    artifact,
});
fs.writeFileSync(path.join(RELEASE_FOLDER, "package.json"), JSON.stringify(newPackage, null, 2));
console.log(`[build/node.js] Finished processing entryFile '${entryFilePathNode}' for artifact '${artifact}'`);
