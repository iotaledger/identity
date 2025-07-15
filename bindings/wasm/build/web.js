const path = require("path");
const fs = require("fs");
const { lintAll } = require("./lints");
const generatePackage = require("./utils/generatePackage");

const artifact = process.argv[2];

const RELEASE_FOLDER = path.join(__dirname, "..", artifact, "web");
const entryFilePath = path.join(RELEASE_FOLDER, `${artifact}.js`);
const entryFile = fs.readFileSync(entryFilePath).toString();
console.log(`[build/web.js] Processing entryFile '${entryFilePath}' for artifact '${artifact}'`);

lintAll(entryFile);

let changedFile = entryFile
    // Comment out generated code as a workaround for webpack (does not recognise import.meta).
    // Regex to avoid hard-coding 'identity_wasm_bg.wasm'.
    .replace(
        /input = new URL\((.*), import\.meta\.url\);/i,
        "// input = new URL($1, import.meta.url);",
    )
    // Create an init function which imports the wasm file.
    .concat(
        `let __initializedIotaWasm = false\r\n\r\nexport function init(path) {\r\n    if (__initializedIotaWasm) {\r\n        return Promise.resolve(wasm)\r\n    }\r\n    return __wbg_init(path || '${artifact}_bg.wasm').then(() => {\r\n        __initializedIotaWasm = true\r\n        return wasm\r\n    })\r\n}\r\n`,
    );

fs.writeFileSync(
    entryFilePath,
    changedFile,
);
console.log(`[build/web.js] Commented out webpack workaround for '${entryFilePath}'.`);

const entryFilePathTs = path.join(RELEASE_FOLDER, `${artifact}.d.ts`);
const entryFileTs = fs.readFileSync(entryFilePathTs).toString();

let changedFileTs = entryFileTs.concat(
    `
/**
* Loads the Wasm file so the lib can be used, relative path to Wasm file
*
* @param {string | undefined} path
*/
export function init (path?: string): Promise<void>;`,
);
fs.writeFileSync(
    entryFilePathTs,
    changedFileTs,
);
console.log(`[build/web.js] Created init function for '${entryFilePathTs}'. Starting generatePackage().`);

// Generate `package.json`.
const newPackage = generatePackage({
    module: "index.js",
    types: "index.d.ts",
    artifact,
});
fs.writeFileSync(path.join(RELEASE_FOLDER, "package.json"), JSON.stringify(newPackage, null, 2));
console.log(`[build/web.js] Finished processing entryFile '${entryFilePathTs}' for artifact '${artifact}'`);
