const fs = require("fs");
const path = require("path");

/**
 * Replaces aliases defined in the `tsconfig.json` `paths` configuration in `js` and `ts` files.
 * If more than one path is defined. The second path is used. Otherwise the first path.
 * @param {string} tsconfig - Path to tsconfig that should be processed
 * @param {string} dist - Folder of files that should be processed
 * @param {string} artifact - Name of the artifact folder. Example: "indentity_wasm"
 * @param {'resolve'=} mode - In "resolve" mode relative paths will be replaced paths relative to the processed file. Note: `basePath` in the tsconfig will not be considered.
 */

function replace(tsconfig, dist, artifact, mode) {
    // Read tsconfig file.
    const tsconfigPath = path.join(__dirname, "..", artifact, tsconfig);
    console.log(`\n using ${tsconfigPath}`);
    let data = JSON.parse(fs.readFileSync(tsconfigPath, "utf8"));
    let a = data.compilerOptions.paths;
    let keys = Object.keys(a);

    // Get `.js` and `.ts` file names from directory.
    const distPath = path.join(__dirname, "..", artifact, dist);
    console.log(`\n working in ${distPath}`);
    let files = readdirSync(distPath);
    files = files.filter((fileName) => fileName.endsWith(".ts") || fileName.endsWith(".js"));

    // Replace the Alias with the second path if present, otherwise use first path.
    for (let file of files) {
        console.log(`\n processing ${file}`);
        let fileData = fs.readFileSync(file, "utf8");
        for (let key of keys) {
            let value = a[key][1] ?? a[key][0];

            const absoluteIncludePath = path.resolve(path.dirname(tsconfigPath), value);
            if (mode == "resolve" && fs.existsSync(absoluteIncludePath)) {
                const absoluteFilePath = path.resolve(path.dirname(file));
                console.log(`\t calculating path from ${absoluteFilePath} to ${absoluteIncludePath}`);
                // replace `\` with `/` to convert windows paths to node compatible imports
                value = path.relative(absoluteFilePath, absoluteIncludePath).replace(/\\/g, "/");
            }

            if(key.endsWith('*')) {
                console.log(`\t dropping '*' from ${key}`);
                key = key.slice(0, -1);
            }

            console.log(`\t replace ${key} with ${value}`);
            fileData = fileData.replaceAll(key, value);
        }
        fs.writeFileSync(file, fileData, "utf8");
    }
}

const readdirSync = (p, a = []) => {
    if (fs.statSync(p).isDirectory()) {
        fs.readdirSync(p).map(f => readdirSync(a[a.push(path.join(p, f)) - 1], a));
    }
    return a;
};

replace(process.argv[2], process.argv[3], process.argv[4], process.argv[5]);
