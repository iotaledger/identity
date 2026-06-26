# WASM build projects using wasm-bindgen

This folder contains several crates using wasm-bindgen to import or export TS types from & to JS runtimes. These crates
are named _artifact_ in the following to indicate that the NodeJS based JS build system is used instead of cargo.

The `build` folder provides build scripts needed to build the artifacts.

Here is an overview of the existing artifacts:

* `identity_wasm`<br>
  Exports the IdentityClient to TypeScript using wasm-bindgen generated wasm bindings

* `iota_move_calls_ts`<br>
  Imports TypeScript IOTA Client SDK types using wasm-bindgen generated wasm bindings
  and implements identity_iota_move_calls traits for wasm32 platforms.

## Building an Artifact

For build instructions please have a look into the artifact README file.

## Build process in general

Each artifact is located in its own artifact folder (see above) containing the following important files and subfolders:

* `tsconfig` files for the `nodejs` and `web` runtimes
* The `package.json` file
* `lib` folder<br>
  Contains TS files used for wasm-bindings
    * Contains `tsconfig` files for the `nodejs` and `web` runtimes with additional TS compiler configurations
* `node` folder<br>
  Distribution folder for the `nodejs` runtime
* `web` folder<br>
  Distribution folder for the `web` runtime
* `src` folder<br>
  Rust code of the crate/artifact
* `tests` folder<br>
  Test code
* `examples` folder<br>
  Example code

The build process is defined by run scripts contained in the artifacts `package.json` file.
The build process for the `nodejs` and `web` runtimes, consists of the following steps:

* cargo build of the crate with target wasm32-unknown-unknown
* wasm-bindgen CLI call, generating `___.js` and `___.d.ts` files in the distribution folder of the artifact (`node` or
  `web`)
* execute the `build/node` or `build/web` build script (see below)
* typescript transpiler call (tsc)<br>
  Converts the TS files in the `lib` folder into JS files.
  JS files are written into the distribution folder of the artifact.
  The distribution folder is configured
  in the applied tsconfig file (located in the `lib` folder of the artifact).
* execute the `build/replace_paths` build script (see below)

## Build scripts contained in the `build` folder

### node.js

Used by the `bundle:nodejs` run task in the package.json file of the artifact.

Process steps:

* Add a [node-fetch polyfill](https://github.com/seanmonstar/reqwest/issues/910)
  at the top of the main js file of the artifact
* Generate a `package.json` file derived from the original package.json of the artifact
  (done by `utils/generatePackage.js`)

### web.js

Used by the `bundle:web` run task in the package.json file of the artifact.

Process steps:

* In the main js file of the artifact:
    * Comment out a webpack workaround by commenting out all occurrences of<br>
      `input = new URL(<SOME_CAPTURED_REGEX_GROUP>, import.meta.url);`
    * Create an init function which imports the artifact wasm file.
* In the typescript source map file `<ARTIFACT_NAME>.d.ts`:
    * Adds the declaration of the above created init function to the typescript source map file
* Generate a `package.json` file derived from the original package.json file of the artifact
  (done by `utils/generatePackage.js`)

### replace_paths.js

Processes all JS and TS files contained in the artifact distribution folder that have previously been created
by wasm-bindgen and the TS compiler (tsc) call.

For each file, it replaces aliases defined in the
[compilerOptions.paths](https://www.typescriptlang.org/docs/handbook/modules/reference.html#paths)
configuration of a specific
tsconfig file by the last entry of the aliases path list (only 1 or 2 paths supported).

It is used by the following run tasks for the following tsconfig files and distribution folders:

| run task             | tsconfig file                  | distribution folder |
|----------------------|--------------------------------|---------------------|
| `bundle:nodejs`      | `./lib/tsconfig.json`          | `node`              |
| `bundle:web`         | `./lib/tsconfig.web.json`      | `web`               |
| `build:examples:web` | `./examples/tsconfig.web.json` | `./examples/dist`   |
