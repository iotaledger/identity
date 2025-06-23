# IOTA Identity WASM

## [Identity Documentation Pages](https://docs.iota.org/iota-identity)

## [Getting started with the IOTA Identity WASM Library.](https://docs.iota.org/iota-identity/getting-started/wasm)

## [API Reference](https://docs.iota.org/references/iota-identity/wasm/api_ref)

## [Examples](https://github.com/iotaledger/identity/tree/main/bindings/wasm/identity_wasm/examples/README.md)

## Install the Library

If your project does not contain it already, install the peer dependency `@iota/iota-sdk` as well.

```bash npm2yarn
npm install @iota/iota-sdk
```

You can install the latest alpha version of the library by running the following command:

```bash npm2yarn
npm install @iota/identity-wasm@alpha
```

## Build the Library

Alternatively, you can build the bindings yourself if you have Rust installed. If not, refer
to [rustup.rs](https://rustup.rs) for the installation.

### Requirements

- [Node.js](https://nodejs.org/en) (>= `v20`)
- [Rust](https://www.rust-lang.org/) (>= 1.65)
- [Cargo](https://doc.rust-lang.org/cargo/) (>= 1.65)
- for running example: a local network node with the IOTA identity package deployed as described [here](./local-network-setup.md)

### 1. Install `wasm-bindgen-cli`

If you want to build the library from source,
you will first need to manually install [`wasm-bindgen-cli`](https://github.com/rustwasm/wasm-bindgen).
A manual installation is required because we use the [Weak References](https://rustwasm.github.io/wasm-bindgen/reference/weak-references.html) feature,
which [`wasm-pack` does not expose](https://github.com/rustwasm/wasm-pack/issues/930).

```bash
cargo install --force wasm-bindgen-cli
```

### 2. Install Dependencies

After installing `wasm-bindgen-cli`, you can install the necessary dependencies using the following command:

```bash
npm install
```

### 3. Build

You can build the bindings for `node.js` using the following command:

```bash npm2yarn
npm run build:nodejs
```

<!--

You can build the bindings for the `web` using the following command:

```bash npm2yarn
npm run build:web
```

-->
