---
title: Getting Started with Rust
sidebar_label: Getting Started
description: Getting started with the IOTA Identity Rust Library.
image: /img/Identity_icon.png
keywords:
- Rust
- Identity
---

## Requirements

- [Rust](https://www.rust-lang.org/) (>= 1.51)
- [Cargo](https://doc.rust-lang.org/cargo/) (>= 1.51)

## Include the Library

To include IOTA Identity in your project add it as a dependency in your `Cargo.toml`:

### Latest Stable Release

This version matches the `main` branch of this repository. It is **stable** and will have **changelogs**.

```rust
[dependencies]
identity = { git = "https://github.com/iotaledger/identity.rs", branch = "main"}
```

### Development Release

This version matches the `dev` branch of this repository. It has all the **latest features**, but as such it **may also have undocumented breaking changes**.

```rust
[dependencies]
identity = { git = "https://github.com/iotaledger/identity.rs", branch = "dev"}
```


## Examples

To try out the [examples](https://github.com/iotaledger/identity.rs/tree/main/examples), you should:

1. Clone the repository:

```bash
git clone https://github.com/iotaledger/identity.rs
```
2. Build the repository:

```bash
cargo build
```
3. Run your first example:

```bash
cargo run --example getting_started
```

## API Reference

If you would like to build the [API Reference](api_reference) yourself from source, you can do so by running the following command:

```rust
cargo doc --document-private-items --no-deps --open
```
