![banner](https://github.com/iotaledger/identity/raw/HEAD/.github/banner_identity.svg)

<p align="center">
  <a href="https://iota.stackexchange.com/" style="text-decoration:none;"><img src="https://img.shields.io/badge/StackExchange-9cf.svg?logo=stackexchange" alt="StackExchange"></a>
  <a href="https://discord.iota.org/" style="text-decoration:none;"><img src="https://img.shields.io/badge/Discord-9cf.svg?logo=discord" alt="Discord"></a>
  <a href="https://github.com/iotaledger/identity/blob/HEAD/LICENSE" style="text-decoration:none;"><img src="https://img.shields.io/github/license/iotaledger/identity.svg" alt="Apache 2.0 license"></a>
  <img src="https://deps.rs/repo/github/iotaledger/identity/status.svg" alt="Dependencies">
  <a href='https://coveralls.io/github/iotaledger/identity?branch=main'><img src='https://coveralls.io/repos/github/iotaledger/identity/badge.svg?branch=main' alt='Coverage Status' /></a>

</p>

<p align="center">
  <a href="#introduction">Introduction</a> ◈
  <a href="#documentation-and-resources">Documentation & Resources</a> ◈
  <a href="#bindings">Bindings</a> ◈
  <a href="#grpc">gRPC</a> ◈
  <a href="#roadmap-and-milestones">Roadmap</a> ◈
  <a href="#contributing">Contributing</a>
</p>

---

> [!NOTE]
> This version of the library is compatible with IOTA Rebased networks and in active development, for a version of the library compatible with IOTA Stardust networks check [here](https://github.com/iotaledger/identity/tree/support/v1.5)

## Introduction

IOTA Identity is a [Rust](https://www.rust-lang.org/) implementation of decentralized digital identity, also known as Self-Sovereign Identity (SSI). It implements the W3C [Decentralized Identifiers (DID)](https://www.w3.org/TR/did-core/) and [Verifiable Credentials](https://www.w3.org/TR/vc-data-model/) specifications. This library can be used to create, resolve and authenticate digital identities and to create verifiable credentials and presentations in order to share information in a verifiable manner and establish trust in the digital world. It does so while supporting secure storage of cryptographic keys, which can be implemented for your preferred key management system. Many of the individual libraries (Rust crates) are agnostic over the concrete DID method, with the exception of some libraries dedicated to implement the [IOTA DID method](https://docs.iota.org/references/iota-identity/iota-did-method-spec/), which is an implementation of decentralized digital identity on IOTA Rebased networks. Written in stable Rust, IOTA Identity has strong guarantees of memory safety and process integrity while maintaining exceptional performance.

## Documentation and Resources

- [Identity Documentation Pages](https://docs.iota.org/iota-identity): Supplementing documentation with context around identity and simple examples on library usage.
- API References:
  - [Rust API Reference](https://iotaledger.github.io/identity/identity_iota/index.html): Package documentation (cargo docs).
  - [Wasm API Reference](https://docs.iota.org/references/iota-identity/wasm/api_ref): Wasm Package documentation.
- Examples:
  - [Rust Examples](https://github.com/iotaledger/identity/tree/main/examples): Practical code snippets to get you started with the library in Rust.
  - [Wasm Examples](https://github.com/iotaledger/identity/tree/main/bindings/wasm/identity_wasm/examples): Practical code snippets to get you started with the library in TypeScript/JavaScript.

## Bindings

[Foreign Function Interface (FFI)](https://en.wikipedia.org/wiki/Foreign_function_interface) Bindings of this [Rust](https://www.rust-lang.org/) library to other programming languages:

- [Web Assembly](https://github.com/iotaledger/identity/tree/main/bindings/wasm/identity_wasm/) (JavaScript/TypeScript)

## gRPC

We provide a collection of experimental [gRPC services](https://github.com/iotaledger/identity/tree/main/bindings/grpc/)

## Roadmap and Milestones

For detailed development progress, see the IOTA Identity development [kanban board](https://github.com/orgs/iotaledger/projects/8/views/5).

## Contributing

We would love to have you help us with the development of IOTA Identity. Each and every contribution is greatly valued!

Please review the [contribution](https://docs.iota.org/iota-identity/contribute) sections in the [IOTA Docs Portal](https://docs.iota.org/iota-identity).

To contribute directly to the repository, simply fork the project, push your changes to your fork and create a pull request to get them included!

The best place to get involved in discussions about this library or to look for support at is the `#identity` channel on the [IOTA Discord](https://discord.iota.org). You can also ask questions on our [Stack Exchange](https://iota.stackexchange.com/).
