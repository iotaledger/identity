---
title: IOTA DIDComm Specification
sidebar_label: Overview
---

:::info

The IOTA DIDComm Specification is in the RFC phase and may undergo changes. Suggestions are welcome at [GitHub #464](https://github.com/iotaledger/identity.rs/discussions/464).

:::

- Version: 0.1
- Status: `IN-PROGRESS`
- Last Updated: 2021-10-29

## Introduction

The IOTA DIDComm Specification standardizes how Self-Sovereign Identities (SSIs) can interact with each other and exchange information. Any applications that implement this standard will naturally be interoperable with each other. This reduces fragmentation in the ecosystem and therefore it is highly recommended to use this for any application built on top of the IOTA Identity framework. The specification defines several [protocols](#protocols), that can be used for common interactions like [issuing](./protocols/issuance) and [presenting](./protocols/presentation) verifiable credentials as well as supporting functions, such as [connection](./protocols/connection) establishment and [authentication](./protocols/authentication.md). Cross-cutting concerns like [error handling](./resources/problem-reports.md) and [credential negotiation](./resources/credential-info.md) are discussed in the [resources](#resources) section.

The IOTA DIDComm Specification builds on the [DIDComm Messaging Specification](https://identity.foundation/didcomm-messaging/spec/) developed by the [Decentralized Identity Foundation (DIF)](https://identity.foundation/) and utilises [external protocols](#external-protocols) from the messaging specification for well-established interactions like feature discovery.

This specification is meant to be a complete solution for common use cases and therefore contains protocols for common SSI interactions. It is possible to extend the specification with custom protocols and custom methods in existing protocols to support application-specific requirements. 

The specification itself is technology agnostic. Much like the [DIDComm Messaging Specification](https://identity.foundation/didcomm-messaging/spec/) there are no restrictions on transport layers and a concrete implementation can be done with many different technologies.

## Conformance

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL
NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",  "MAY", and
"OPTIONAL" in this specification are to be interpreted as described in
[BCP 14](https://www.rfc-editor.org/info/bcp14)[[RFC 2119]](https://www.rfc-editor.org/rfc/rfc2119.txt).

## Versioning

Protocols follow [Semantic Versioning 2.0](https://semver.org/) conventions.

## Protocols

The specification defines several [DIDComm protocols](https://identity.foundation/didcomm-messaging/spec/#protocols) that can be used for common SSI interactions:

| Name | Version | Description | 
| :--- | :---: | :--- |
| [Connection](./protocols/connection.md) | 0.1 | Establishes a [DIDComm connection](https://identity.foundation/didcomm-messaging/spec/#connections) between two parties. |
| [Authentication](./protocols/authentication.md) | 0.1 | Allows two parties to mutually authenticate, verifying the DID of each other. |
| [Presentation](./protocols/presentation.md) | 0.1 | Allows presentation of verifiable credentials that are issued to a holder and uniquely presented to a third-party verifier. |
| [Issuance](./protocols/issuance.md) | 0.1 | Allows the exchange of a verifiable credential between an issuer and a holder. | 
| [Signing](./protocols/signing.md) | 0.1 | Allows a trusted-party to request the signing of an unsigned verifiable credential by an issuer. |
| [Revocation](./protocols/revocation.md) | 0.1 | Allows to request revocation of an issued credential, either by the holder or a trusted-party. |
| [Revocation Options](./protocols/revocation-options.md) | 0.1 | Allows discovery of available [`RevocationInfo`](./protocols/revocation#RevocationInfo) types for use with the [revocation](./protocols/revocation) protocol. |
| [Post](./protocols/post.md) | 0.1 | Allows the sending of a single message with arbitrary data. |
| [Termination](./protocols/termination.md) | 0.1 | Indicates the graceful termination of a connection. |

## External Protocols

In addition to the protocols defined in this specification, we RECOMMEND implementors use the following well-known protocols:

| Name | Version | Description |
| :--- | :---: | :--- | 
| [Discover Features](https://github.com/decentralized-identity/didcomm-messaging/blob/ef997c9d3cd1cd24eb182ffa2930a095d3b856a9/docs/spec-files/feature_discovery.md) | 2.0 | Describes how agents can query one another to discover which features they support, and to what extent. |
| [Trust Ping](https://github.com/decentralized-identity/didcomm-messaging/blob/9039564e143380a0085a788b6dfd20e63873b9ca/docs/spec-files/trustping.md) | 1.0 | A standard way for agents to test connectivity, responsiveness, and security of a DIDComm channel. | 

## Resources

Additionally, general guidelines on concerns across protocols are provided:

| Name | Description |
| :--- | :--- |
| [Problem Reports](./resources/problem-reports.md) | Definitions of expected problem reports and guidance on global handling. |
| [Credential Info](./resources/credential-info.md) | Definition of methods to negotiate a specific kind of verifiable credential. |

## Diagrams

The diagrams in this specification follow the [BPMN 2.0](https://www.omg.org/spec/BPMN/2.0/) notation. The diagrams are created with https://www.diagrams.net, the source is embedded in the `.svg` files.

## Changelog

See [CHANGELOG](./CHANGELOG).

## Future Work

◈ If necessary, discuss ways for some agent to request the start of an interaction. This has narrow use cases, but might be interesting in the long run.
◈ Add section or article on anonymous encryption, sender authenticated encryption, signed messages. Include a table of comparisons with guarantees? E.g. authentication, eavesdropping protection, integrity etc.
