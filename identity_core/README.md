IOTA Identity - Core  
===

The core types and utilities for IOTA identity.

The types and traits exposed by this crate are mainly intended to be used by the other crates constituting the [IOTA Identity Framework](https://docs.iota.org/iota-identity).

## Common Data Types

This crate exposes some fundamental data types used across the IOTA Identity Framework:

- [`Context`](crate::common::Context): represents [JSON-LD contexts](https://www.w3.org/TR/vc-data-model/#contexts).
- [`Timestamp`](crate::common::Timestamp): an [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339) compliant timestamp.
- [`Url`](crate::common::Url): a URL string.
- Collections: [`OneOrMany`](crate::common::OneOrMany), [`OneOrSet`](crate::common::OneOrSet), and [`OrderedSet`](crate::common::OrderedSet).

The above types are located in the [`common` module](crate::common).

## Convenient JSON Serialization

The [`ToJson`](crate::convert::ToJson) and [`FromJson`](crate::convert::FromJson) traits from this crate provide convenience functions to convert most types from the IOTA Identity Framework to and from a few common JSON representations.

## Base Encoding Utilities

[`BaseEncoding`](crate::convert::BaseEncoding) provides methods to encode and decode binary text with respect to several bases.
