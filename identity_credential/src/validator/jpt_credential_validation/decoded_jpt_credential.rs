// Copyright 2020-2024 IOTA Stiftung, Fondazione Links
// SPDX-License-Identifier: Apache-2.0

use identity_core::common::Object;
use jsonprooftoken::jwp::issued::JwpIssued;

use crate::credential::Credential;

/// Decoded [`Credential`] from a cryptographically verified JWP.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct DecodedJptCredential<T = Object> {
  /// The decoded credential parsed to the [Verifiable Credentials Data model](https://www.w3.org/TR/vc-data-model/).
  pub credential: Credential<T>,
  /// The custom claims parsed from the JPT.
  pub custom_claims: Option<Object>,
  /// The decoded and verifier Issued JWP, will be used to construct the Presented JWP
  pub decoded_jwp: JwpIssued,
}
