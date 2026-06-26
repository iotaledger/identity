// Copyright 2020-2024 IOTA Stiftung, Fondazione Links
// SPDX-License-Identifier: Apache-2.0

use identity_core::common::Object;
use identity_core::common::Url;
use jsonprooftoken::jwp::presented::JwpPresented;

use crate::credential::Credential;

/// Decoded [`Credential`] from a cryptographically verified JWP.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct DecodedJptPresentation<T = Object> {
  /// The decoded credential parsed to the [Verifiable Credentials Data model](https://www.w3.org/TR/vc-data-model/).
  pub credential: Credential<T>,
  /// The `aud` property parsed from the JWT claims.
  pub aud: Option<Url>,
  /// The custom claims parsed from the JPT.
  pub custom_claims: Option<Object>,
  /// The decoded and verifier Issued JWP, will be used to construct the Presented JWP
  pub decoded_jwp: JwpPresented,
}
