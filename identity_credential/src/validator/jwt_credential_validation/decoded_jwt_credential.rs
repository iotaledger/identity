// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::credential::credential_v2::Credential as CredentialV2;
use crate::credential::Credential;
use identity_core::common::Object;
use identity_verification::jose::jws::JwsHeader;

/// Decoded [`Credential`] from a cryptographically verified JWS.
///
/// Note that having an instance of this type only means the JWS it was constructed from was verified.
/// It does not imply anything about a potentially present proof property on the credential itself.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct DecodedJwtCredential<T = Object> {
  /// The decoded credential parsed to the [Verifiable Credentials Data model](https://www.w3.org/TR/vc-data-model/).
  pub credential: Credential<T>,
  /// The protected header parsed from the JWS.
  pub header: Box<JwsHeader>,
  /// The custom claims parsed from the JWT.
  pub custom_claims: Option<Object>,
}

/// Decoded [`CredentialV2`] from a cryptographically verified JWS.
///
/// Note that having an instance of this type only means the JWS it was constructed from was verified.
/// It does not imply anything about a potentially present proof property on the credential itself.
pub struct DecodedJwtCredentialV2<T = Object> {
  /// The decoded credential parsed to the [Verifiable Credentials Data model](https://www.w3.org/TR/vc-data-model/).
  pub credential: CredentialV2<T>,
  /// The protected header parsed from the JWS.
  pub header: Box<JwsHeader>,
  /// The custom claims parsed from the JWT.
  pub custom_claims: Option<Object>,
}
