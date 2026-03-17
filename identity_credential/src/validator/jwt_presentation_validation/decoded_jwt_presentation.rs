// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_core::common::Object;
use identity_core::common::StringOrUrl;
use identity_core::common::Timestamp;
use identity_verification::jws::JwsHeader;

use crate::presentation::Presentation;

/// Decoded [`Presentation`] from a cryptographically verified JWS.
///
/// Note that having an instance of this type only means the JWS it was constructed from was verified.
/// It does not imply anything about a potentially present proof property on the presentation itself.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct DecodedJwtPresentation<CRED, T = Object> {
  /// The decoded presentation parsed to the [Verifiable Credentials Data Model v1.1](https://www.w3.org/TR/vc-data-model-1.1/).
  pub presentation: Presentation<CRED, T>,
  /// The protected header parsed from the JWS.
  pub header: Box<JwsHeader>,
  /// The expiration date parsed from the JWT claims.
  pub expiration_date: Option<Timestamp>,
  /// The issuance date parsed from the JWT claims.
  pub issuance_date: Option<Timestamp>,
  /// The `aud` property parsed from the JWT claims.
  pub aud: Option<StringOrUrl>,
  /// The custom claims parsed from the JWT.
  pub custom_claims: Option<Object>,
}
