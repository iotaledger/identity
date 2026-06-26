// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! The core types used to create Verifiable Credentials.

#![allow(clippy::module_inception)]

mod builder;
mod credential;
mod credential_v2;
mod enveloped_credential;
mod evidence;
mod issuer;
#[cfg(feature = "jpt-bbs-plus")]
mod jpt;
#[cfg(feature = "jpt-bbs-plus")]
mod jwp_credential_options;
mod jws;
mod jwt;
mod jwt_serialization;
mod linked_domain_service;
mod linked_verifiable_presentation_service;
mod policy;
mod proof;
mod refresh;
#[cfg(feature = "revocation-bitmap")]
mod revocation_bitmap_status;
mod schema;
mod status;
mod subject;

use identity_core::common::Context;
use identity_core::common::Object;
use identity_core::common::OneOrMany;
use identity_core::common::Timestamp;

pub use self::builder::CredentialBuilder;
pub use self::credential::Credential;
pub use self::evidence::Evidence;
pub use self::issuer::Issuer;
#[cfg(feature = "jpt-bbs-plus")]
pub use self::jpt::Jpt;
#[cfg(feature = "jpt-bbs-plus")]
pub use self::jwp_credential_options::JwpCredentialOptions;
pub use self::jws::Jws;
pub use self::jwt::*;
pub use self::jwt_serialization::JwtCredential;
pub use self::linked_domain_service::LinkedDomainService;
pub use self::linked_verifiable_presentation_service::LinkedVerifiablePresentationService;
pub use self::policy::Policy;
pub use self::proof::Proof;
pub use self::refresh::RefreshService;
#[cfg(feature = "revocation-bitmap")]
pub use self::revocation_bitmap_status::try_index_to_u32;
#[cfg(feature = "revocation-bitmap")]
pub use self::revocation_bitmap_status::RevocationBitmapStatus;
pub use self::schema::Schema;
pub use self::status::Status;
pub use self::subject::Subject;
pub use credential_v2::Credential as CredentialV2;
pub use enveloped_credential::*;

#[cfg(feature = "validator")]
pub(crate) use self::jwt_serialization::CredentialJwtClaims;
#[cfg(feature = "presentation")]
pub(crate) use self::jwt_serialization::IssuanceDateClaims;

trait CredentialSealed {}

/// A VerifiableCredential type. This trait is implemented for [Credential]
/// and for [CredentialV2](credential_v2::Credential).
#[allow(private_bounds)]
pub trait CredentialT: CredentialSealed {
  /// The type of the custom claims.
  type Properties;

  /// The Credential's context.
  fn context(&self) -> &OneOrMany<Context>;
  /// The Credential's types.
  fn type_(&self) -> &OneOrMany<String>;
  /// The Credential's subjects.
  fn subject(&self) -> &OneOrMany<Subject>;
  /// The Credential's issuer.
  fn issuer(&self) -> &Issuer;
  /// The Credential's issuance date.
  fn valid_from(&self) -> Timestamp;
  /// The Credential's expiration date, if any.
  fn valid_until(&self) -> Option<Timestamp>;
  /// The Credential's validity status, if any.
  fn status(&self) -> Option<&Status>;
  /// The Credential's custom properties.
  fn properties(&self) -> &Self::Properties;
  /// Whether the Credential's `nonTransferable` property is set.
  fn non_transferable(&self) -> bool;
  /// The Credential's base context.
  fn base_context(&self) -> &'static Context;
  /// Serializes this credential as a JWT payload encoded string.
  fn serialize_jwt(&self, custom_claims: Option<Object>) -> Result<String, crate::Error>;
}
