// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! The core types used to create Verifiable Credentials.

#![allow(clippy::module_inception)]

mod builder;
mod credential;
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

pub use self::builder::CredentialBuilder;
pub use self::credential::Credential;
pub use self::evidence::Evidence;
pub use self::issuer::Issuer;
#[cfg(feature = "jpt-bbs-plus")]
pub use self::jpt::Jpt;
#[cfg(feature = "jpt-bbs-plus")]
pub use self::jwp_credential_options::JwpCredentialOptions;
pub use self::jws::Jws;
pub use self::jwt::Jwt;
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

#[cfg(feature = "validator")]
pub(crate) use self::jwt_serialization::CredentialJwtClaims;
#[cfg(feature = "presentation")]
pub(crate) use self::jwt_serialization::IssuanceDateClaims;
