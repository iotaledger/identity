// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! The core types used to create Verifiable Presentations.

#![allow(clippy::module_inception)]

#[cfg(feature = "jpt-bbs-plus")]
mod jwp_presentation_builder;
#[cfg(feature = "jpt-bbs-plus")]
mod jwp_presentation_options;
mod jwt_presentation_options;
mod jwt_serialization;
mod presentation;
mod presentation_builder;

#[cfg(feature = "jpt-bbs-plus")]
pub use self::jwp_presentation_builder::SelectiveDisclosurePresentation;
pub use self::jwt_presentation_options::JwtPresentationOptions;
pub use self::presentation::Presentation;
pub use self::presentation_builder::PresentationBuilder;
#[cfg(feature = "jpt-bbs-plus")]
pub use jwp_presentation_options::JwpPresentationOptions;

#[cfg(feature = "validator")]
pub(crate) use self::jwt_serialization::JwtPresentationV2Claims;
#[cfg(feature = "validator")]
pub(crate) use self::jwt_serialization::PresentationJwtClaims;
