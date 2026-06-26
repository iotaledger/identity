// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Verifiable Credential and Presentation validators.

#[cfg(feature = "jpt-bbs-plus")]
pub use self::jpt_credential_validation::*;
#[cfg(feature = "jpt-bbs-plus")]
pub use self::jpt_presentation_validation::*;
pub use self::jwt_credential_validation::*;
pub use self::jwt_presentation_validation::*;
pub use self::options::FailFast;
pub use self::options::StatusCheck;
pub use self::options::SubjectHolderRelationship;
#[cfg(feature = "sd-jwt")]
pub use self::sd_jwt::*;

#[cfg(feature = "jpt-bbs-plus")]
mod jpt_credential_validation;
#[cfg(feature = "jpt-bbs-plus")]
mod jpt_presentation_validation;
mod jwt_credential_validation;
mod jwt_presentation_validation;
mod options;
#[cfg(feature = "sd-jwt")]
mod sd_jwt;
#[cfg(test)]
pub(crate) mod test_utils;
