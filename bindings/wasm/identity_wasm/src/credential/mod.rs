// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::module_inception)]

pub use self::credential::WasmCredential;
pub use self::credential_builder::*;
pub use self::domain_linkage_configuration::WasmDomainLinkageConfiguration;
pub use self::jpt::*;
pub use self::jpt_credential_validator::*;
pub use self::jpt_presentiation_validation::*;
pub use self::jws::WasmJws;
pub use self::jwt::WasmJwt;
pub use self::jwt_credential_validation::*;
pub use self::jwt_presentation_validation::*;
pub use self::linked_verifiable_presentation_service::*;
pub use self::options::WasmFailFast;
pub use self::options::WasmSubjectHolderRelationship;
pub use self::presentation::*;
pub use self::proof::WasmProof;
pub use self::revocation::*;
pub use self::types::*;

mod credential;
mod credential_builder;
mod domain_linkage_configuration;
mod domain_linkage_credential_builder;
mod domain_linkage_validator;
mod jpt;
mod jpt_credential_validator;
mod jpt_presentiation_validation;
mod jws;
mod jwt;
mod jwt_credential_validation;
mod jwt_presentation_validation;
mod linked_domain_service;
mod linked_verifiable_presentation_service;
mod options;
mod presentation;
mod proof;
mod revocation;
mod types;
