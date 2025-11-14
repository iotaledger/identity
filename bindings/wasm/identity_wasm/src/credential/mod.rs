// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::module_inception)]

use identity_iota::core::Object;
use identity_iota::credential::Credential;
use identity_iota::credential::CredentialT;
use identity_iota::credential::CredentialV2;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

pub use self::credential::WasmCredential;
pub use self::credential_builder::*;
pub use self::credential_v2::*;
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
mod credential_v2;
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

#[wasm_bindgen]
extern "C" {
  /// A VC Credential. Either {@link Credential} or {@link CredentialV2}.
  #[derive(Clone)]
  #[wasm_bindgen(typescript_type = "Credential | CredentialV2")]
  pub type CredentialAny;

  #[wasm_bindgen(method, js_name = toJSON)]
  pub fn to_json(this: &CredentialAny) -> JsValue;
}

impl CredentialAny {
  pub(crate) fn try_to_dyn_credential(&self) -> Result<Box<dyn CredentialT<Properties = Object> + Sync>, JsValue> {
    let json_repr = self.to_json();
    serde_wasm_bindgen::from_value::<Credential>(json_repr.clone())
      .map(|c| Box::new(c) as Box<dyn CredentialT<Properties = Object> + Sync>)
      .or_else(|_| {
        serde_wasm_bindgen::from_value::<CredentialV2>(json_repr)
          .map(|c| Box::new(c) as Box<dyn CredentialT<Properties = Object> + Sync>)
      })
      .map_err(|e| e.into())
  }
}
