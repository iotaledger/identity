// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::error::WasmResult;
use identity_iota::core::Timestamp;
use identity_iota::core::Url;
use identity_iota::credential::DomainLinkageCredentialBuilder;
use identity_iota::did::CoreDID;
use proc_typescript::typescript;
use wasm_bindgen::prelude::*;

impl TryFrom<IDomainLinkageCredential> for DomainLinkageCredentialBuilder {
  type Error = JsValue;

  fn try_from(values: IDomainLinkageCredential) -> std::result::Result<Self, Self::Error> {
    let IDomainLinkageCredentialHelper {
      issuer,
      issuance_date,
      expiration_date,
      origin,
    } = values.into_serde::<IDomainLinkageCredentialHelper>().wasm_result()?;

    let mut builder: DomainLinkageCredentialBuilder = DomainLinkageCredentialBuilder::new();
    if let Some(issuer) = issuer {
      builder = builder.issuer(issuer);
    }
    if let Some(issuance_date) = issuance_date {
      builder = builder.issuance_date(issuance_date);
    }
    if let Some(expiration_date) = expiration_date {
      builder = builder.expiration_date(expiration_date);
    }
    if let Some(origin) = origin {
      builder = builder.origin(origin);
    }
    Ok(builder)
  }
}

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "IDomainLinkageCredential")]
  pub type IDomainLinkageCredential;
}

/// Fields to create a new Domain Linkage {@link Credential}.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[typescript(name = "IDomainLinkageCredential", readonly, optional)]
struct IDomainLinkageCredentialHelper {
  /// A reference to the issuer of the {@link Credential}.
  #[typescript(optional = false, type = "CoreDID | IotaDID")]
  issuer: Option<CoreDID>,
  /// A timestamp of when the {@link Credential} becomes valid. Defaults to the current datetime.
  #[typescript(name = "issuanceDate", type = "Timestamp")]
  issuance_date: Option<Timestamp>,
  /// A timestamp of when the {@link Credential} should no longer be considered valid.
  #[typescript(optional = false, name = "expirationDate", type = "Timestamp")]
  expiration_date: Option<Timestamp>,
  /// The origin, on which the {@link Credential} is issued.
  #[typescript(optional = false, name = "origin", type = "string")]
  origin: Option<Url>,
}
