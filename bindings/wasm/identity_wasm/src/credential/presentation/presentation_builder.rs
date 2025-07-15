// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::core::Context;
use identity_iota::core::Object;
use identity_iota::core::OneOrMany;
use identity_iota::core::Url;
use identity_iota::credential::Policy;
use identity_iota::credential::PresentationBuilder;
use identity_iota::credential::RefreshService;
use proc_typescript::typescript;
use wasm_bindgen::prelude::*;

use crate::credential::UnknownCredential;
use crate::error::WasmResult;

impl TryFrom<IPresentation> for PresentationBuilder<UnknownCredential> {
  type Error = JsValue;

  fn try_from(values: IPresentation) -> std::result::Result<Self, Self::Error> {
    let IPresentationHelper {
      context,
      id,
      r#type,
      verifiable_credential,
      holder,
      refresh_service,
      terms_of_use,
      properties,
    } = values.into_serde::<IPresentationHelper>().wasm_result()?;

    let mut builder: PresentationBuilder<UnknownCredential> =
      PresentationBuilder::new(Url::parse(holder).wasm_result()?, properties);

    if let Some(context) = context {
      for value in context.into_vec() {
        builder = builder.context(value);
      }
    }
    if let Some(id) = id {
      builder = builder.id(Url::parse(id).wasm_result()?);
    }
    if let Some(types) = r#type {
      for value in types.iter() {
        builder = builder.type_(value);
      }
    }
    for credential in verifiable_credential.into_vec() {
      builder = builder.credential(credential);
    }
    if let Some(refresh_service) = refresh_service {
      for service in refresh_service.into_vec() {
        builder = builder.refresh_service(service);
      }
    }
    if let Some(terms_of_use) = terms_of_use {
      for policy in terms_of_use.into_vec() {
        builder = builder.terms_of_use(policy);
      }
    }

    Ok(builder)
  }
}

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "IPresentation")]
  pub type IPresentation;
}

/// Fields for constructing a new {@link Presentation}.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[typescript(name = "IPresentation", readonly, optional)]
struct IPresentationHelper {
  /// The JSON-LD context(s) applicable to the presentation.
  #[typescript(type = "string | Record<string, any> | Array<string | Record<string, any>>")]
  context: Option<OneOrMany<Context>>,
  /// A unique URI that may be used to identify the presentation.
  #[typescript(type = "string")]
  id: Option<String>,
  /// One or more URIs defining the type of the presentation. Contains the base context by default.
  #[typescript(name = "type", type = "string | Array<string>")]
  r#type: Option<OneOrMany<String>>,
  /// JWT Credential(s) expressing the claims of the presentation.
  #[typescript(
    optional = false,
    name = "verifiableCredential",
    type = "Jwt | Credential | Record<string, any> | Array<Jwt | Credential | Record<string, any>>"
  )]
  verifiable_credential: OneOrMany<UnknownCredential>,
  /// The entity that generated the presentation.
  #[typescript(optional = false, type = "string | CoreDID | IotaDID")]
  holder: String,
  /// Service(s) used to refresh an expired {@link Credential} in the presentation.
  #[typescript(name = "refreshService", type = "RefreshService | Array<RefreshService>")]
  refresh_service: Option<OneOrMany<RefreshService>>,
  /// Terms-of-use specified by the presentation holder.
  #[typescript(name = "termsOfUse", type = "Policy | Array<Policy>")]
  terms_of_use: Option<OneOrMany<Policy>>,
  /// Miscellaneous properties.
  #[serde(flatten)]
  #[typescript(optional = false, name = "[properties: string]", type = "unknown")]
  properties: Object,
}
