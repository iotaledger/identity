// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::core::Context;
use identity_iota::core::Object;
use identity_iota::core::OneOrMany;
use identity_iota::core::Timestamp;
use identity_iota::core::Url;
use identity_iota::credential::credential_v2::Credential as CredentialV2;
use identity_iota::credential::CredentialBuilder;
use identity_iota::credential::DomainLinkageCredentialBuilder;
use identity_iota::credential::Evidence;
use identity_iota::credential::Issuer;
use identity_iota::credential::Policy;
use identity_iota::credential::Proof;
use identity_iota::credential::RefreshService;
use identity_iota::credential::Schema;
use identity_iota::credential::Status;
use identity_iota::credential::Subject;
use proc_typescript::typescript;
use serde_json::Value;
use std::collections::BTreeMap;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

use crate::common::ArrayString;
use crate::common::MapStringAny;
use crate::common::RecordStringAny;
use crate::common::WasmTimestamp;
use crate::credential::domain_linkage_credential_builder::IDomainLinkageCredential;
use crate::credential::ArrayContext;
use crate::credential::ArrayEvidence;
use crate::credential::ArrayPolicy;
use crate::credential::ArrayRefreshService;
use crate::credential::ArraySchema;
use crate::credential::ArrayStatus;
use crate::credential::ArraySubject;
use crate::credential::UrlOrIssuer;
use crate::credential::WasmProof;
use crate::error::Result;
use crate::error::WasmResult;

/// Represents a set of claims describing an entity.
#[wasm_bindgen(js_name = CredentialV2, inspectable)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WasmCredentialV2(pub(crate) CredentialV2);

#[wasm_bindgen(js_class = CredentialV2)]
impl WasmCredentialV2 {
  /// Returns the base JSON-LD context.
  #[wasm_bindgen(js_name = "BaseContext")]
  pub fn base_context() -> Result<String> {
    match CredentialV2::<Object>::base_context() {
      Context::Url(url) => Ok(url.to_string()),
      Context::Obj(_) => Err(JsError::new("Credential.BaseContext should be a single URL").into()),
    }
  }

  /// Returns the base type.
  #[wasm_bindgen(js_name = "BaseType")]
  pub fn base_type() -> String {
    CredentialV2::<Object>::base_type().to_owned()
  }

  /// Constructs a new {@link Credential}.
  #[wasm_bindgen(constructor)]
  pub fn new(values: ICredentialV2) -> Result<WasmCredentialV2> {
    let builder: CredentialBuilder = CredentialBuilder::try_from(values)?;
    builder.build_v2().map(Self).wasm_result()
  }

  #[wasm_bindgen(js_name = "createDomainLinkageCredential")]
  pub fn create_domain_linkage_credential(values: IDomainLinkageCredential) -> Result<WasmCredentialV2> {
    let builder: DomainLinkageCredentialBuilder = DomainLinkageCredentialBuilder::try_from(values)?;
    builder.build_v2().map(Self).wasm_result()
  }

  /// Returns a copy of the JSON-LD context(s) applicable to the {@link Credential}.
  #[wasm_bindgen]
  pub fn context(&self) -> Result<ArrayContext> {
    self
      .0
      .context
      .iter()
      .map(JsValue::from_serde)
      .collect::<std::result::Result<js_sys::Array, _>>()
      .wasm_result()
      .map(|value| value.unchecked_into::<ArrayContext>())
  }

  /// Returns a copy of the unique `URI` identifying the {@link Credential} .
  #[wasm_bindgen]
  pub fn id(&self) -> Option<String> {
    self.0.id.as_ref().map(|url| url.to_string())
  }

  /// Returns a copy of the URIs defining the type of the {@link Credential}.
  #[wasm_bindgen(js_name = "type")]
  pub fn types(&self) -> ArrayString {
    self
      .0
      .types
      .iter()
      .map(|s| s.as_str())
      .map(JsValue::from_str)
      .collect::<js_sys::Array>()
      .unchecked_into::<ArrayString>()
  }

  /// Returns a copy of the {@link Credential} subject(s).
  #[wasm_bindgen(js_name = credentialSubject)]
  pub fn credential_subject(&self) -> Result<ArraySubject> {
    self
      .0
      .credential_subject
      .iter()
      .map(JsValue::from_serde)
      .collect::<std::result::Result<js_sys::Array, _>>()
      .wasm_result()
      .map(|value| value.unchecked_into::<ArraySubject>())
  }

  /// Returns a copy of the issuer of the {@link Credential}.
  #[wasm_bindgen]
  pub fn issuer(&self) -> Result<UrlOrIssuer> {
    JsValue::from_serde(&self.0.issuer)
      .map(|value| value.unchecked_into::<UrlOrIssuer>())
      .wasm_result()
  }

  /// Returns a copy of the timestamp of when the {@link Credential} becomes valid.
  #[wasm_bindgen(js_name = "validFrom")]
  pub fn valid_from(&self) -> WasmTimestamp {
    WasmTimestamp::from(self.0.valid_from)
  }

  /// Returns a copy of the timestamp of when the {@link Credential} should no longer be considered valid.
  #[wasm_bindgen(js_name = "validUntil")]
  pub fn valid_until(&self) -> Option<WasmTimestamp> {
    self.0.valid_until.map(WasmTimestamp::from)
  }

  /// Returns a copy of the information used to determine the current status of the {@link Credential}.
  #[wasm_bindgen(js_name = "credentialStatus")]
  pub fn credential_status(&self) -> Result<ArrayStatus> {
    self
      .0
      .credential_status
      .iter()
      .map(JsValue::from_serde)
      .collect::<std::result::Result<js_sys::Array, _>>()
      .wasm_result()
      .map(|value| value.unchecked_into::<ArrayStatus>())
  }

  /// Returns a copy of the information used to assist in the enforcement of a specific {@link Credential} structure.
  #[wasm_bindgen(js_name = "credentialSchema")]
  pub fn credential_schema(&self) -> Result<ArraySchema> {
    self
      .0
      .credential_schema
      .iter()
      .map(JsValue::from_serde)
      .collect::<std::result::Result<js_sys::Array, _>>()
      .wasm_result()
      .map(|value| value.unchecked_into::<ArraySchema>())
  }

  /// Returns a copy of the service(s) used to refresh an expired {@link Credential}.
  #[wasm_bindgen(js_name = "refreshService")]
  pub fn refresh_service(&self) -> Result<ArrayRefreshService> {
    self
      .0
      .refresh_service
      .iter()
      .map(JsValue::from_serde)
      .collect::<std::result::Result<js_sys::Array, _>>()
      .wasm_result()
      .map(|value| value.unchecked_into::<ArrayRefreshService>())
  }

  /// Returns a copy of the terms-of-use specified by the {@link Credential} issuer.
  #[wasm_bindgen(js_name = "termsOfUse")]
  pub fn terms_of_use(&self) -> Result<ArrayPolicy> {
    self
      .0
      .terms_of_use
      .iter()
      .map(JsValue::from_serde)
      .collect::<std::result::Result<js_sys::Array, _>>()
      .wasm_result()
      .map(|value| value.unchecked_into::<ArrayPolicy>())
  }

  /// Returns a copy of the human-readable evidence used to support the claims within the {@link Credential}.
  #[wasm_bindgen]
  pub fn evidence(&self) -> Result<ArrayEvidence> {
    self
      .0
      .evidence
      .iter()
      .map(JsValue::from_serde)
      .collect::<std::result::Result<js_sys::Array, _>>()
      .wasm_result()
      .map(|value| value.unchecked_into::<ArrayEvidence>())
  }

  /// Returns whether or not the {@link Credential} must only be contained within a  {@link Presentation}
  /// with a proof issued from the {@link Credential} subject.
  #[wasm_bindgen(js_name = "nonTransferable")]
  pub fn non_transferable(&self) -> Option<bool> {
    self.0.non_transferable
  }

  /// Optional cryptographic proof, unrelated to JWT.
  #[wasm_bindgen]
  pub fn proof(&self) -> Option<WasmProof> {
    self.0.proof.clone().map(WasmProof)
  }

  /// Returns a copy of the miscellaneous properties on the {@link Credential}.
  #[wasm_bindgen]
  pub fn properties(&self) -> Result<MapStringAny> {
    MapStringAny::try_from(&self.0.properties)
  }

  /// Serializes the `Credential` as a JWT claims set
  /// in accordance with [VC Data Model v2.0](https://www.w3.org/TR/vc-data-model-2.0/).
  ///
  /// The resulting object can be used as the payload of a JWS when issuing the credential.  
  #[wasm_bindgen(js_name = "toJwtClaims")]
  pub fn to_jwt_claims(&self, custom_claims: Option<RecordStringAny>) -> Result<RecordStringAny> {
    let serialized: String = if let Some(object) = custom_claims {
      let object: BTreeMap<String, Value> = object.into_serde().wasm_result()?;
      self.0.serialize_jwt(Some(object)).wasm_result()?
    } else {
      self.0.serialize_jwt(None).wasm_result()?
    };
    let serialized: BTreeMap<String, Value> = serde_json::from_str(&serialized).wasm_result()?;
    Ok(
      JsValue::from_serde(&serialized)
        .wasm_result()?
        .unchecked_into::<RecordStringAny>(),
    )
  }
}

impl_wasm_json!(WasmCredentialV2, CredentialV2);
impl_wasm_clone!(WasmCredentialV2, CredentialV2);

impl From<CredentialV2> for WasmCredentialV2 {
  fn from(credential: CredentialV2) -> WasmCredentialV2 {
    Self(credential)
  }
}

#[wasm_bindgen]
extern "C" {
  #[derive(Clone)]
  #[wasm_bindgen(typescript_type = "ICredentialV2")]
  pub type ICredentialV2;
}

/// Fields for constructing a new {@link Credential}.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[typescript(name = "ICredentialV2", readonly, optional)]
pub(crate) struct ICredentialHelperV2 {
  /// The JSON-LD context(s) applicable to the {@link Credential}.
  #[typescript(type = "string | Record<string, any> | Array<string | Record<string, any>>")]
  context: Option<OneOrMany<Context>>,
  /// A unique URI that may be used to identify the {@link Credential}.
  #[typescript(type = "string")]
  id: Option<String>,
  /// One or more URIs defining the type of the {@link Credential}. Contains the base context by default.
  #[typescript(name = "type", type = "string | Array<string>")]
  r#type: Option<OneOrMany<String>>,
  /// One or more objects representing the {@link Credential} subject(s).
  #[typescript(optional = false, name = "credentialSubject", type = "Subject | Array<Subject>")]
  credential_subject: Option<OneOrMany<Subject>>,
  /// A reference to the issuer of the {@link Credential}.
  #[typescript(optional = false, type = "string | CoreDID | IotaDID | Issuer")]
  issuer: Option<Issuer>,
  /// A timestamp of when the {@link Credential} becomes valid. Defaults to the current datetime.
  #[typescript(name = "validFrom", type = "Timestamp")]
  valid_from: Option<Timestamp>,
  /// A timestamp of when the {@link Credential} should no longer be considered valid.
  #[typescript(name = "validUntil", type = "Timestamp")]
  valid_until: Option<Timestamp>,
  /// Information used to determine the current status of the {@link Credential}.
  #[typescript(name = "credentialStatus", type = "Status")]
  credential_status: Option<Status>,
  /// Information used to assist in the enforcement of a specific {@link Credential} structure.
  #[typescript(name = "credentialSchema", type = "Schema | Array<Schema>")]
  credential_schema: Option<OneOrMany<Schema>>,
  /// Service(s) used to refresh an expired {@link Credential}.
  #[typescript(name = "refreshService", type = "RefreshService | Array<RefreshService>")]
  refresh_service: Option<OneOrMany<RefreshService>>,
  /// Terms-of-use specified by the {@link Credential} issuer.
  #[typescript(name = "termsOfUse", type = "Policy | Array<Policy>")]
  terms_of_use: Option<OneOrMany<Policy>>,
  /// Human-readable evidence used to support the claims within the {@link Credential}.
  #[typescript(type = "Evidence | Array<Evidence>")]
  evidence: Option<OneOrMany<Evidence>>,
  /// Indicates that the {@link Credential} must only be contained within a {@link Presentation} with a proof issued
  /// from the {@link Credential} subject.
  #[typescript(name = "nonTransferable", type = "boolean")]
  non_transferable: Option<bool>,
  // The `proof` property of the {@link Credential}.
  #[typescript(type = "Proof")]
  proof: Option<Proof>,
  /// Miscellaneous properties.
  #[serde(flatten)]
  #[typescript(optional = false, name = "[properties: string]", type = "unknown")]
  properties: Object,
}

impl TryFrom<ICredentialV2> for CredentialBuilder {
  type Error = JsValue;

  fn try_from(values: ICredentialV2) -> std::result::Result<Self, Self::Error> {
    let ICredentialHelperV2 {
      context,
      id,
      r#type,
      credential_subject,
      issuer,
      valid_from,
      valid_until,
      credential_status,
      credential_schema,
      refresh_service,
      terms_of_use,
      evidence,
      non_transferable,
      proof,
      properties,
    } = values.into_serde::<ICredentialHelperV2>().wasm_result()?;

    let mut builder: CredentialBuilder = CredentialBuilder::new(properties);

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
    if let Some(credential_subject) = credential_subject {
      for subject in credential_subject.into_vec() {
        builder = builder.subject(subject);
      }
    }
    if let Some(issuer) = issuer {
      builder = builder.issuer(issuer);
    }
    if let Some(valid_from) = valid_from {
      builder = builder.valid_from(valid_from);
    }
    if let Some(valid_until) = valid_until {
      builder = builder.expiration_date(valid_until);
    }
    if let Some(credential_status) = credential_status {
      builder = builder.status(credential_status);
    }
    if let Some(credential_schema) = credential_schema {
      for schema in credential_schema.into_vec() {
        builder = builder.schema(schema);
      }
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
    if let Some(evidence) = evidence {
      for value in evidence.into_vec() {
        builder = builder.evidence(value);
      }
    }
    if let Some(non_transferable) = non_transferable {
      builder = builder.non_transferable(non_transferable);
    }
    if let Some(proof) = proof {
      builder = builder.proof(proof);
    }

    Ok(builder)
  }
}
