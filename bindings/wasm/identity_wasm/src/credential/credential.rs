// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::core::Context;
use identity_iota::core::Object;
use identity_iota::credential::Credential;
use identity_iota::credential::CredentialBuilder;
use identity_iota::credential::DomainLinkageCredentialBuilder;
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
use crate::credential::ICredential;
use crate::credential::UrlOrIssuer;
use crate::credential::WasmProof;
use crate::error::Result;
use crate::error::WasmResult;

/// Represents a set of claims describing an entity.
#[wasm_bindgen(js_name = Credential, inspectable)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WasmCredential(pub(crate) Credential);

#[wasm_bindgen(js_class = Credential)]
impl WasmCredential {
  /// Returns the base JSON-LD context.
  #[wasm_bindgen(js_name = "BaseContext")]
  pub fn base_context() -> Result<String> {
    match Credential::<Object>::base_context() {
      Context::Url(url) => Ok(url.to_string()),
      Context::Obj(_) => Err(JsError::new("Credential.BaseContext should be a single URL").into()),
    }
  }

  /// Returns the base type.
  #[wasm_bindgen(js_name = "BaseType")]
  pub fn base_type() -> String {
    Credential::<Object>::base_type().to_owned()
  }

  /// Constructs a new {@link Credential}.
  #[wasm_bindgen(constructor)]
  pub fn new(values: ICredential) -> Result<WasmCredential> {
    let builder: CredentialBuilder = CredentialBuilder::try_from(values)?;
    builder.build().map(Self).wasm_result()
  }

  #[wasm_bindgen(js_name = "createDomainLinkageCredential")]
  pub fn create_domain_linkage_credential(values: IDomainLinkageCredential) -> Result<WasmCredential> {
    let builder: DomainLinkageCredentialBuilder = DomainLinkageCredentialBuilder::try_from(values)?;
    builder.build().map(Self).wasm_result()
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
  #[wasm_bindgen(js_name = "issuanceDate")]
  pub fn issuance_date(&self) -> WasmTimestamp {
    WasmTimestamp::from(self.0.issuance_date)
  }

  /// Returns a copy of the timestamp of when the {@link Credential} should no longer be considered valid.
  #[wasm_bindgen(js_name = "expirationDate")]
  pub fn expiration_date(&self) -> Option<WasmTimestamp> {
    self.0.expiration_date.map(WasmTimestamp::from)
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

  /// Sets the `proof` property of the {@link Credential}.
  ///
  /// Note that this proof is not related to JWT.
  #[wasm_bindgen(js_name = "setProof")]
  pub fn set_proof(&mut self, proof: Option<WasmProof>) {
    self.0.set_proof(proof.map(|wasm_proof| wasm_proof.0))
  }

  /// Serializes the `Credential` as a JWT claims set
  /// in accordance with [VC Data Model v1.1](https://www.w3.org/TR/vc-data-model/#json-web-token).
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

impl_wasm_json!(WasmCredential, Credential);
impl_wasm_clone!(WasmCredential, Credential);

impl From<Credential> for WasmCredential {
  fn from(credential: Credential) -> WasmCredential {
    Self(credential)
  }
}
