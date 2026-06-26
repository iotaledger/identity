// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::ops::Deref;

use identity_iota::core::Context;
use identity_iota::core::Url;
use identity_iota::credential::status_list_2021::CredentialStatus;
use identity_iota::credential::status_list_2021::StatusList2021Credential;
use identity_iota::credential::status_list_2021::StatusList2021CredentialBuilder;
use identity_iota::credential::status_list_2021::StatusPurpose;
use identity_iota::credential::Issuer;
use wasm_bindgen::prelude::*;

use crate::common::WasmTimestamp;
use crate::credential::WasmCredential;
use crate::credential::WasmProof;
use crate::error::Result;
use crate::error::WasmResult;

use super::WasmStatusList2021;
use super::WasmStatusList2021Entry;

#[wasm_bindgen(js_name = CredentialStatus)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum WasmCredentialStatus {
  Revoked = 0,
  Suspended = 1,
  Valid = 2,
}

impl From<CredentialStatus> for WasmCredentialStatus {
  fn from(value: CredentialStatus) -> Self {
    match value {
      CredentialStatus::Revoked => Self::Revoked,
      CredentialStatus::Suspended => Self::Suspended,
      CredentialStatus::Valid => Self::Valid,
    }
  }
}

impl From<WasmCredentialStatus> for CredentialStatus {
  fn from(value: WasmCredentialStatus) -> Self {
    match value {
      WasmCredentialStatus::Revoked => Self::Revoked,
      WasmCredentialStatus::Suspended => Self::Suspended,
      WasmCredentialStatus::Valid => Self::Valid,
    }
  }
}

/// Purpose of a {@link StatusList2021}.
#[wasm_bindgen(js_name = StatusPurpose)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum WasmStatusPurpose {
  /// Used for revocation.
  Revocation = 0,
  /// Used for suspension.
  Suspension = 1,
}

impl From<StatusPurpose> for WasmStatusPurpose {
  fn from(value: StatusPurpose) -> Self {
    match value {
      StatusPurpose::Revocation => Self::Revocation,
      StatusPurpose::Suspension => Self::Suspension,
    }
  }
}

impl From<WasmStatusPurpose> for StatusPurpose {
  fn from(value: WasmStatusPurpose) -> Self {
    match value {
      WasmStatusPurpose::Revocation => Self::Revocation,
      WasmStatusPurpose::Suspension => Self::Suspension,
    }
  }
}

/// A parsed [StatusList2021Credential](https://www.w3.org/TR/2023/WD-vc-status-list-20230427/#statuslist2021credential).
#[wasm_bindgen(js_name = "StatusList2021Credential", inspectable)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(from = "StatusList2021Credential", into = "StatusList2021Credential")]
pub struct WasmStatusList2021Credential {
  pub(crate) inner: StatusList2021Credential,
  wasm_credential: WasmCredential,
}

impl Deref for WasmStatusList2021Credential {
  type Target = WasmCredential;
  fn deref(&self) -> &Self::Target {
    &self.wasm_credential
  }
}

impl From<StatusList2021Credential> for WasmStatusList2021Credential {
  fn from(value: StatusList2021Credential) -> Self {
    Self {
      wasm_credential: WasmCredential(value.clone().into_inner()),
      inner: value,
    }
  }
}

impl From<WasmStatusList2021Credential> for StatusList2021Credential {
  fn from(value: WasmStatusList2021Credential) -> Self {
    value.inner
  }
}

#[wasm_bindgen(js_class = StatusList2021Credential)]
impl WasmStatusList2021Credential {
  /// Creates a new {@link StatusList2021Credential}.
  #[wasm_bindgen(constructor)]
  pub fn new(credential: WasmCredential) -> Result<WasmStatusList2021Credential> {
    StatusList2021Credential::try_from(credential.0)
      .map(Into::into)
      .wasm_result()
  }

  #[wasm_bindgen]
  pub fn id(&self) -> String {
    self.inner.id.as_deref().map(ToString::to_string).unwrap()
  }

  /// Sets the given credential's status using the `index`-th entry of this status list.
  /// Returns the created `credentialStatus`.
  #[wasm_bindgen(js_name = "setCredentialStatus")]
  pub fn set_credential_status(
    &mut self,
    credential: &mut WasmCredential,
    index: usize,
    revoked_or_suspended: bool,
  ) -> Result<WasmStatusList2021Entry> {
    let entry = self
      .inner
      .set_credential_status(&mut credential.0, index, revoked_or_suspended)
      .wasm_result()?;
    self.wasm_credential = WasmCredential(self.inner.clone().into_inner());

    Ok(WasmStatusList2021Entry(entry))
  }

  /// Returns the {@link StatusPurpose} of this {@link StatusList2021Credential}.
  #[wasm_bindgen]
  pub fn purpose(&self) -> WasmStatusPurpose {
    self.inner.purpose().into()
  }

  /// Returns the state of the `index`-th entry, if any.
  #[wasm_bindgen]
  pub fn entry(&self, index: usize) -> Result<WasmCredentialStatus> {
    self.inner.entry(index).map(WasmCredentialStatus::from).wasm_result()
  }

  #[wasm_bindgen(js_name = "clone")]
  pub fn wasm_clone(&self) -> WasmStatusList2021Credential {
    self.clone()
  }

  #[wasm_bindgen(js_name = "fromJSON")]
  pub fn from_json(json: JsValue) -> Result<WasmStatusList2021Credential> {
    json.into_serde::<WasmStatusList2021Credential>().wasm_result()
  }

  #[wasm_bindgen(js_name = "toJSON")]
  pub fn to_json(&self) -> Result<JsValue> {
    JsValue::from_serde(self).wasm_result()
  }
}

/// Builder type to construct valid {@link StatusList2021Credential} instances.
#[wasm_bindgen(js_name = StatusList2021CredentialBuilder)]
pub struct WasmStatusList2021CredentialBuilder(StatusList2021CredentialBuilder);

#[wasm_bindgen(js_class = StatusList2021CredentialBuilder)]
impl WasmStatusList2021CredentialBuilder {
  /// Creates a new {@link StatusList2021CredentialBuilder}.
  #[wasm_bindgen(constructor)]
  pub fn new(status_list: Option<WasmStatusList2021>) -> WasmStatusList2021CredentialBuilder {
    Self(StatusList2021CredentialBuilder::new(status_list.unwrap_or_default().0))
  }

  /// Sets the purpose of the {@link StatusList2021Credential} that is being created.
  #[wasm_bindgen]
  pub fn purpose(mut self, purpose: WasmStatusPurpose) -> WasmStatusList2021CredentialBuilder {
    self.0 = self.0.purpose(purpose.into());
    self
  }

  /// Sets `credentialSubject.id`.
  #[wasm_bindgen(js_name = "subjectId")]
  pub fn subject_id(mut self, id: String) -> Result<WasmStatusList2021CredentialBuilder> {
    let id = Url::parse(id).wasm_result()?;
    self.0 = self.0.subject_id(id);

    Ok(self)
  }

  /// Sets the expiration date of the credential.
  #[wasm_bindgen(js_name = "expirationDate")]
  pub fn expiration_date(mut self, time: WasmTimestamp) -> WasmStatusList2021CredentialBuilder {
    self.0 = self.0.expiration_date(time.0);
    self
  }

  /// Sets the issuer of the credential.
  #[wasm_bindgen]
  pub fn issuer(mut self, issuer: String) -> Result<WasmStatusList2021CredentialBuilder> {
    let issuer = Url::parse(issuer).wasm_result()?;
    self.0 = self.0.issuer(Issuer::Url(issuer));

    Ok(self)
  }

  /// Sets the context of the credential.
  #[wasm_bindgen]
  pub fn context(mut self, context: String) -> Result<WasmStatusList2021CredentialBuilder> {
    let ctx = Context::Url(Url::parse(context).wasm_result()?);
    self.0 = self.0.context(ctx);

    Ok(self)
  }

  /// Adds a credential type.
  #[wasm_bindgen(js_name = "type")]
  pub fn r#type(mut self, t: String) -> WasmStatusList2021CredentialBuilder {
    self.0 = self.0.add_type(t);
    self
  }

  /// Adds a credential's proof.
  #[wasm_bindgen]
  pub fn proof(mut self, proof: WasmProof) -> WasmStatusList2021CredentialBuilder {
    self.0 = self.0.proof(proof.0);
    self
  }

  /// Attempts to build a valid {@link StatusList2021Credential} with the previously provided data.
  #[wasm_bindgen]
  pub fn build(self) -> Result<WasmStatusList2021Credential> {
    let credential = self.0.build().wasm_result()?;

    WasmStatusList2021Credential::new(WasmCredential(credential.into_inner()))
  }
}
