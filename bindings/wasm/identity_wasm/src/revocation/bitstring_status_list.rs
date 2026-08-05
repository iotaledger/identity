// Copyright 2020-2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_iota::core::Context;
use identity_iota::core::OneOrMany;
use identity_iota::core::Timestamp;
use identity_iota::core::Url;
use identity_iota::credential::bitstring_status_list_v1::BitstringStatusListCredential;
use identity_iota::credential::bitstring_status_list_v1::BitstringStatusListCredentialBuilder;
use identity_iota::credential::bitstring_status_list_v1::BitstringStatusListEntry;
use identity_iota::credential::bitstring_status_list_v1::BitstringStatusListEntryBuilder;
use identity_iota::credential::bitstring_status_list_v1::StatusMessage;
use identity_iota::credential::bitstring_status_list_v1::StatusPurpose;
use identity_iota::credential::bitstring_status_list_v1::StatusValue;
use identity_iota::credential::Proof;
use wasm_bindgen::prelude::*;

use crate::credential::WasmCredentialV2;

#[wasm_bindgen(typescript_custom_section)]
const ENTRY_INTERFACE: &str = r#"
export type StatusPurpose = "refresh" | "revocation" | "suspension" | "message" | string;
export type StatusMessage = {
  status: string;
  message: string;
};

export interface BitstringStatusListEntryParams {
  id?: string;
  statusPurpose: StatusPurpose;
  statusListIndex: string | number;
  statusListCredential: string;
  statusMessage?: string[];
  statusReference?: string | string[];
}
"#;

#[wasm_bindgen(js_name = BitstringStatusListEntry)]
pub struct WasmBitstringStatusListEntry(pub(crate) BitstringStatusListEntry);

#[wasm_bindgen(js_class = BitstringStatusListEntry)]
impl WasmBitstringStatusListEntry {
  #[wasm_bindgen(constructor)]
  pub fn new(
    #[wasm_bindgen(unchecked_param_type = "BitstringStatusListEntryParams")] params: JsValue,
  ) -> Result<Self, JsValue> {
    let params: EntryParamsHelper = serde_wasm_bindgen::from_value(params)?;
    BitstringStatusListEntryBuilder::from(params)
      .build()
      .map(Self)
      .map_err(|err| JsValue::from_str(&err.to_string()))
  }

  #[wasm_bindgen(getter)]
  pub fn id(&self) -> Option<String> {
    self.0.id().map(|id| id.to_string())
  }

  #[wasm_bindgen(getter, js_name = "type")]
  pub fn type_(&self) -> String {
    self.0.type_().to_string()
  }

  #[wasm_bindgen(getter, js_name = statusPurpose, unchecked_return_type = "StatusPurpose")]
  pub fn status_purpose(&self) -> String {
    self.0.status_purpose().to_string()
  }

  #[wasm_bindgen(getter, js_name = statusListIndex)]
  pub fn status_list_index(&self) -> usize {
    self.0.status_list_index()
  }

  #[wasm_bindgen(getter, js_name = statusListCredential)]
  pub fn status_list_credential(&self) -> String {
    self.0.status_list_credential().to_string()
  }

  #[wasm_bindgen(getter, js_name = statusSize)]
  pub fn status_size(&self) -> usize {
    self.0.status_size()
  }

  #[wasm_bindgen(getter, js_name = statusMessage, unchecked_return_type = "StatusMessage[]")]
  pub fn status_message(&self) -> Vec<WasmStatusMessage> {
    self.0.status_message().iter().cloned().map(WasmStatusMessage).collect()
  }

  #[wasm_bindgen(getter, js_name = statusReference)]
  pub fn status_reference(&self) -> Vec<String> {
    self.0.status_reference().iter().map(|url| url.to_string()).collect()
  }

  #[wasm_bindgen(js_name = toJSON)]
  pub fn to_json(&self) -> Result<String, JsError> {
    Ok(serde_json::to_string(&self.0)?)
  }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct EntryParamsHelper {
  id: Option<Url>,
  status_purpose: StatusPurpose,
  #[serde(deserialize_with = "number_from_either_string_or_number")]
  status_list_index: usize,
  status_list_credential: Url,
  #[serde(default)]
  status_message: Vec<String>,
  #[serde(default)]
  status_reference: OneOrMany<Url>,
}

impl From<EntryParamsHelper> for BitstringStatusListEntryBuilder {
  fn from(params: EntryParamsHelper) -> Self {
    let mut builder = BitstringStatusListEntryBuilder::default()
      .status_purpose(params.status_purpose)
      .credential(params.status_list_credential)
      .index(params.status_list_index)
      .references(params.status_reference)
      .ordered_messages(params.status_message);

    if let Some(id) = params.id {
      builder = builder.id(id);
    }

    builder
  }
}

#[wasm_bindgen(js_name = StatusMessage, skip_typescript)]
pub struct WasmStatusMessage(pub(crate) StatusMessage);

#[wasm_bindgen(js_class = StatusMessage)]
impl WasmStatusMessage {
  #[wasm_bindgen(constructor)]
  pub fn new(#[wasm_bindgen(unchecked_param_type = "StatusMessage")] value: JsValue) -> Result<Self, JsValue> {
    Ok(serde_wasm_bindgen::from_value(value).map(Self)?)
  }

  #[wasm_bindgen(getter)]
  pub fn status(&self) -> String {
    format!("{:#x}", self.0.status)
  }

  #[wasm_bindgen(getter)]
  pub fn message(&self) -> String {
    self.0.message.clone()
  }
}

#[wasm_bindgen(typescript_custom_section)]
const CREDENTIAL_PARAMS: &str = r#"
export interface BitstringStatusListCredentialParams {
  id?: string;
  validFrom?: string;
  validUntil?: string;
  issuer: string;
  context?: string[] | object[];
  type?: string[];
  proof?: object;
  numberOfEntries?: number;
  statusPurposes: StatusPurpose | StatusPurposes[];
  statusMessages?: StatusMessage[];
  ttl?: number;
}

export interface EntryStatus {
  status: number;
  valid: boolean;
  purpose: StatusPurpose;
  message?: StatusMessage;
}
"#;

#[wasm_bindgen(js_name = BitstringStatusListCredential)]
pub struct WasmBitstringStatusListCredential(pub(crate) BitstringStatusListCredential);

#[wasm_bindgen(js_class = BitstringStatusListCredential)]
impl WasmBitstringStatusListCredential {
  #[wasm_bindgen(constructor)]
  pub fn new(
    #[wasm_bindgen(unchecked_param_type = "BitstringStatusListCredentialParams")] params: JsValue,
  ) -> Result<Self, JsValue> {
    let params: CredentialParamsHelper = serde_wasm_bindgen::from_value(params)?;
    let credential = BitstringStatusListCredentialBuilder::from(params)
      .build()
      .map_err(|e| JsError::from(e))?;

    Ok(Self(credential))
  }

  #[wasm_bindgen(js_name = fromCredential)]
  pub fn from_credential(credential: &WasmCredentialV2) -> Result<Self, JsError> {
    Ok(Self(credential.clone().0.try_into()?))
  }

  #[wasm_bindgen(getter)]
  pub fn id(&self) -> Option<String> {
    self.0.id().map(Url::to_string)
  }

  #[wasm_bindgen(js_name = toCredential)]
  pub fn to_credential(&self) -> WasmCredentialV2 {
    WasmCredentialV2(self.0.as_ref().clone())
  }

  #[wasm_bindgen(getter, js_name = statusPurpose, unchecked_return_type = "StatusPurpose[]")]
  pub fn status_purpose(&self) -> Vec<String> {
    self.0.purposes().iter().map(|purpose| purpose.to_string()).collect()
  }

  #[wasm_bindgen(getter, js_name = encodedList)]
  pub fn encoded_list(&self) -> String {
    self.0.encoded_list().to_string()
  }

  #[wasm_bindgen(getter)]
  pub fn ttl(&self) -> Option<u64> {
    self.0.ttl()
  }

  #[wasm_bindgen(getter, js_name = entrySize)]
  pub fn entry_size(&self) -> u32 {
    self.0.entry_size() as u32
  }

  #[wasm_bindgen(js_name = getEntryStatus, unchecked_return_type = "EntryStatus")]
  pub fn get_entry_status(&self, index: usize, purpose: &str) -> Result<JsValue, JsError> {
    let purpose = purpose.parse()?;
    let status = self.0.entry(index, &purpose)?;
    Ok(serde_wasm_bindgen::to_value(&status)?)
  }

  #[wasm_bindgen(js_name = setEntryStatus)]
  pub fn set_entry_status(
    &mut self,
    #[wasm_bindgen(unchecked_param_type = "bool | StatusMessage")] entry: &WasmBitstringStatusListEntry,
    value: &JsValue,
  ) -> Result<(), JsError> {
    let status_value = if let Some(flag) = value.as_bool() {
      StatusValue::Flag(flag)
    } else {
      StatusValue::Message(&serde_wasm_bindgen::from_value(value.clone())?)
    };

    self.0.update().set_entry(&entry.0, status_value)?;

    Ok(())
  }

  #[wasm_bindgen(js_name = toJSON)]
  pub fn to_json(&self) -> Result<String, JsError> {
    Ok(serde_json::to_string(&self.0)?)
  }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialParamsHelper {
  id: Option<Url>,
  valid_from: Option<Timestamp>,
  valid_until: Option<Timestamp>,
  issuer: Url,
  #[serde(default)]
  context: Vec<Context>,
  #[serde(default)]
  type_: Vec<String>,
  proof: Option<Proof>,
  number_of_entries: Option<usize>,
  status_purposes: OneOrMany<StatusPurpose>,
  #[serde(default)]
  status_messages: Vec<StatusMessage>,
  ttl: Option<u64>,
}

impl From<CredentialParamsHelper> for BitstringStatusListCredentialBuilder {
  fn from(params: CredentialParamsHelper) -> Self {
    let mut builder = BitstringStatusListCredentialBuilder::default()
      .issuer(params.issuer)
      .status_purposes(params.status_purposes)
      .status_messages(params.status_messages);

    if let Some(id) = params.id {
      builder = builder.id(id);
    }
    if let Some(valid_from) = params.valid_from {
      builder = builder.valid_from(valid_from);
    }
    if let Some(valid_until) = params.valid_until {
      builder = builder.valid_until(valid_until);
    }
    builder = params
      .context
      .into_iter()
      .fold(builder, |builder, ctx| builder.context(ctx));
    builder = params
      .type_
      .into_iter()
      .fold(builder, |builder, ty| builder.add_type(ty));

    if let Some(proof) = params.proof {
      builder = builder.proof(proof);
    }
    if let Some(number_of_entries) = params.number_of_entries {
      builder = builder.number_of_entries(number_of_entries);
    }
    if let Some(ttl) = params.ttl {
      builder = builder.ttl(ttl);
    }

    builder
  }
}

fn number_from_either_string_or_number<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
  D: serde::Deserializer<'de>,
{
  use serde::de::Visitor;

  struct EitherStringOrNumber;
  impl<'de> Visitor<'de> for EitherStringOrNumber {
    type Value = usize;
    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
      formatter.write_str("a string-encoded unsigned number or an unsigned number")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
      E: serde::de::Error,
    {
      v.parse::<usize>().map_err(E::custom)
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
    where
      E: serde::de::Error,
    {
      Ok(v as usize)
    }
  }

  deserializer.deserialize_any(EitherStringOrNumber)
}
