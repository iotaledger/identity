// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use serde::Serialize;

use crate::error::Error;
use crate::error::Result;
use crate::jws::JwsHeader;
use crate::jws::Recipient;
use std::borrow::Cow;

use crate::jwu;

/// A Payload that has been encoded according to the b64 parameter.
pub(super) enum MaybeEncodedPayload<'payload> {
  Encoded(String),
  NotEncoded(&'payload [u8]),
}

impl<'payload> MaybeEncodedPayload<'payload> {
  /// Transform payload according to the b64 extracted from the protected header.  
  /// See: https://tools.ietf.org/html/rfc7797#section-3
  pub(super) fn encode_if_b64(payload: &'payload [u8], protected_header: Option<&JwsHeader>) -> Self {
    if jwu::extract_b64(protected_header) {
      MaybeEncodedPayload::Encoded(jwu::encode_b64(payload))
    } else {
      MaybeEncodedPayload::NotEncoded(payload)
    }
  }

  /// Represent the possibly encoded payload as a byte slice.
  pub(super) fn as_bytes(&self) -> &[u8] {
    match *self {
      Self::Encoded(ref value) => value.as_bytes(),
      Self::NotEncoded(value) => value,
    }
  }

  /// Calls a serialization format dependent validator and converts the possibly encoded payload into
  /// a string that can be used as a non-decoded payload in a JWS.
  pub(super) fn into_non_detached<F>(self, not_encoded_validator: F) -> Result<Cow<'payload, str>>
  where
    F: FnOnce(&[u8]) -> Result<&str>,
  {
    match self {
      Self::Encoded(value) => Ok(Cow::Owned(value)),
      Self::NotEncoded(value) => Ok(Cow::Borrowed(not_encoded_validator(value)?)),
    }
  }
}

impl<'payload> From<MaybeEncodedPayload<'payload>> for Cow<'payload, [u8]> {
  fn from(value: MaybeEncodedPayload<'payload>) -> Self {
    match value {
      MaybeEncodedPayload::Encoded(value) => Cow::Owned(value.into()),
      MaybeEncodedPayload::NotEncoded(value) => Cow::Borrowed(value),
    }
  }
}

// ===================================================================================
//  JWS JSON Serialization encoding utils
// ===================================================================================

pub(super) fn validate_headers_json_serialization(recipient: Recipient<'_>) -> Result<()> {
  let Recipient { protected, unprotected } = recipient;
  if protected.is_none() && unprotected.is_none() {
    return Err(Error::MissingHeader("at least one header must be set"));
  };

  jwu::validate_jws_headers(protected, unprotected)
}

#[derive(Serialize)]
pub(super) struct JwsSignature<'unprotected> {
  #[serde(skip_serializing_if = "Option::is_none")]
  pub(super) header: Option<&'unprotected JwsHeader>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub(super) protected: Option<String>,
  pub(super) signature: String,
}

#[derive(Serialize)]
pub(super) struct Flatten<'payload, 'unprotected> {
  #[serde(skip_serializing_if = "Option::is_none")]
  pub(super) payload: Option<&'payload str>,
  #[serde(flatten)]
  pub(super) signature: JwsSignature<'unprotected>,
}

impl Flatten<'_, '_> {
  pub(super) fn to_json(&self) -> Result<String> {
    serde_json::to_string(&self).map_err(Error::InvalidJson)
  }
}

#[derive(Serialize)]
pub(super) struct General<'payload, 'unprotected> {
  #[serde(skip_serializing_if = "Option::is_none")]
  pub(super) payload: Option<&'payload str>,
  pub(super) signatures: Vec<JwsSignature<'unprotected>>,
}

impl General<'_, '_> {
  pub(super) fn to_json(&self) -> Result<String> {
    serde_json::to_string(&self).map_err(Error::InvalidJson)
  }
}

pub(super) struct SigningData {
  pub(super) signing_input: Box<[u8]>,
  pub(super) protected_header: Option<String>,
}

impl SigningData {
  pub(super) fn new(processed_payload: &[u8], protected_header: Option<&JwsHeader>) -> Result<Self> {
    let protected_header: Option<String> = protected_header.map(jwu::encode_b64_json).transpose()?;
    let signing_input: Box<[u8]> = jwu::create_message(
      protected_header.as_deref().map(str::as_bytes).unwrap_or_default(),
      processed_payload,
    )
    .into();
    Ok(SigningData {
      signing_input,
      protected_header,
    })
  }

  pub(super) fn into_signature<'unprotected>(
    self,
    signature: &[u8],
    unprotected_header: Option<&'unprotected JwsHeader>,
  ) -> JwsSignature<'unprotected> {
    JwsSignature {
      protected: self.protected_header,
      header: unprotected_header,
      signature: jwu::encode_b64(signature),
    }
  }
}
