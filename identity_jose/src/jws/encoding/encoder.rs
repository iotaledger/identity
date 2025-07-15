// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use self::encoder_state::ReadyState;
use self::encoder_state::RecipientProcessingState;

use crate::error::Error;
use crate::error::Result;
use crate::jws::encoding::utils::JwsSignature;
use crate::jws::CharSet;
use crate::jws::JwsHeader;
use crate::jws::Recipient;
use std::borrow::Cow;

use crate::jwu;

use super::utils;
use super::utils::Flatten;
use super::utils::General;
use super::utils::MaybeEncodedPayload;
use super::utils::SigningData;

/// A JWS encoder supporting the Compact JWS serialization format.
///
/// See (<https://www.rfc-editor.org/rfc/rfc7515#section-3.1>).  
pub struct CompactJwsEncoder<'a> {
  protected_header: String,
  processed_payload: Option<Cow<'a, str>>,
  signing_input: Box<[u8]>,
}

#[derive(Debug, Copy, Clone)]
/// Options determining whether the payload is detached and if not
/// which additional requirements the payload must satisfy.
pub enum CompactJwsEncodingOptions {
  /// Includes the payload in the JWS, i.e. non-detached mode.
  NonDetached {
    /// The requirements towards the character set when encoding a JWS.
    charset_requirements: CharSet,
  },
  /// Does not include the payload in the JWS, i.e. detached mode.
  Detached,
}

impl<'payload> CompactJwsEncoder<'payload> {
  /// Start the process of encoding a JWS. This prepares the values that need to be signed. See
  /// [`Self::into_jws`](CompactJwsEncoder::into_jws()) for information on how to proceed.
  ///
  /// # Options
  /// This will prepare a JWS with a non-detached payload that satisfies the requirements of [`CharSet::Default`]. See
  /// [`Self::new_with_options`](CompactJwsEncoder::new_with_options()) for alternative configurations.  
  pub fn new(payload: &'payload [u8], protected_header: &JwsHeader) -> Result<Self> {
    Self::new_with_options(
      payload,
      protected_header,
      CompactJwsEncodingOptions::NonDetached {
        charset_requirements: CharSet::Default,
      },
    )
  }

  /// Similar to [`Self::new`](CompactJwsEncoder::new), but with more configuration options. See
  /// [`CompactJwsEncodingOptions`].
  pub fn new_with_options(
    payload: &'payload [u8],
    protected_header: &JwsHeader,
    options: CompactJwsEncodingOptions,
  ) -> Result<Self> {
    Self::validate_header(protected_header)?;
    let encoded_protected_header: String = jwu::encode_b64_json(protected_header)?;
    let maybe_encoded: MaybeEncodedPayload<'_> = MaybeEncodedPayload::encode_if_b64(payload, Some(protected_header));
    let signing_input: Box<[u8]> =
      jwu::create_message(encoded_protected_header.as_bytes(), maybe_encoded.as_bytes()).into();

    let processed_payload: Option<Cow<'payload, str>> = {
      if let CompactJwsEncodingOptions::NonDetached { charset_requirements } = options {
        Some(maybe_encoded.into_non_detached(|input| charset_requirements.validate(input))?)
      } else {
        None
      }
    };

    Ok(Self {
      protected_header: encoded_protected_header,
      processed_payload,
      signing_input,
    })
  }

  /// The signing input. This has been computed according to the
  /// [JWS Signing Input Formula](https://www.rfc-editor.org/rfc/rfc7797#section-3) using the
  /// protected header and payload given in the constructor.
  pub fn signing_input(&self) -> &[u8] {
    &self.signing_input
  }

  fn validate_header(protected_header: &JwsHeader) -> Result<()> {
    jwu::validate_jws_headers(Some(protected_header), None)
  }

  /// convert this into a JWS. The `signature` value is expected to be
  /// the signature on [`Self::signing_input`] by the private key corresponding to the public key
  /// referenced in the JWS header in accordance with the `alg` value of said header.
  pub fn into_jws(self, signature: &[u8]) -> String {
    let signature = jwu::encode_b64(signature);
    if let Some(payload) = self.processed_payload {
      format!("{}.{}.{}", self.protected_header, payload, &signature)
    } else {
      format!("{}..{}", self.protected_header, &signature)
    }
  }
}

// ===============================================================================================================================
//  JWS JSON Serialization
// ===============================================================================================================================

// ===================================================================================
//  Flattened JWS Json Serialization
// ===================================================================================

/// An encoder supporting the Flattened JWS JSON Serialiazion format.
///
/// See (<https://www.rfc-editor.org/rfc/rfc7515#section-7.2.2>).
pub struct FlattenedJwsEncoder<'payload, 'unprotected> {
  processed_payload: Option<Cow<'payload, str>>,
  signing_data: SigningData,
  unprotected_header: Option<&'unprotected JwsHeader>,
}

impl<'payload, 'unprotected> FlattenedJwsEncoder<'payload, 'unprotected> {
  /// Start the process of encoding a JWS. This prepares the values that need to be signed. See
  /// [`Self::into_jws`](CompactJwsEncoder::into_jws()) for information on how to proceed.
  pub fn new(payload: &'payload [u8], recipient: Recipient<'unprotected>, detached: bool) -> Result<Self> {
    utils::validate_headers_json_serialization(recipient)?;
    let maybe_encoded: MaybeEncodedPayload<'_> = MaybeEncodedPayload::encode_if_b64(payload, recipient.protected);
    let signing_data: SigningData = SigningData::new(maybe_encoded.as_bytes(), recipient.protected)?;
    let processed_payload: Option<Cow<'payload, str>> = if !detached {
      // The only additional validation required when processing the payload to be used with the flattened JWS Json
      // serialization is that it is a valid JSON value, but we check for that later during serialization.
      Some(maybe_encoded.into_non_detached(|bytes| std::str::from_utf8(bytes).map_err(Error::InvalidUtf8))?)
    } else {
      None
    };

    Ok(Self {
      processed_payload,
      signing_data,
      unprotected_header: recipient.unprotected,
    })
  }

  /// The signing input. This has been computed according to the
  /// [JWS Signing Input Formula](https://www.rfc-editor.org/rfc/rfc7797#section-3) using the
  /// protected header from the [`Recipient`] and payload given in the constructor respectively.
  pub fn signing_input(&self) -> &[u8] {
    &self.signing_data.signing_input
  }

  /// Convert this into a JWS. The `signature` value is expected to be
  /// the signature on [`Self::signing_input`] by the private key corresponding to the public key
  /// referenced in the JWS header in accordance with the `alg` value of said header.
  pub fn into_jws(self, signature: &[u8]) -> Result<String> {
    let FlattenedJwsEncoder {
      processed_payload,
      signing_data,
      unprotected_header,
    } = self;

    Flatten {
      payload: processed_payload.as_deref(),
      signature: signing_data.into_signature(signature, unprotected_header),
    }
    .to_json()
  }
}

// ===================================================================================
//  General JWS Json Serialization
// ===================================================================================

mod encoder_state {
  use super::utils::SigningData;
  use crate::jws::JwsHeader;
  pub struct ReadyState;
  pub struct RecipientProcessingState<'unprotected> {
    pub(super) signing_data: SigningData,
    pub(super) unprotected_header: Option<&'unprotected JwsHeader>,
  }
}

/// A General JWS Encoder that is currently processing the latest [`Recipient`].
pub type RecipientProcessingEncoder<'payload, 'unprotected> =
  GeneralJwsEncoder<'payload, 'unprotected, RecipientProcessingState<'unprotected>>;

/// An encoder for the General JWS JSON Serialization format.
pub struct GeneralJwsEncoder<'payload, 'unprotected, STATE = ReadyState> {
  partially_processed_payload: Cow<'payload, [u8]>,
  signatures: Vec<JwsSignature<'unprotected>>,
  detached: bool,
  b64: bool,
  state: STATE,
}

impl<'payload, 'unprotected> GeneralJwsEncoder<'payload, 'unprotected> {
  /// Start encoding a JWS with the General JWS JSON serialization format.
  /// This will prepare the signing input which must be signed as a next step. See
  /// [`RecipientProcessingEncoder::set_signature`](RecipientProcessingEncoder::set_signature()).
  pub fn new(
    payload: &'payload [u8],
    first_recipient: Recipient<'unprotected>,
    detached: bool,
  ) -> Result<RecipientProcessingEncoder<'payload, 'unprotected>> {
    utils::validate_headers_json_serialization(first_recipient)?;
    let partially_processed_payload: Cow<'payload, [u8]> =
      MaybeEncodedPayload::encode_if_b64(payload, first_recipient.protected).into();
    let signing_data = SigningData::new(&partially_processed_payload, first_recipient.protected)?;
    Ok(RecipientProcessingEncoder {
      partially_processed_payload,
      signatures: Vec::new(),
      detached,
      b64: jwu::extract_b64(first_recipient.protected),
      state: RecipientProcessingState {
        signing_data,
        unprotected_header: first_recipient.unprotected,
      },
    })
  }

  /// Start the process of creating an additional signature entry corresponding to the
  /// given `recipient`.
  pub fn add_recipient(
    self,
    recipient: Recipient<'unprotected>,
  ) -> Result<RecipientProcessingEncoder<'payload, 'unprotected>> {
    // Ensure that the b64 value is consistent across all signatures.
    let new_b64 = jwu::extract_b64(recipient.protected);
    if new_b64 != self.b64 {
      return Err(Error::InvalidParam("b64"));
    };
    // Validate headers
    utils::validate_headers_json_serialization(recipient)?;

    let signing_data = SigningData::new(&self.partially_processed_payload, recipient.protected)?;
    let state = RecipientProcessingState {
      signing_data,
      unprotected_header: recipient.unprotected,
    };
    let Self {
      partially_processed_payload,
      signatures,
      detached,
      b64,
      ..
    } = self;
    Ok(RecipientProcessingEncoder {
      partially_processed_payload,
      signatures,
      detached,
      b64,
      state,
    })
  }

  /// Finalize the encoding process and obtain a JWS serialized
  /// according to the General JWS JSON serialization format.
  pub fn into_jws(self) -> Result<String> {
    let GeneralJwsEncoder {
      partially_processed_payload,
      signatures,
      detached,
      ..
    } = self;
    let general: General<'_, '_> = {
      if detached {
        General {
          payload: None,
          signatures,
        }
      } else {
        General {
          payload: Some(
            std::str::from_utf8(&partially_processed_payload).map_err(|_| Error::InvalidContent("invalid utf8"))?,
          ),
          signatures,
        }
      }
    };
    general.to_json()
  }
}

impl<'payload, 'unprotected> RecipientProcessingEncoder<'payload, 'unprotected> {
  /// The signing input to be signed for the recipient currently being processed.
  /// This has been computed according to the
  /// [JWS Signing Input Formula](https://www.rfc-editor.org/rfc/rfc7797#section-3) using the
  /// protected header from the latest [`Recipient`] and the payload set in the
  /// [`GeneralJwsEncoder::new`](GeneralJwsEncoder::new()).
  pub fn signing_input(&self) -> &[u8] {
    &self.state.signing_data.signing_input
  }

  /// Set the signature computed in the manner defined for the algorithm present in the
  /// recipient's protected header over the [`signing input`](RecipientProcessingEncoder::signing_input()).
  pub fn set_signature(self, signature: &[u8]) -> GeneralJwsEncoder<'payload, 'unprotected> {
    let Self {
      partially_processed_payload,
      mut signatures,
      b64,
      detached,
      state: RecipientProcessingState {
        unprotected_header,
        signing_data,
      },
    } = self;
    let new_signature = signing_data.into_signature(signature, unprotected_header);
    signatures.push(new_signature);
    GeneralJwsEncoder {
      partially_processed_payload,
      signatures,
      b64,
      detached,
      state: ReadyState {},
    }
  }
}
