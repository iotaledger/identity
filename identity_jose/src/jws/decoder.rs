// Copyright 2020-2025 IOTA Stiftung, Fondazione LINKS
// SPDX-License-Identifier: Apache-2.0

use core::str;
use std::borrow::Cow;

use crate::error::Error;
use crate::error::Result;
use crate::jwk::CompositeAlgId;
use crate::jwk::Jwk;
use crate::jwk::PostQuantumJwk;
use crate::jwk::TraditionalJwk;
use crate::jws::JwsAlgorithm;
use crate::jws::JwsHeader;
use crate::jwu::create_message;
use crate::jwu::decode_b64;
use crate::jwu::decode_b64_json;
use crate::jwu::filter_non_empty_bytes;
use crate::jwu::parse_utf8;
use crate::jwu::validate_jws_headers;

use super::JwsVerifier;
use super::VerificationInput;

/// A cryptographically verified decoded token from a JWS.
///
/// Contains the decoded headers and the raw claims.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct DecodedJws<'a> {
  /// The decoded protected header.
  pub protected: JwsHeader,
  /// The decoded unprotected header.
  pub unprotected: Option<Box<JwsHeader>>,
  /// The decoded raw claims.
  pub claims: Cow<'a, [u8]>,
}

enum DecodedHeaders {
  Protected(JwsHeader),
  Unprotected(JwsHeader),
  Both {
    protected: JwsHeader,
    // Use box to reduce size
    unprotected: Box<JwsHeader>,
  },
}

impl DecodedHeaders {
  fn new(protected: Option<JwsHeader>, unprotected: Option<JwsHeader>) -> Result<Self> {
    match (protected, unprotected) {
      (Some(protected), Some(unprotected)) => Ok(Self::Both {
        protected,
        unprotected: Box::new(unprotected),
      }),
      (Some(protected), None) => Ok(Self::Protected(protected)),
      (None, Some(unprotected)) => Ok(Self::Unprotected(unprotected)),
      (None, None) => Err(Error::MissingHeader("no headers were decoded")),
    }
  }

  fn protected_header(&self) -> Option<&JwsHeader> {
    match self {
      DecodedHeaders::Protected(ref header) => Some(header),
      DecodedHeaders::Both { ref protected, .. } => Some(protected),
      DecodedHeaders::Unprotected(_) => None,
    }
  }

  fn unprotected_header(&self) -> Option<&JwsHeader> {
    match self {
      DecodedHeaders::Unprotected(ref header) => Some(header),
      DecodedHeaders::Both { ref unprotected, .. } => Some(unprotected.as_ref()),
      DecodedHeaders::Protected(_) => None,
    }
  }
}

/// A partially decoded JWS containing claims, and the decoded verification data
/// for its corresponding signature (headers, signing input and signature). This data
/// can be cryptographically verified using a [`JwsVerifier`]. See [`Self::verify`](Self::verify).
pub struct JwsValidationItem<'a> {
  headers: DecodedHeaders,
  signing_input: Box<[u8]>,
  decoded_signature: Box<[u8]>,
  claims: Cow<'a, [u8]>,
}
impl<'a> JwsValidationItem<'a> {
  /// Returns the decoded protected header if it exists.
  pub fn protected_header(&self) -> Option<&JwsHeader> {
    self.headers.protected_header()
  }

  /// Returns the Nonce from the protected header if it is set.
  pub fn nonce(&self) -> Option<&str> {
    self.protected_header().and_then(|header| header.nonce())
  }

  /// Returns the kid from the protected header if it is set.
  pub fn kid(&self) -> Option<&str> {
    self.protected_header().and_then(|header| header.kid())
  }

  /// Returns the decoded unprotected header if it exists.
  pub fn unprotected_header(&self) -> Option<&JwsHeader> {
    self.headers.unprotected_header()
  }

  /// The algorithm parsed from the protected header if it exists.
  pub fn alg(&self) -> Option<JwsAlgorithm> {
    self.protected_header().and_then(|protected| protected.alg())
  }

  /// Returns the JWS claims.
  pub fn claims(&self) -> &[u8] {
    &self.claims
  }

  /// Returns the signing input .
  ///
  /// See [RFC 7515: section 5.2 part 8.](https://www.rfc-editor.org/rfc/rfc7515#section-5.2) and
  /// [RFC 7797 section 3](https://www.rfc-editor.org/rfc/rfc7797#section-3).
  pub fn signing_input(&self) -> &[u8] {
    &self.signing_input
  }

  /// Returns the decoded JWS signature.
  pub fn decoded_signature(&self) -> &[u8] {
    &self.decoded_signature
  }

  /// Constructs [`VerificationInput`] from this data and passes it to the given `verifier` along with the
  /// provided `public_key`.
  ///
  /// # Errors
  /// Apart from the fallible call to [`JwsVerifier::verify`] this method can also error if there is no
  /// `alg` present in the protected header (in which case the verifier cannot be called) or if the given `public_key`
  /// has a different value present in its `alg` field.
  ///
  /// # Note
  /// One may want to perform other validations before calling this method, such as for instance checking the nonce
  /// (see [`Self::nonce`](Self::nonce())).
  pub fn verify<T>(self, verifier: &T, public_key: &Jwk) -> Result<DecodedJws<'a>>
  where
    T: JwsVerifier,
  {
    // Destructure data
    let JwsValidationItem {
      headers,
      claims,
      signing_input,
      decoded_signature,
    } = self;
    let (protected, unprotected): (JwsHeader, Option<Box<JwsHeader>>) = match headers {
      DecodedHeaders::Protected(protected) => (protected, None),
      DecodedHeaders::Both { protected, unprotected } => (protected, Some(unprotected)),
      DecodedHeaders::Unprotected(_) => return Err(Error::MissingHeader("missing protected header")),
    };

    // Extract and validate alg from the protected header.
    let alg: JwsAlgorithm = protected.alg().ok_or(Error::ProtectedHeaderWithoutAlg)?;
    public_key.check_alg(alg.name())?;

    // Construct verification input
    let input = VerificationInput {
      alg,
      signing_input,
      decoded_signature,
    };
    // Call verifier
    verifier
      .verify(input, public_key)
      .map_err(Error::SignatureVerificationError)?;

    Ok(DecodedJws {
      protected,
      unprotected,
      claims,
    })
  }

  /// Hybrid signature verification.
  pub fn verify_hybrid<TRV, PQV>(
    self,
    traditional_verifier: &TRV,
    pq_verifier: &PQV,
    traditional_pk: &TraditionalJwk,
    pq_pk: &PostQuantumJwk,
  ) -> Result<DecodedJws<'a>>
  where
    TRV: JwsVerifier,
    PQV: JwsVerifier,
  {
    // Destructure data
    let JwsValidationItem {
      headers,
      claims,
      signing_input,
      decoded_signature,
    } = self;

    let (protected, unprotected): (JwsHeader, Option<Box<JwsHeader>>) = match headers {
      DecodedHeaders::Protected(protected) => (protected, None),
      DecodedHeaders::Both { protected, unprotected } => (protected, Some(unprotected)),
      DecodedHeaders::Unprotected(_) => return Err(Error::MissingHeader("missing protected header")),
    };

    // Extract and validate alg from the protected header.
    let alg: JwsAlgorithm = protected.alg().ok_or(Error::ProtectedHeaderWithoutAlg)?;

    // M' = Prefix || Domain || len(ctx) || ctx || M
    let (t_alg, pq_alg, signing_input, traditional_signature_len) = match alg {
      JwsAlgorithm::IdMldsa44Ed25519 => {
        //Prefix: CompositeAlgorithmSignatures2025
        let mut input = b"CompositeAlgorithmSignatures2025".to_vec();

        //Domain: id-MLDSA44-Ed25519
        input.extend_from_slice(CompositeAlgId::IdMldsa44Ed25519.domain());

        //len(ctx) = 0
        input.push(0x00);

        //M
        input.extend(signing_input);
        (
          JwsAlgorithm::EdDSA,
          JwsAlgorithm::IdMldsa44Ed25519,
          input,
          crypto::signatures::ed25519::Signature::LENGTH,
        )
      }
      JwsAlgorithm::IdMldsa65Ed25519 => {
        //Prefix: CompositeAlgorithmSignatures2025
        let mut input = b"CompositeAlgorithmSignatures2025".to_vec();

        //Domain: id-MLDSA65-Ed25519
        input.extend_from_slice(CompositeAlgId::IdMldsa65Ed25519.domain());
        
        //len(ctx) = 0
        input.push(0x00);

        //M
        input.extend(signing_input);

        (
          JwsAlgorithm::EdDSA,
          JwsAlgorithm::IdMldsa65Ed25519,
          input,
          crypto::signatures::ed25519::Signature::LENGTH,
        )
      }
      _ => return Err(Error::JwsAlgorithmParsingError),
    };
    
    traditional_pk.check_alg(t_alg.name())?;

    let extracted_signature_t = &decoded_signature[..traditional_signature_len];
    let extracted_signature_pq = &decoded_signature[traditional_signature_len..];

    // Construct verification input
    let input1 = VerificationInput {
      alg: t_alg,
      signing_input: signing_input.clone().into(),
      decoded_signature: extracted_signature_t.into(),
    };

    // Call the traditional verifier
    traditional_verifier
      .verify(input1, &traditional_pk)
      .map_err(Error::SignatureVerificationError)?;

    let input2 = VerificationInput {
      alg: pq_alg,
      signing_input: signing_input.into(),
      decoded_signature: extracted_signature_pq.into(),
    };
    
    // Call the PQ verifier
    pq_verifier
      .verify(input2, &pq_pk)
      .map_err(Error::SignatureVerificationError)?;
    
    Ok(DecodedJws {
      protected,
      unprotected,
      claims,
    })
  }
}

// =============================================================================================
// Format dependent deserializable helper structs used by the decoder
// =============================================================================================
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct JwsSignature<'a> {
  header: Option<JwsHeader>,
  protected: Option<&'a str>,
  signature: &'a str,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct General<'a> {
  payload: Option<&'a str>,
  signatures: Vec<JwsSignature<'a>>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Flatten<'a> {
  payload: Option<&'a str>,
  #[serde(flatten)]
  signature: JwsSignature<'a>,
}

// =============================================================================
// Decoder
// =============================================================================

/// The [`Decoder`] is responsible for decoding a JWS into one or more [`JwsValidationItems`](JwsValidationItem).
#[derive(Debug, Clone)]
pub struct Decoder;

impl Decoder {
  /// Constructs a new [`Decoder`].
  pub fn new() -> Decoder {
    Self
  }

  /// Decode a JWS encoded with the [JWS compact serialization format](https://www.rfc-editor.org/rfc/rfc7515#section-3.1).
  ///
  ///
  /// ### Working with detached payloads
  ///
  /// A detached payload can be supplied in the `detached_payload` parameter.
  /// [More Info](https://tools.ietf.org/html/rfc7515#appendix-F)
  pub fn decode_compact_serialization<'b>(
    &self,
    jws_bytes: &'b [u8],
    detached_payload: Option<&'b [u8]>,
  ) -> Result<JwsValidationItem<'b>> {
    let mut segments = jws_bytes.split(|byte| *byte == b'.');

    let (Some(protected), Some(payload), Some(signature), None) =
      (segments.next(), segments.next(), segments.next(), segments.next())
    else {
      return Err(Error::InvalidContent("invalid segments count"));
    };

    let signature: JwsSignature<'_> = JwsSignature {
      header: None,
      protected: Some(parse_utf8(protected)?),
      signature: parse_utf8(signature)?,
    };

    let payload = Self::expand_payload(detached_payload, Some(payload))?;

    self.decode_signature(payload, signature)
  }

  /// Decode a JWS encoded with the [flattened JWS JSON serialization format](https://www.rfc-editor.org/rfc/rfc7515#section-7.2.2).
  ///
  /// ### Working with detached payloads
  ///
  /// A detached payload can be supplied in the `detached_payload` parameter.
  /// [More Info](https://tools.ietf.org/html/rfc7515#appendix-F)
  pub fn decode_flattened_serialization<'b>(
    &self,
    jws_bytes: &'b [u8],
    detached_payload: Option<&'b [u8]>,
  ) -> Result<JwsValidationItem<'b>> {
    let data: Flatten<'_> = serde_json::from_slice(jws_bytes).map_err(Error::InvalidJson)?;
    let payload = Self::expand_payload(detached_payload, data.payload)?;
    let signature = data.signature;
    self.decode_signature(payload, signature)
  }

  fn decode_signature<'a, 'b>(
    &self,
    payload: &'b [u8],
    jws_signature: JwsSignature<'a>,
  ) -> Result<JwsValidationItem<'b>> {
    let JwsSignature {
      header: unprotected_header,
      protected,
      signature,
    } = jws_signature;

    let protected_header: Option<JwsHeader> = protected.map(decode_b64_json).transpose()?;
    validate_jws_headers(protected_header.as_ref(), unprotected_header.as_ref())?;

    let protected_bytes: &[u8] = protected.map(str::as_bytes).unwrap_or_default();
    let signing_input: Box<[u8]> = create_message(protected_bytes, payload).into();
    let decoded_signature: Box<[u8]> = decode_b64(signature)?.into();

    let claims: Cow<'b, [u8]> = if protected_header.as_ref().and_then(|value| value.b64()).unwrap_or(true) {
      Cow::Owned(decode_b64(payload)?)
    } else {
      Cow::Borrowed(payload)
    };

    Ok(JwsValidationItem {
      headers: DecodedHeaders::new(protected_header, unprotected_header)?,
      signing_input,
      decoded_signature,
      claims,
    })
  }

  fn expand_payload<'b>(
    detached_payload: Option<&'b [u8]>,
    parsed_payload: Option<&'b (impl AsRef<[u8]> + ?Sized)>,
  ) -> Result<&'b [u8]> {
    match (detached_payload, filter_non_empty_bytes(parsed_payload)) {
      (Some(payload), None) => Ok(payload),
      (None, Some(payload)) => Ok(payload),
      (Some(_), Some(_)) => Err(Error::InvalidContent("multiple payloads")),
      (None, None) => Err(Error::InvalidContent("missing payload")),
    }
  }
}

// =======================================
// General JWS JSON serialization support
// =======================================

/// An iterator over the [`JwsValidationItems`](JwsValidationItem) corresponding to the
/// signatures in a JWS encoded with the general JWS JSON serialization format.  
pub struct JwsValidationIter<'decoder, 'payload, 'signatures> {
  decoder: &'decoder Decoder,
  signatures: std::vec::IntoIter<JwsSignature<'signatures>>,
  payload: &'payload [u8],
}

impl<'payload> Iterator for JwsValidationIter<'_, 'payload, '_> {
  type Item = Result<JwsValidationItem<'payload>>;

  fn next(&mut self) -> Option<Self::Item> {
    self
      .signatures
      .next()
      .map(|signature| self.decoder.decode_signature(self.payload, signature))
  }
}

impl Decoder {
  /// Decode a JWS encoded with the [general JWS JSON serialization format](https://www.rfc-editor.org/rfc/rfc7515#section-7.2.1)
  ///
  ///  
  /// ### Working with detached payloads
  /// A detached payload can be supplied in the `detached_payload` parameter.
  /// [More Info](https://tools.ietf.org/html/rfc7515#appendix-F)
  pub fn decode_general_serialization<'decoder, 'data>(
    &'decoder self,
    jws_bytes: &'data [u8],
    detached_payload: Option<&'data [u8]>,
  ) -> Result<JwsValidationIter<'decoder, 'data, 'data>> {
    let data: General<'data> = serde_json::from_slice(jws_bytes).map_err(Error::InvalidJson)?;

    let payload = Self::expand_payload(detached_payload, data.payload)?;
    let signatures = data.signatures;

    Ok(JwsValidationIter {
      decoder: self,
      payload,
      signatures: signatures.into_iter(),
    })
  }
}

impl Default for Decoder {
  fn default() -> Self {
    Self::new()
  }
}

#[cfg(test)]
mod tests {
  use crate::jwt::JwtClaims;

  use super::*;

  const RFC_7515_APPENDIX_EXAMPLE_CLAIMS: &str = r#"
  {
    "iss":"joe",
    "exp":1300819380,
    "http://example.com/is_root":true
  }
  "#;

  const SIGNING_INPUT_ES256_RFC_7515_APPENDIX_EXAMPLE: &[u8] = &[
    101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 70, 85, 122, 73, 49, 78, 105, 74, 57, 46, 101, 121, 74, 112, 99,
    51, 77, 105, 79, 105, 74, 113, 98, 50, 85, 105, 76, 65, 48, 75, 73, 67, 74, 108, 101, 72, 65, 105, 79, 106, 69,
    122, 77, 68, 65, 52, 77, 84, 107, 122, 79, 68, 65, 115, 68, 81, 111, 103, 73, 109, 104, 48, 100, 72, 65, 54, 76,
    121, 57, 108, 101, 71, 70, 116, 99, 71, 120, 108, 76, 109, 78, 118, 98, 83, 57, 112, 99, 49, 57, 121, 98, 50, 57,
    48, 73, 106, 112, 48, 99, 110, 86, 108, 102, 81,
  ];

  // Test https://www.rfc-editor.org/rfc/rfc7515#appendix-A.6
  #[test]
  fn rfc7515_appendix_a_6() {
    let general_jws_json_serialized: &str = r#"
    {
      "payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
      "signatures": [
        {
          "protected": "eyJhbGciOiJSUzI1NiJ9",
          "header": {
            "kid": "2010-12-29"
          },
          "signature": "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"
        },
        {
          "protected": "eyJhbGciOiJFUzI1NiJ9",
          "header": {
            "kid": "e9bc097a-ce51-4036-9562-d2ade882db0d"
          },
          "signature": "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
        }
      ]
    }"#;

    let claims: JwtClaims<serde_json::Value> = serde_json::from_str(RFC_7515_APPENDIX_EXAMPLE_CLAIMS).unwrap();

    let decoder = Decoder::new();

    let mut signature_iter = decoder
      .decode_general_serialization(general_jws_json_serialized.as_bytes(), None)
      .unwrap()
      .filter_map(|decoded| decoded.ok());

    // Check that the lifetimes are not overly restrictive:
    let first_signature_decoding = signature_iter.next().unwrap();
    let second_signature_decoding = signature_iter.next().unwrap();
    drop(signature_iter);

    // Check assertions for the first signature:
    assert_eq!(first_signature_decoding.alg().unwrap(), JwsAlgorithm::RS256);
    assert_eq!(
      first_signature_decoding
        .unprotected_header()
        .and_then(|value| value.kid())
        .unwrap(),
      "2010-12-29"
    );
    let decoded_claims: JwtClaims<serde_json::Value> =
      serde_json::from_slice(first_signature_decoding.claims()).unwrap();
    assert_eq!(claims, decoded_claims);

    // Check assertions for the second signature:
    assert_eq!(second_signature_decoding.alg().unwrap(), JwsAlgorithm::ES256);
    assert_eq!(
      second_signature_decoding
        .unprotected_header()
        .and_then(|value| value.kid())
        .unwrap(),
      "e9bc097a-ce51-4036-9562-d2ade882db0d"
    );

    let decoded_claims: JwtClaims<serde_json::Value> =
      serde_json::from_slice(second_signature_decoding.claims()).unwrap();
    assert_eq!(decoded_claims, claims);
    assert_eq!(
      SIGNING_INPUT_ES256_RFC_7515_APPENDIX_EXAMPLE,
      second_signature_decoding.signing_input()
    );
  }

  // Test https://www.rfc-editor.org/rfc/rfc7515#appendix-A.7
  #[test]
  fn rfc7515_appendix_a_7() {
    let flattened_jws_json_serialized: &str = r#"
    {
      "payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
      "protected":"eyJhbGciOiJFUzI1NiJ9",
      "header": {"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},
      "signature": "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
     }
    "#;

    let claims: JwtClaims<serde_json::Value> = serde_json::from_str(RFC_7515_APPENDIX_EXAMPLE_CLAIMS).unwrap();
    let decoder = Decoder::new();
    let decoded = decoder
      .decode_flattened_serialization(flattened_jws_json_serialized.as_bytes(), None)
      .unwrap();
    assert_eq!(decoded.alg().unwrap(), JwsAlgorithm::ES256);
    assert_eq!(
      decoded.unprotected_header().and_then(|value| value.kid()).unwrap(),
      "e9bc097a-ce51-4036-9562-d2ade882db0d"
    );

    assert_eq!(decoded.signing_input(), SIGNING_INPUT_ES256_RFC_7515_APPENDIX_EXAMPLE);
    let decoded_claims: JwtClaims<serde_json::Value> = serde_json::from_slice(decoded.claims()).unwrap();
    assert_eq!(decoded_claims, claims);
  }
}
