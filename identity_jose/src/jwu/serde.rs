// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::str;

use crate::error::Error;
use crate::error::Result;
use crate::jose::JoseHeader;
use crate::jws::JwsHeader;

// The default value of the "b64" header parameter
const DEFAULT_B64: bool = true;

// Claims defined in the base JWE/JWS RFCs
const PREDEFINED: &[&str] = &[
  "alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#s256", "typ", "cty", "crit", "enc", "zip", "epk", "apu", "apv",
  "iv", "tag", "p2s", "p2c",
];

// The extension parameters supported by this library.
const PERMITTED_CRITS: &[&str] = &["b64"];

pub(crate) fn parse_utf8(slice: &(impl AsRef<[u8]> + ?Sized)) -> Result<&str> {
  str::from_utf8(slice.as_ref()).map_err(Error::InvalidUtf8)
}

pub(crate) fn filter_non_empty_bytes<'a, T, U>(value: T) -> Option<&'a [u8]>
where
  T: Into<Option<&'a U>>,
  U: AsRef<[u8]> + ?Sized + 'a,
{
  value.into().map(AsRef::as_ref).filter(|value| !value.is_empty())
}

pub(crate) fn create_message(header: &[u8], claims: &[u8]) -> Vec<u8> {
  let capacity: usize = header.len() + 1 + claims.len();
  let mut message: Vec<u8> = Vec::with_capacity(capacity);

  message.extend(header);
  message.push(b'.');
  message.extend(claims);
  message
}

pub(crate) fn extract_b64(header: Option<&JwsHeader>) -> bool {
  header.and_then(JwsHeader::b64).unwrap_or(DEFAULT_B64)
}

pub(crate) fn validate_jws_headers(protected: Option<&JwsHeader>, unprotected: Option<&JwsHeader>) -> Result<()> {
  validate_disjoint(protected, unprotected)?;
  validate_crit(protected, unprotected)?;
  validate_b64(protected, unprotected)?;

  Ok(())
}

/// Validates that the "crit" parameter satisfies the following requirements:
/// 1. It is integrity protected.
/// 2. It is not encoded as an empty list.
/// 3. It does not contain any header parameters defined by the JOSE JWS/JWA specifications.
/// 4. It's values are contained in the given `permitted` array.
/// 5. All values in "crit" are present in at least one of the `protected` or `unprotected` headers.
///
/// See (<https://www.rfc-editor.org/rfc/rfc7515#section-4.1.11>)
pub(crate) fn validate_crit<T>(protected: Option<&T>, unprotected: Option<&T>) -> Result<()>
where
  T: JoseHeader,
{
  // The "crit" parameter MUST be integrity protected
  if unprotected.map(|header| header.has_claim("crit")).unwrap_or_default() {
    return Err(Error::InvalidParam("unprotected crit"));
  }

  let values: Option<&[String]> = protected.and_then(|header| header.common().crit());

  // The "crit" parameter MUST NOT be an empty list
  if values.map(|values| values.is_empty()).unwrap_or_default() {
    return Err(Error::InvalidParam("empty crit"));
  }

  let values: &[String] = values.unwrap_or_default();

  for value in values {
    // The "crit" parameter MUST NOT contain any header parameters defined by
    // the JOSE JWS/JWA specifications.
    if PREDEFINED.contains(&&**value) {
      return Err(Error::InvalidParam("crit contains pre-defined parameters"));
    }

    // The "crit" parameter MUST be understood by the application.
    if !PERMITTED_CRITS.contains(&AsRef::<str>::as_ref(value)) {
      return Err(Error::InvalidParam("unpermitted crit"));
    }

    let exists: bool = protected
      .map(|header| header.has_claim(value))
      .or_else(|| unprotected.map(|header| header.has_claim(value)))
      .unwrap_or_default();

    if !exists {
      return Err(Error::InvalidParam("crit"));
    }
  }

  Ok(())
}

/// Checks that the provided headers satisfy the requirements of (<https://www.rfc-editor.org/rfc/rfc7797#section-3>).
pub(crate) fn validate_b64(protected: Option<&JwsHeader>, unprotected: Option<&JwsHeader>) -> Result<()> {
  // The "b64" parameter MUST be integrity protected
  if unprotected.and_then(JwsHeader::b64).is_some() {
    return Err(Error::InvalidParam("unprotected `b64` parameter"));
  }

  let b64: Option<bool> = protected.and_then(|header| header.b64());
  let crit: Option<&[String]> = protected.and_then(|header| header.crit());

  // The "b64" parameter MUST be included in the "crit" parameter values
  match (b64, crit) {
    (Some(_), Some(values)) if values.iter().any(|value| value == "b64") => Ok(()),
    (Some(_), None) => Err(Error::InvalidParam(
      "`b64` param must be included in the crit parameter values",
    )),
    _ => Ok(()),
  }
}

pub(crate) fn validate_disjoint(protected: Option<&JwsHeader>, unprotected: Option<&JwsHeader>) -> Result<()> {
  let is_disjoint: bool = match (protected, unprotected) {
    (Some(protected), Some(unprotected)) => protected.is_disjoint(unprotected),
    _ => true,
  };

  if is_disjoint {
    Ok(())
  } else {
    Err(Error::InvalidContent(
      "protected and unprotected headers are not disjoint",
    ))
  }
}
