// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::fmt::Display;
use core::fmt::Formatter;
use core::str::FromStr;
use std::borrow::Cow;

use crate::error::Error;
use crate::error::Result;

const ED25519_VERIFICATION_KEY_2018_STR: &str = "Ed25519VerificationKey2018";
const X25519_KEY_AGREEMENT_KEY_2019_STR: &str = "X25519KeyAgreementKey2019";
const JSON_WEB_KEY_METHOD_TYPE: &str = "JsonWebKey";
const JSON_WEB_KEY_2020_STR: &str = "JsonWebKey2020";

/// verification method types.
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct MethodType(Cow<'static, str>);

impl MethodType {
  /// The `Ed25519VerificationKey2018` method type.
  pub const ED25519_VERIFICATION_KEY_2018: Self = Self(Cow::Borrowed(ED25519_VERIFICATION_KEY_2018_STR));
  /// The `X25519KeyAgreementKey2019` method type.
  pub const X25519_KEY_AGREEMENT_KEY_2019: Self = Self(Cow::Borrowed(X25519_KEY_AGREEMENT_KEY_2019_STR));
  /// A verification method for use with JWT verification as prescribed by the [`Jwk`](::identity_jose::jwk::Jwk)
  /// in the [`publicKeyJwk`](crate::MethodData::PublicKeyJwk) entry.
  #[deprecated(since = "1.3.0", note = "use JSON_WEB_KEY_2020 instead")]
  pub const JSON_WEB_KEY: Self = Self(Cow::Borrowed(JSON_WEB_KEY_METHOD_TYPE));
  /// A verification method for use with JWT verification as prescribed by the [`Jwk`](::identity_jose::jwk::Jwk)
  /// in the [`publicKeyJwk`](crate::MethodData::PublicKeyJwk) entry.
  pub const JSON_WEB_KEY_2020: Self = Self(Cow::Borrowed(JSON_WEB_KEY_2020_STR));
  /// Construct a custom method type.
  pub fn custom(type_: impl AsRef<str>) -> Self {
    Self(Cow::Owned(type_.as_ref().to_owned()))
  }
}

impl MethodType {
  /// Returns the string representation of a [`MethodType`].
  pub fn as_str(&self) -> &str {
    &self.0
  }
}

impl AsRef<str> for MethodType {
  fn as_ref(&self) -> &str {
    self.0.as_ref()
  }
}

impl Display for MethodType {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    f.write_str(self.as_str())
  }
}

impl FromStr for MethodType {
  type Err = Error;

  fn from_str(string: &str) -> Result<Self, Self::Err> {
    match string {
      ED25519_VERIFICATION_KEY_2018_STR => Ok(Self::ED25519_VERIFICATION_KEY_2018),
      X25519_KEY_AGREEMENT_KEY_2019_STR => Ok(Self::X25519_KEY_AGREEMENT_KEY_2019),
      JSON_WEB_KEY_METHOD_TYPE => Ok(
        #[allow(deprecated)]
        Self::JSON_WEB_KEY,
      ),
      JSON_WEB_KEY_2020_STR => Ok(Self::JSON_WEB_KEY_2020),
      _ => Ok(Self(Cow::Owned(string.to_owned()))),
    }
  }
}

#[cfg(test)]
mod tests {
  use serde_json::Value;

  use super::*;

  #[test]
  fn test_method_type_serde() {
    for method_type in [
      MethodType::ED25519_VERIFICATION_KEY_2018,
      MethodType::X25519_KEY_AGREEMENT_KEY_2019,
      MethodType::JSON_WEB_KEY_2020,
    ] {
      let ser: Value = serde_json::to_value(method_type.clone()).unwrap();
      assert_eq!(ser.as_str().unwrap(), method_type.as_str());
      let de: MethodType = serde_json::from_value(ser.clone()).unwrap();
      assert_eq!(de, method_type);

      assert_eq!(MethodType::from_str(method_type.as_str()).unwrap(), method_type);
      assert_eq!(MethodType::from_str(ser.as_str().unwrap()).unwrap(), method_type);
    }
  }
}
