// Copyright 2020-2025 IOTA Stiftung, Fondazione LINKS
// SPDX-License-Identifier: Apache-2.0

use core::fmt::Display;
use core::fmt::Formatter;
use core::fmt::Result;
use std::str::FromStr;

/// Supported algorithms for the JSON Web Signatures `alg` claim.
///
/// [More Info](https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms)
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize, serde::Serialize)]
#[cfg_attr(not(feature = "custom_alg"), derive(Copy))]
#[allow(non_camel_case_types)]
pub enum JwsAlgorithm {
  /// HMAC using SHA-256
  HS256,
  /// HMAC using SHA-384
  HS384,
  /// HMAC using SHA-512
  HS512,
  /// RSASSA-PKCS1-v1_5 using SHA-256
  RS256,
  /// RSASSA-PKCS1-v1_5 using SHA-384
  RS384,
  /// RSASSA-PKCS1-v1_5 using SHA-512
  RS512,
  /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256
  PS256,
  /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384
  PS384,
  /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512
  PS512,
  /// ECDSA using P-256 and SHA-256
  ES256,
  /// ECDSA using P-384 and SHA-384
  ES384,
  /// ECDSA using P-521 and SHA-512
  ES512,
  /// ECDSA using secp256k1 curve and SHA-256
  ES256K,
  /// No digital signature or MAC performed
  #[serde(rename = "none")]
  NONE,
  /// EdDSA signature algorithms
  EdDSA,
  /// JSON Web Signature Algorithm for ML-DSA-44
  /// [More Info](https://datatracker.ietf.org/doc/html/draft-ietf-cose-dilithium#name-the-ml-dsa-algorithm-family)
  #[serde(rename = "ML-DSA-44")]
  ML_DSA_44,
  /// JSON Web Signature Algorithm for ML-DSA-44
  /// [More Info](https://datatracker.ietf.org/doc/html/draft-ietf-cose-dilithium#name-the-ml-dsa-algorithm-family)
  #[serde(rename = "ML-DSA-65")]
  ML_DSA_65,
  /// JSON Web Signature Algorithm for ML-DSA-44
  /// [More Info](https://datatracker.ietf.org/doc/html/draft-ietf-cose-dilithium#name-the-ml-dsa-algorithm-family)
  #[serde(rename = "ML-DSA-87")]
  ML_DSA_87,
  /// JSON Web Signature Algorithm for SLH-DSA-SHA2-128s
  /// [More Info](https://datatracker.ietf.org/doc/html/draft-ietf-cose-sphincs-plus#name-the-slh-dsa-algorithm-famil)
  #[serde(rename = "SLH-DSA-SHA2-128s")]
  SLH_DSA_SHA2_128s,
  /// JSON Web Signature Algorithm for SLH-DSA-SHAKE-128s
  /// [More Info](https://datatracker.ietf.org/doc/html/draft-ietf-cose-sphincs-plus#name-the-slh-dsa-algorithm-famil)
  #[serde(rename = "SLH-DSA-SHAKE-128s")]
  SLH_DSA_SHAKE_128s,
  /// JSON Web Signature Algorithm for SLH-DSA-SHA2-128f
  /// [More Info](https://datatracker.ietf.org/doc/html/draft-ietf-cose-sphincs-plus#name-the-slh-dsa-algorithm-famil)
  #[serde(rename = "SLH-DSA-SHA2-128f")]
  SLH_DSA_SHA2_128f,
  ///SLH_DSA_SHAKE_128f
  #[serde(rename = "SLH-DSA-SHAKE-128f")]
  SLH_DSA_SHAKE_128f,
  ///SLH_DSA_SHA2_192s
  #[serde(rename = "SLH-DSA-SHA2-192s")]
  SLH_DSA_SHA2_192s,
  ///SLH_DSA_SHAKE_192s
  #[serde(rename = "SLH-DSA-SHAKE-192s")]
  SLH_DSA_SHAKE_192s,
  ///SLH-DSA-SHA2-192f
  #[serde(rename = "SLH-DSA-SHA2-192f")]
  SLH_DSA_SHA2_192f,
  ///SLH-DSA-SHAKE-192f
  #[serde(rename = "SLH-DSA-SHAKE-192f")]
  SLH_DSA_SHAKE_192f,
  ///SLH-DSA-SHA2-256s
  #[serde(rename = "SLH-DSA-SHA2-256s")]
  SLH_DSA_SHA2_256s,
  ///SLH-DSA-SHA2-256s
  #[serde(rename = "SLH-DSA-SHAKE-256s")]
  SLH_DSA_SHAKE_256s,
  ///SLH-DSA-SHA2-256f
  #[serde(rename = "SLH-DSA-SHA2-256f")]
  SLH_DSA_SHA2_256f,
  ///SLH-DSA-SHAKE-256f
  #[serde(rename = "SLH-DSA-SHAKE-256f")]
  SLH_DSA_SHAKE_256f,
  ///FALCON512
  FALCON512,
  ///FALCON1024
  FALCON1024,
  ///id-MLDSA44-Ed25519
  #[serde(rename = "id-MLDSA44-Ed25519")]
  IdMldsa44Ed25519,
  ///id-MLDSA65-Ed25519
  #[serde(rename = "id-MLDSA65-Ed25519")]
  IdMldsa65Ed25519,
  /// Custom algorithm
  #[cfg(feature = "custom_alg")]
  #[serde(untagged)]
  Custom(String),
}

impl JwsAlgorithm {
  /// A slice of all supported [`JwsAlgorithm`]s.
  ///
  /// Not available when feature `custom_alg` is enabled
  /// as it is not possible to enumerate all variants when
  /// supporting arbitrary `alg` values.
  #[cfg(not(feature = "custom_alg"))]
  pub const ALL: &'static [Self] = &[
    Self::HS256,
    Self::HS384,
    Self::HS512,
    Self::RS256,
    Self::RS384,
    Self::RS512,
    Self::PS256,
    Self::PS384,
    Self::PS512,
    Self::ES256,
    Self::ES384,
    Self::ES512,
    Self::ES256K,
    Self::NONE,
    Self::EdDSA,
    Self::ML_DSA_44,
    Self::ML_DSA_65,
    Self::ML_DSA_87,
    Self::SLH_DSA_SHA2_128s,
    Self::SLH_DSA_SHAKE_128s,
    Self::SLH_DSA_SHA2_128f,
    Self::SLH_DSA_SHAKE_128f,
    Self::SLH_DSA_SHA2_192s,
    Self::SLH_DSA_SHAKE_192s,
    Self::SLH_DSA_SHA2_192f,
    Self::SLH_DSA_SHAKE_192f,
    Self::SLH_DSA_SHA2_256s,
    Self::SLH_DSA_SHAKE_256s,
    Self::SLH_DSA_SHA2_256f,
    Self::SLH_DSA_SHAKE_256f,
    Self::FALCON512,
    Self::FALCON1024,
    Self::IdMldsa44Ed25519,
    Self::IdMldsa65Ed25519,
  ];

  /// Returns the JWS algorithm as a `str` slice.
  #[cfg(not(feature = "custom_alg"))]
  pub const fn name(self) -> &'static str {
    match self {
      Self::HS256 => "HS256",
      Self::HS384 => "HS384",
      Self::HS512 => "HS512",
      Self::RS256 => "RS256",
      Self::RS384 => "RS384",
      Self::RS512 => "RS512",
      Self::PS256 => "PS256",
      Self::PS384 => "PS384",
      Self::PS512 => "PS512",
      Self::ES256 => "ES256",
      Self::ES384 => "ES384",
      Self::ES512 => "ES512",
      Self::ES256K => "ES256K",
      Self::NONE => "none",
      Self::EdDSA => "EdDSA",
      Self::ML_DSA_44 => "ML-DSA-44",
      Self::ML_DSA_65 => "ML-DSA-65",
      Self::ML_DSA_87 => "ML-DSA-87",
      Self::SLH_DSA_SHA2_128s => "SLH-DSA-SHA2-128s",
      Self::SLH_DSA_SHAKE_128s => "SLH-DSA-SHAKE-128s",
      Self::SLH_DSA_SHA2_128f => "SLH-DSA-SHA2-128f",
      Self::SLH_DSA_SHAKE_128f => "SLH-DSA-SHAKE-128f",
      Self::SLH_DSA_SHA2_192s => "SLH-DSA-SHA2-192s",
      Self::SLH_DSA_SHAKE_192s => "SLH-DSA-SHAKE-192s",
      Self::SLH_DSA_SHA2_192f => "SLH-DSA-SHA2-192f",
      Self::SLH_DSA_SHAKE_192f => "SLH-DSA-SHAKE-192f",
      Self::SLH_DSA_SHA2_256s => "SLH-DSA-SHA2-256s",
      Self::SLH_DSA_SHAKE_256s => "SLH-DSA-SHAKE-256s",
      Self::SLH_DSA_SHA2_256f => "SLH-DSA-SHA2-256f",
      Self::SLH_DSA_SHAKE_256f => "SLH-DSA-SHAKE-256f",
      Self::FALCON512 => "FALCON512",
      Self::FALCON1024 => "FALCON1024",
      Self::IdMldsa44Ed25519 => "id-MLDSA44-Ed25519",
      Self::IdMldsa65Ed25519 => "id-MLDSA65-Ed25519",
    }
  }

  /// Returns the JWS algorithm as a `str` slice.
  #[cfg(feature = "custom_alg")]
  pub fn name(&self) -> String {
    match self {
      Self::HS256 => "HS256".to_string(),
      Self::HS384 => "HS384".to_string(),
      Self::HS512 => "HS512".to_string(),
      Self::RS256 => "RS256".to_string(),
      Self::RS384 => "RS384".to_string(),
      Self::RS512 => "RS512".to_string(),
      Self::PS256 => "PS256".to_string(),
      Self::PS384 => "PS384".to_string(),
      Self::PS512 => "PS512".to_string(),
      Self::ES256 => "ES256".to_string(),
      Self::ES384 => "ES384".to_string(),
      Self::ES512 => "ES512".to_string(),
      Self::ES256K => "ES256K".to_string(),
      Self::NONE => "none".to_string(),
      Self::EdDSA => "EdDSA".to_string(),
      Self::ML_DSA_44 => "ML-DSA-44".to_string(),
      Self::ML_DSA_65 => "ML-DSA-65".to_string(),
      Self::ML_DSA_87 => "ML-DSA-87".to_string(),
      Self::SLH_DSA_SHA2_128s => "SLH-DSA-SHA2-128s".to_string(),
      Self::SLH_DSA_SHAKE_128s => "SLH-DSA-SHAKE-128s".to_string(),
      Self::SLH_DSA_SHA2_128f => "SLH-DSA-SHA2-128f".to_string(),
      Self::SLH_DSA_SHAKE_128f => "SLH-DSA-SHAKE-128f".to_string(),
      Self::SLH_DSA_SHA2_192s => "SLH-DSA-SHA2-192s".to_string(),
      Self::SLH_DSA_SHAKE_192s => "SLH-DSA-SHAKE-192s".to_string(),
      Self::SLH_DSA_SHA2_192f => "SLH-DSA-SHA2-192f".to_string(),
      Self::SLH_DSA_SHAKE_192f => "SLH-DSA-SHAKE-192f".to_string(),
      Self::SLH_DSA_SHA2_256s => "SLH-DSA-SHA2-256s".to_string(),
      Self::SLH_DSA_SHAKE_256s => "SLH-DSA-SHAKE-256s".to_string(),
      Self::SLH_DSA_SHA2_256f => "SLH-DSA-SHA2-256f".to_string(),
      Self::SLH_DSA_SHAKE_256f => "SLH-DSA-SHAKE-256f".to_string(),
      Self::FALCON512 => "FALCON512".to_string(),
      Self::FALCON1024 => "FALCON1024".to_string(),
      Self::IdMldsa44Ed25519 => "id-MLDSA44-Ed25519".to_string(),
      Self::IdMldsa65Ed25519 => "id-MLDSA65-Ed25519".to_string(),
      Self::Custom(name) => name.clone(),
    }
  }
}

impl FromStr for JwsAlgorithm {
  type Err = crate::error::Error;

  fn from_str(string: &str) -> std::result::Result<Self, Self::Err> {
    match string {
      "HS256" => Ok(Self::HS256),
      "HS384" => Ok(Self::HS384),
      "HS512" => Ok(Self::HS512),
      "RS256" => Ok(Self::RS256),
      "RS384" => Ok(Self::RS384),
      "RS512" => Ok(Self::RS512),
      "PS256" => Ok(Self::PS256),
      "PS384" => Ok(Self::PS384),
      "PS512" => Ok(Self::PS512),
      "ES256" => Ok(Self::ES256),
      "ES384" => Ok(Self::ES384),
      "ES512" => Ok(Self::ES512),
      "ES256K" => Ok(Self::ES256K),
      "none" => Ok(Self::NONE),
      "EdDSA" => Ok(Self::EdDSA),
      "ML-DSA-44" => Ok(Self::ML_DSA_44),
      "ML-DSA-65" => Ok(Self::ML_DSA_65),
      "ML-DSA-87" => Ok(Self::ML_DSA_87),
      "SLH-DSA-SHA2-128s" => Ok(Self::SLH_DSA_SHA2_128s),
      "SLH-DSA-SHAKE-128s" => Ok(Self::SLH_DSA_SHAKE_128s),
      "SLH-DSA-SHA2-128f" => Ok(Self::SLH_DSA_SHA2_128f),
      "SLH-DSA-SHAKE-128f" => Ok(Self::SLH_DSA_SHAKE_128f),
      "SLH-DSA-SHA2-192s" => Ok(Self::SLH_DSA_SHA2_192s),
      "SLH-DSA-SHAKE-192s" => Ok(Self::SLH_DSA_SHAKE_192s),
      "SLH-DSA-SHA2-192f" => Ok(Self::SLH_DSA_SHA2_192f),
      "SLH-DSA-SHAKE-192f" => Ok(Self::SLH_DSA_SHAKE_192f),
      "SLH-DSA-SHA2-256s" => Ok(Self::SLH_DSA_SHA2_256s),
      "SLH-DSA-SHAKE-256s" => Ok(Self::SLH_DSA_SHAKE_256s),
      "SLH-DSA-SHA2-256f" => Ok(Self::SLH_DSA_SHA2_256f),
      "SLH-DSA-SHAKE-256f" => Ok(Self::SLH_DSA_SHAKE_256f),
      "FALCON512" => Ok(Self::FALCON512),
      "FALCON1024" => Ok(Self::FALCON1024),
      "id-MLDSA44-Ed25519" => Ok(Self::IdMldsa44Ed25519),
      "id-MLDSA65-Ed25519" => Ok(Self::IdMldsa65Ed25519),
      #[cfg(feature = "custom_alg")]
      value => Ok(Self::Custom(value.to_string())),
      #[cfg(not(feature = "custom_alg"))]
      _ => Err(crate::error::Error::JwsAlgorithmParsingError),
    }
  }
}

#[cfg(not(feature = "custom_alg"))]
impl Display for JwsAlgorithm {
  fn fmt(&self, f: &mut Formatter<'_>) -> Result {
    f.write_str(self.name())
  }
}

#[cfg(feature = "custom_alg")]
impl Display for JwsAlgorithm {
  fn fmt(&self, f: &mut Formatter<'_>) -> Result {
    f.write_str(&(*self).name())
  }
}
