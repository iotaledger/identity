// Copyright 2020-2025 IOTA Stiftung, Fondazione LINKS
// SPDX-License-Identifier: Apache-2.0

use zeroize::Zeroize;

use super::BlsCurve;
use super::JwkParamsAkp;
use crate::error::Error;
use crate::error::Result;
use crate::jwk::EcCurve;
use crate::jwk::EcxCurve;
use crate::jwk::EdCurve;
use crate::jwk::JwkType;

/// Algorithm-specific parameters for JSON Web Keys.
///
/// [More Info](https://tools.ietf.org/html/rfc7518#section-6)
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize, serde::Serialize)]
#[serde(untagged)]
#[derive(Zeroize)]
#[zeroize(drop)]
pub enum JwkParams {
  /// Elliptic Curve parameters.
  Ec(JwkParamsEc),
  /// RSA parameters.
  Rsa(JwkParamsRsa),
  /// Octet Sequence parameters used to represent symmetric keys.
  Oct(JwkParamsOct),
  /// Octet Key Pairs parameters.
  Okp(JwkParamsOkp),
  /// Algorithm Key Pair Type parameters
  Akp(JwkParamsAkp),
}

impl JwkParams {
  /// Creates new `JwkParams` with the given `kty` parameter.
  pub const fn new(kty: JwkType) -> Self {
    match kty {
      JwkType::Ec => Self::Ec(JwkParamsEc::new()),
      JwkType::Rsa => Self::Rsa(JwkParamsRsa::new()),
      JwkType::Oct => Self::Oct(JwkParamsOct::new()),
      JwkType::Okp => Self::Okp(JwkParamsOkp::new()),
      JwkType::Akp => Self::Akp(JwkParamsAkp::new())
    }
  }

  /// Returns the key type `kty`.
  pub const fn kty(&self) -> JwkType {
    match self {
      Self::Ec(inner) => inner.kty(),
      Self::Rsa(inner) => inner.kty(),
      Self::Oct(inner) => inner.kty(),
      Self::Okp(inner) => inner.kty(),
      Self::Akp(_) => JwkType::Akp
    }
  }

  /// Returns a clone with _all_ private key components unset. The `None` variant is returned
  /// in the case of [`JwkParams::Oct`] as such keys are not considered public by
  /// this library.
  pub fn to_public(&self) -> Option<Self> {
    match self {
      Self::Okp(inner) => Some(Self::Okp(inner.to_public())),
      Self::Ec(inner) => Some(Self::Ec(inner.to_public())),
      Self::Rsa(inner) => Some(Self::Rsa(inner.to_public())),
      Self::Oct(_) => None,
      Self::Akp(inner) => Some(Self::Akp(inner.to_public()))
    }
  }

  /// Removes all private key components.
  /// In the case of [JwkParams::Oct], this method does nothing.
  pub fn strip_private(&mut self) {
    match self {
      Self::Okp(inner) => inner.strip_private(),
      Self::Ec(inner) => inner.strip_private(),
      Self::Rsa(inner) => inner.strip_private(),
      Self::Oct(_) => (),
    }
  }

  /// Returns this key with _all_ private key components unset.
  /// In the case of [JwkParams::Oct], this method returns [None].
  pub fn into_public(mut self) -> Option<Self> {
    if matches!(self, JwkParams::Oct(_)) {
      None
    } else {
      self.strip_private();
      Some(self)
    }
  }

  /// Returns `true` if _all_ private key components are unset, `false` otherwise.
  pub fn is_public(&self) -> bool {
    match self {
      Self::Okp(value) => value.is_public(),
      Self::Ec(value) => value.is_public(),
      Self::Rsa(value) => value.is_public(),
      Self::Oct(value) => value.is_public(),
      Self::Akp(value) => value.is_public()
    }
  }
}

// =============================================================================
// Jwk Params Ec
// =============================================================================

/// Parameters for Elliptic Curve Keys.
///
/// [More Info](https://tools.ietf.org/html/rfc7518#section-6.2)
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize, serde::Serialize, Zeroize)]
#[zeroize(drop)]
pub struct JwkParamsEc {
  /// Identifies the cryptographic curve used with the key.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7518#section-6.2.1.1)
  pub crv: String, // Curve
  /// The `x` coordinate for the Elliptic Curve point as a base64url-encoded
  /// value.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7518#section-6.2.1.2)
  pub x: String, // X Coordinate
  /// The `y` coordinate for the Elliptic Curve point as a base64url-encoded
  /// value.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7518#section-6.2.1.3)
  pub y: String, // Y Coordinate
  /// The Elliptic Curve private key as a base64url-encoded value.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7518#section-6.2.2.1)
  #[serde(skip_serializing_if = "Option::is_none")]
  pub d: Option<String>, // ECC Private Key
}

impl Default for JwkParamsEc {
  fn default() -> Self {
    Self::new()
  }
}

impl JwkParamsEc {
  /// Creates new JWK EC Params.
  pub const fn new() -> Self {
    Self {
      crv: String::new(),
      x: String::new(),
      y: String::new(),
      d: None,
    }
  }

  /// Returns the key type `kty`.
  pub const fn kty(&self) -> JwkType {
    JwkType::Ec
  }

  /// Returns a clone with _all_ private key components unset.
  pub fn to_public(&self) -> Self {
    Self {
      crv: self.crv.clone(),
      x: self.x.clone(),
      y: self.y.clone(),
      d: None,
    }
  }

  /// Returns `true` if _all_ private key components of the key are unset, `false` otherwise.
  pub fn is_public(&self) -> bool {
    self.d.is_none()
  }

  /// Returns `true` if _all_ private key components of the key are set, `false` otherwise.
  pub fn is_private(&self) -> bool {
    self.d.is_some()
  }

  /// Unsets _all_ private key components.
  pub fn strip_private(&mut self) {
    self.d = None;
  }

  /// Returns this key with _all_ private key components unset.
  pub fn into_public(mut self) -> Self {
    self.strip_private();
    self
  }

  /// Returns the [`EcCurve`] if it is of a supported type.
  pub fn try_ec_curve(&self) -> Result<EcCurve> {
    match &*self.crv {
      "P-256" => Ok(EcCurve::P256),
      "P-384" => Ok(EcCurve::P384),
      "P-521" => Ok(EcCurve::P521),
      "secp256k1" => Ok(EcCurve::Secp256K1),
      _ => Err(Error::KeyError("Ec Curve")),
    }
  }

  /// Returns the [`BlsCurve`] if it is of a supported type.
  pub fn try_bls_curve(&self) -> Result<BlsCurve> {
    match &*self.crv {
      "BLS12381G1" => Ok(BlsCurve::BLS12381G1),
      "BLS12381G2" => Ok(BlsCurve::BLS12381G2),
      "BLS48581G1" => Ok(BlsCurve::BLS48581G1),
      "BLS48581G2" => Ok(BlsCurve::BLS48581G2),
      _ => Err(Error::KeyError("BLS Curve")),
    }
  }
}

impl From<JwkParamsEc> for JwkParams {
  fn from(other: JwkParamsEc) -> Self {
    Self::Ec(other)
  }
}

// =============================================================================
// Jwk Params Rsa
// =============================================================================

/// Parameters for RSA Keys.
///
/// [More Info](https://tools.ietf.org/html/rfc7518#section-6.3)
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize, serde::Serialize, Zeroize)]
#[zeroize(drop)]
pub struct JwkParamsRsa {
  /// The modulus value for the RSA public key as a base64urlUInt-encoded value.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7518#section-6.3.1.1)
  pub n: String, // Modulus
  /// The exponent value for the RSA public key as a base64urlUInt-encoded
  /// value.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7518#section-6.3.1.2)
  pub e: String, // Exponent
  /// The private exponent value for the RSA private key as a
  /// base64urlUInt-encoded value.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7518#section-6.3.2.1)
  #[serde(skip_serializing_if = "Option::is_none")]
  pub d: Option<String>, // Private Exponent
  /// The first prime factor as a base64urlUInt-encoded value.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7518#section-6.3.2.2)
  #[serde(skip_serializing_if = "Option::is_none")]
  pub p: Option<String>, // First Prime Factor
  /// The second prime factor as a base64urlUInt-encoded value.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7518#section-6.3.2.3)
  #[serde(skip_serializing_if = "Option::is_none")]
  pub q: Option<String>, // Second Prime Factor
  /// The Chinese Remainder Theorem (CRT) exponent of the first factor as a
  /// base64urlUInt-encoded value.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7518#section-6.3.2.4)
  #[serde(skip_serializing_if = "Option::is_none")]
  pub dp: Option<String>, // First Factor CRT Exponent
  /// The CRT exponent of the second factor as a base64urlUInt-encoded value.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7518#section-6.3.2.5)
  #[serde(skip_serializing_if = "Option::is_none")]
  pub dq: Option<String>, // Second Factor CRT Exponent
  /// The CRT coefficient of the second factor as a base64urlUInt-encoded value.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7518#section-6.3.2.6)
  #[serde(skip_serializing_if = "Option::is_none")]
  pub qi: Option<String>, // First CRT Coefficient
  /// An array of information about any third and subsequent primes, should they
  /// exist.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7518#section-6.3.2.7)
  #[serde(skip_serializing_if = "Option::is_none")]
  pub oth: Option<Vec<JwkParamsRsaPrime>>, // Other Primes Info
}

/// Parameters for RSA Primes
///
/// [More Info](https://tools.ietf.org/html/rfc7518#section-6.3.2.7)
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize, serde::Serialize, Zeroize)]
#[zeroize(drop)]
pub struct JwkParamsRsaPrime {
  /// The value of a subsequent prime factor as a base64urlUInt-encoded value.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7518#section-6.3.2.7.1)
  pub r: String, // Prime Factor
  /// The CRT exponent of the corresponding prime factor as a
  /// base64urlUInt-encoded value.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7518#section-6.3.2.7.2)
  pub d: String, // Factor CRT Exponent
  /// The CRT coefficient of the corresponding prime factor as a
  /// base64urlUInt-encoded value.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7518#section-6.3.2.7.3)
  pub t: String, // Factor CRT Coefficient
}

impl Default for JwkParamsRsa {
  fn default() -> Self {
    Self::new()
  }
}

impl JwkParamsRsa {
  /// Creates new JWK RSA Params.
  pub const fn new() -> Self {
    Self {
      n: String::new(),
      e: String::new(),
      d: None,
      p: None,
      q: None,
      dp: None,
      dq: None,
      qi: None,
      oth: None,
    }
  }

  /// Returns the key type `kty`.
  pub const fn kty(&self) -> JwkType {
    JwkType::Rsa
  }

  /// Returns a clone with _all_ private key components unset.
  pub fn to_public(&self) -> Self {
    Self {
      n: self.n.clone(),
      e: self.e.clone(),
      d: None,
      p: None,
      q: None,
      dp: None,
      dq: None,
      qi: None,
      oth: None,
    }
  }

  /// Returns `true` if _all_ private key components of the key are unset, `false` otherwise.
  pub fn is_public(&self) -> bool {
    self.d.is_none()
      && self.p.is_none()
      && self.q.is_none()
      && self.dp.is_none()
      && self.dq.is_none()
      && self.qi.is_none()
      && self.oth.is_none()
  }

  /// Returns `true` if _all_ private key components of the key are set, `false` otherwise.
  ///
  /// Since the `oth` parameter is optional in a private key, its presence is not checked.
  pub fn is_private(&self) -> bool {
    self.d.is_some()
      && self.p.is_some()
      && self.q.is_some()
      && self.dp.is_some()
      && self.dq.is_some()
      && self.qi.is_some()
  }

  /// Unsets _all_ private key components.
  pub fn strip_private(&mut self) {
    self.d = None;
    self.p = None;
    self.q = None;
    self.dp = None;
    self.dq = None;
    self.qi = None;
  }

  /// Returns this key with _all_ private key components unset.
  pub fn into_public(mut self) -> Self {
    self.strip_private();
    self
  }
}

impl From<JwkParamsRsa> for JwkParams {
  fn from(other: JwkParamsRsa) -> Self {
    Self::Rsa(other)
  }
}

// =============================================================================
// Jwk Params Oct
// =============================================================================

/// Parameters for Symmetric Keys.
///
/// [More Info](https://tools.ietf.org/html/rfc7518#section-6.4)
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize, serde::Serialize, Zeroize)]
#[zeroize(drop)]
pub struct JwkParamsOct {
  /// The symmetric key as a base64url-encoded value.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7518#section-6.4.1)
  pub k: String, // Key Value
}

impl Default for JwkParamsOct {
  fn default() -> Self {
    Self::new()
  }
}

impl JwkParamsOct {
  /// Creates new JWK Oct Params.
  pub const fn new() -> Self {
    Self { k: String::new() }
  }

  /// Returns the key type `kty`.
  pub const fn kty(&self) -> JwkType {
    JwkType::Oct
  }

  /// Always returns `false`. Octet sequence keys
  /// are not considered public by this library.
  pub fn is_public(&self) -> bool {
    false
  }
}

impl From<JwkParamsOct> for JwkParams {
  fn from(other: JwkParamsOct) -> Self {
    Self::Oct(other)
  }
}

// =============================================================================
// Jwk Params Okp
// =============================================================================

/// Parameters for Octet Key Pairs.
///
/// [More Info](https://tools.ietf.org/html/rfc8037#section-2)
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize, serde::Serialize, Zeroize)]
#[zeroize(drop)]
pub struct JwkParamsOkp {
  /// The subtype of the key pair.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc8037#section-2)
  pub crv: String, // Key SubType
  /// The public key as a base64url-encoded value.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc8037#section-2)
  pub x: String, // Public Key
  /// The private key as a base64url-encoded value.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc8037#section-2)
  #[serde(skip_serializing_if = "Option::is_none")]
  pub d: Option<String>, // Private Key
}

impl Default for JwkParamsOkp {
  fn default() -> Self {
    Self::new()
  }
}

impl JwkParamsOkp {
  /// Creates new JWK OKP Params.
  pub const fn new() -> Self {
    Self {
      crv: String::new(),
      x: String::new(),
      d: None,
    }
  }

  /// Returns the key type `kty`.
  pub const fn kty(&self) -> JwkType {
    JwkType::Okp
  }

  /// Returns a clone with _all_ private key components unset.
  pub fn to_public(&self) -> Self {
    Self {
      crv: self.crv.clone(),
      x: self.x.clone(),
      d: None,
    }
  }

  /// Returns `true` if _all_ private key components of the key are unset, `false` otherwise.
  pub fn is_public(&self) -> bool {
    self.d.is_none()
  }

  /// Returns `true` if _all_ private key components of the key are set, `false` otherwise.
  pub fn is_private(&self) -> bool {
    self.d.is_some()
  }

  /// Unsets _all_ private key components.
  pub fn strip_private(&mut self) {
    self.d = None;
  }

  /// Returns this key with _all_ private key components unset.
  pub fn into_public(mut self) -> Self {
    self.strip_private();
    self
  }

  /// Returns the [`EdCurve`] if it is of a supported type.
  pub fn try_ed_curve(&self) -> Result<EdCurve> {
    match &*self.crv {
      "Ed25519" => Ok(EdCurve::Ed25519),
      "Ed448" => Ok(EdCurve::Ed448),
      _ => Err(Error::KeyError("Ed Curve")),
    }
  }

  /// Returns the [`EcxCurve`] if it is of a supported type.
  pub fn try_ecx_curve(&self) -> Result<EcxCurve> {
    match &*self.crv {
      "X25519" => Ok(EcxCurve::X25519),
      "X448" => Ok(EcxCurve::X448),
      _ => Err(Error::KeyError("Ecx Curve")),
    }
  }
}

impl From<JwkParamsOkp> for JwkParams {
  fn from(other: JwkParamsOkp) -> Self {
    Self::Okp(other)
  }
}
