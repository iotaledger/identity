// Copyright 2025 Fondazione LINKS
// SPDX-License-Identifier: Apache-2.0

use identity_core::common::Url;
use zeroize::Zeroize;

use crate::error::Error;
use crate::error::Result;
use crate::jwk::Jwk;
use crate::jwk::JwkOperation;
use crate::jwk::JwkParams;
use crate::jwk::JwkParamsAkp;
use crate::jwk::JwkParamsEc;
use crate::jwk::JwkParamsOct;
use crate::jwk::JwkParamsOkp;
use crate::jwk::JwkParamsRsa;
use crate::jwk::JwkThumbprintSha256;
use crate::jwk::JwkType;
use crate::jwk::JwkUse;


/// A post-quantum key encoded as JWK.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, Zeroize)]
#[serde(transparent)]
pub struct PostQuantumJwk(Jwk);

impl PostQuantumJwk {
  /// Creates a new [PostQuantumJwk].
  pub fn new(kty: JwkType) -> Result<Self> {
    if kty != JwkType::Akp {
      return Err(Error::KeyError("PostQuantumJwk can only be created with JwkType::Akp"));
    }

    Ok(
      Self(
        Jwk{
          kty,
          use_: None,
          key_ops: None,
          alg: None,
          kid: None,
          x5u: None,
          x5c: None,
          x5t: None,
          x5t_s256: None,
          params: JwkParams::new(kty),
        }
      )
    )
  }

  /// Creates a new `PostQuantumJwk` from the given params.
  pub fn from_params(params: impl Into<JwkParams>) -> Result<Self> {
    let params: JwkParams = params.into();

    if params.kty() != JwkType::Akp{
      return Err(Error::KeyError("PostQuantumJwk can only be created from a JwkParamsAkp"));
    }

    Ok(
      Self(
        Jwk{
          kty: params.kty(),
          use_: None,
          key_ops: None,
          alg: None,
          kid: None,
          x5u: None,
          x5c: None,
          x5t: None,
          x5t_s256: None,
          params: params,
        }
      )
    )
  }

  /// Returns the value for the key type parameter (kty).
  pub fn kty(&self) -> JwkType {
    self.0.kty()
  }
  
  /// Returns the value for the use property (use).
  pub fn use_(&self) -> Option<JwkUse> {
    self.0.use_()
  }

  /// Sets a value for the key use parameter (use).
  pub fn set_use(&mut self, value: impl Into<JwkUse>) {
    self.0.set_use(value)
  }

  /// Returns the value for the key operations parameter (key_ops).
  pub fn key_ops(&self) -> Option<&[JwkOperation]> {
    self.0.key_ops()
  }

  /// Sets values for the key operations parameter (key_ops).
  pub fn set_key_ops(&mut self, value: impl IntoIterator<Item = impl Into<JwkOperation>>) {
    self.0.set_key_ops(value);
  }

  /// Returns the value for the algorithm property (alg).
  pub fn alg(&self) -> Option<&str> {
    self.0.alg()
  }

  /// Returns the value of the key ID property (kid).
  pub fn kid(&self) -> Option<&str> {
    self.0.kid()
  }

  /// Sets a value for the key ID property (kid).
  pub fn set_kid(&mut self, value: impl Into<String>) {
    self.0.set_kid(value);
  }

  /// Returns the value of the X.509 URL property (x5u).
  pub fn x5u(&self) -> Option<&Url> {
    self.0.x5u()
  }

  /// Sets a value for the X.509 URL property (x5u).
  pub fn set_x5u(&mut self, value: impl Into<Url>) {
    self.0.set_x5u(value);
  }

  /// Returns the value of the X.509 certificate chain property (x5c).
  pub fn x5c(&self) -> Option<&[String]> {
    self.0.x5c()
  }

  /// Sets values for the X.509 certificate chain property (x5c).
  pub fn set_x5c(&mut self, value: impl IntoIterator<Item = impl Into<String>>) {
    self.0.set_x5c(value);
  }

  /// Returns the value of the X.509 certificate SHA-1 thumbprint property
  /// (x5t).
  pub fn x5t(&self) -> Option<&str> {
    self.0.x5t()
  }

  /// Sets a value for the X.509 certificate SHA-1 thumbprint property (x5t).
  pub fn set_x5t(&mut self, value: impl Into<String>) {
    self.0.set_x5t(value);
  }

  /// Returns the value of the X.509 certificate SHA-256 thumbprint property
  /// (x5t#S256).
  pub fn x5t_s256(&self) -> Option<&str> {
    self.0.x5t_s256()
  }

  /// Sets a value for the X.509 certificate SHA-256 thumbprint property
  /// (x5t#S256).
  pub fn set_x5t_s256(&mut self, value: impl Into<String>) {
    self.0.set_x5t_s256(value);
  }

  /// Returns a reference to the custom inner JWK properties.
  pub fn params(&self) -> &JwkParams {
    self.0.params()
  }

  /// Returns a mutable reference to the custom inner JWK properties.
  pub fn params_mut(&mut self) -> &mut JwkParams {
    self.0.params_mut()
  }

  /// Sets the value of the custom inner JWK properties.
  ///
  /// The passed `params` must be appropriate for the key type (`kty`), an error is returned otherwise.
  ///
  /// If you want to set `params` unchecked, use [`set_params_unchecked`](Self::set_params_unchecked).
  pub fn set_params(&mut self, params: impl Into<JwkParams>) -> Result<()> {
    self.0.set_params(params)
  }

  /// Sets the value of the custom JWK properties.
  ///
  /// Does not check whether the passed params are appropriate for the set key type (`kty`).
  pub fn set_params_unchecked(&mut self, value: impl Into<JwkParams>) {
    self.0.set_params_unchecked(value)
  }

  /// Returns the [`JwkParamsAkp`] in this JWK if it is of type `Akp`.
  pub fn try_akp_params(&self) -> Result<&JwkParamsAkp> {
    match self.params() {
      JwkParams::Akp(params) => Ok(params),
      _ => Err(Error::KeyError("Akp")),
    }
  }

  /// Returns a mutable reference to the [`JwkParamsAkp`] in this JWK if it is of type `Akp`.
  pub fn try_akp_params_mut(&mut self) -> Result<&mut JwkParamsAkp> {
    match self.params_mut() {
      JwkParams::Akp(params) => Ok(params),
      _ => Err(Error::KeyError("Akp")),
    }
  }

  // ===========================================================================
  // Thumbprint
  // ===========================================================================

  /// Creates a Thumbprint of the JSON Web Key according to [RFC7638](https://tools.ietf.org/html/rfc7638).
  ///
  /// `SHA2-256` is used as the hash function *H*.
  ///
  /// The thumbprint is returned as a base64url-encoded string.
  pub fn thumbprint_sha256_b64(&self) -> String {
    self.0.thumbprint_sha256_b64()
  }

  /// Creates a Thumbprint of the JSON Web Key according to [RFC7638](https://tools.ietf.org/html/rfc7638).
  ///
  /// `SHA2-256` is used as the hash function *H*.
  ///
  /// The thumbprint is returned as an unencoded array of bytes.
  pub fn thumbprint_sha256(&self) -> JwkThumbprintSha256 {
    self.0.thumbprint_sha256()
  }

  /// Creates the JSON string of the JSON Web Key according to [RFC7638](https://tools.ietf.org/html/rfc7638),
  /// which is used as the input for the JWK thumbprint hashing procedure.
  /// This can be used as input for a custom hash function.
  pub fn thumbprint_hash_input(&self) -> String {
    self.0.thumbprint_hash_input()
  }

  // ===========================================================================
  // Validations
  // ===========================================================================

  /// Checks if the `alg` claim of the JWK is equal to `expected`.
  pub fn check_alg(&self, expected: impl AsRef<str>) -> Result<()> {
    self.0.check_alg(expected)
  }

  /// Returns `true` if _all_ private key components of the key are unset, `false` otherwise.
  pub fn is_public(&self) -> bool {
    self.0.is_public()
  }

  /// Returns `true` if _all_ private key components of the key are set, `false` otherwise.
  pub fn is_private(&self) -> bool {
    self.0.is_private()
  }

  /// Returns a clone of the PostQuantumJwk with _all_ private key components unset.
  ///
  /// The `None` variant is returned when `kty = oct` as this key type is not considered public by this library.
  pub fn to_public(&self) -> Option<PostQuantumJwk> {
    self.0.to_public()
      .map(|jwk| PostQuantumJwk(jwk))
  }

}

impl Drop for PostQuantumJwk {
  fn drop(&mut self) {
    self.zeroize();
  }
}

impl TryFrom<Jwk> for PostQuantumJwk {
  type Error = Error;

  fn try_from(value: Jwk) -> Result<Self> {
    if value.kty != JwkType::Akp {
      return Err(Error::KeyError("PostQuantumJwk can only be created from a Jwk with kty = Akp"));
    }
    Ok(Self(value))
  }
}

impl Into<Jwk> for &PostQuantumJwk {
  fn into(self) -> Jwk {
    self.0.clone()
  }
}

/// Wrapper to the [`Jwk`] structure to enforce the exclusive use of traditional JWK encoded keys in the [`CompositeJwk`]
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, Zeroize)]
pub struct TraditionalJwk(Jwk);

impl TraditionalJwk {
  /// Creates a new TraditionalJwk
  pub fn new(kty: JwkType) -> Result<Self> {
    if kty == JwkType::Akp {
      return Err(Error::KeyError("TraditionalJwk can only be created with different from JwkType::Akp"));
    }

    Ok(
      Self(
        Jwk{
          kty,
          use_: None,
          key_ops: None,
          alg: None,
          kid: None,
          x5u: None,
          x5c: None,
          x5t: None,
          x5t_s256: None,
          params: JwkParams::new(kty),
        }
      )
    )
  }

  /// Creates a new `Jwk` from the given params.
  pub fn from_params(params: impl Into<JwkParams>) -> Result<Self> {
    let params: JwkParams = params.into();

    if params.kty() == JwkType::Akp{
      return Err(Error::KeyError("TraditionalJwk can only be created with different from JwkType::Akp"));
    }

    Ok(
      Self(
        Jwk{
          kty: params.kty(),
          use_: None,
          key_ops: None,
          alg: None,
          kid: None,
          x5u: None,
          x5c: None,
          x5t: None,
          x5t_s256: None,
          params: params,
        }
      )
    )
  }

  /// Returns the value for the key type parameter (kty).
  pub fn kty(&self) -> JwkType {
    self.0.kty()
  }
  
  /// Returns the value for the use property (use).
  pub fn use_(&self) -> Option<JwkUse> {
    self.0.use_()
  }

  /// Sets a value for the key use parameter (use).
  pub fn set_use(&mut self, value: impl Into<JwkUse>) {
    self.0.set_use(value)
  }

  /// Returns the value for the key operations parameter (key_ops).
  pub fn key_ops(&self) -> Option<&[JwkOperation]> {
    self.0.key_ops()
  }

  /// Sets values for the key operations parameter (key_ops).
  pub fn set_key_ops(&mut self, value: impl IntoIterator<Item = impl Into<JwkOperation>>) {
    self.0.set_key_ops(value);
  }

  /// Returns the value for the algorithm property (alg).
  pub fn alg(&self) -> Option<&str> {
    self.0.alg()
  }

  /// Returns the value of the key ID property (kid).
  pub fn kid(&self) -> Option<&str> {
    self.0.kid()
  }

  /// Sets a value for the key ID property (kid).
  pub fn set_kid(&mut self, value: impl Into<String>) {
    self.0.set_kid(value);
  }

  /// Returns the value of the X.509 URL property (x5u).
  pub fn x5u(&self) -> Option<&Url> {
    self.0.x5u()
  }

  /// Sets a value for the X.509 URL property (x5u).
  pub fn set_x5u(&mut self, value: impl Into<Url>) {
    self.0.set_x5u(value);
  }

  /// Returns the value of the X.509 certificate chain property (x5c).
  pub fn x5c(&self) -> Option<&[String]> {
    self.0.x5c()
  }

  /// Sets values for the X.509 certificate chain property (x5c).
  pub fn set_x5c(&mut self, value: impl IntoIterator<Item = impl Into<String>>) {
    self.0.set_x5c(value);
  }

  /// Returns the value of the X.509 certificate SHA-1 thumbprint property
  /// (x5t).
  pub fn x5t(&self) -> Option<&str> {
    self.0.x5t()
  }

  /// Sets a value for the X.509 certificate SHA-1 thumbprint property (x5t).
  pub fn set_x5t(&mut self, value: impl Into<String>) {
    self.0.set_x5t(value);
  }

  /// Returns the value of the X.509 certificate SHA-256 thumbprint property
  /// (x5t#S256).
  pub fn x5t_s256(&self) -> Option<&str> {
    self.0.x5t_s256()
  }

  /// Sets a value for the X.509 certificate SHA-256 thumbprint property
  /// (x5t#S256).
  pub fn set_x5t_s256(&mut self, value: impl Into<String>) {
    self.0.set_x5t_s256(value);
  }

  /// Returns a reference to the custom JWK properties.
  pub fn params(&self) -> &JwkParams {
    self.0.params()
  }

  /// Returns a mutable reference to the custom JWK properties.
  pub fn params_mut(&mut self) -> &mut JwkParams {
    self.0.params_mut()
  }

  /// Sets the value of the custom JWK properties.
  ///
  /// The passed `params` must be appropriate for the key type (`kty`), an error is returned otherwise.
  ///
  /// If you want to set `params` unchecked, use [`set_params_unchecked`](Self::set_params_unchecked).
  pub fn set_params(&mut self, params: impl Into<JwkParams>) -> Result<()> {
    self.0.set_params(params)
  }

  /// Sets the value of the custom JWK properties.
  ///
  /// Does not check whether the passed params are appropriate for the set key type (`kty`).
  pub fn set_params_unchecked(&mut self, value: impl Into<JwkParams>) {
    self.0.set_params_unchecked(value)
  }

  /// Returns the [`JwkParamsEc`] in this inner JWK if it is of type `Ec`.
  pub fn try_ec_params(&self) -> Result<&JwkParamsEc> {
    self.0.try_ec_params()
  }

  /// Returns a mutable reference to the [`JwkParamsEc`] in this inner JWK if it is of type `Ec`.
  pub fn try_ec_params_mut(&mut self) -> Result<&mut JwkParamsEc> {
    self.0.try_ec_params_mut()
  }

  /// Returns the [`JwkParamsRsa`] in this inner JWK if it is of type `Rsa`.
  pub fn try_rsa_params(&self) -> Result<&JwkParamsRsa> {
    self.0.try_rsa_params()
  }

  /// Returns a mutable reference to the [`JwkParamsRsa`] in this inner JWK if it is of type `Rsa`.
  pub fn try_rsa_params_mut(&mut self) -> Result<&mut JwkParamsRsa> {
    self.0.try_rsa_params_mut()
  }

  /// Returns the [`JwkParamsOct`] in this inner JWK if it is of type `Oct`.
  pub fn try_oct_params(&self) -> Result<&JwkParamsOct> {
    self.0.try_oct_params()
  }

  /// Returns a mutable reference to the [`JwkParamsOct`] in this JWK if it is of type `Oct`.
  pub fn try_oct_params_mut(&mut self) -> Result<&mut JwkParamsOct> {
    self.0.try_oct_params_mut()
  }

  /// Returns the [`JwkParamsOkp`] in this inner JWK if it is of type `Okp`.
  pub fn try_okp_params(&self) -> Result<&JwkParamsOkp> {
    self.0.try_okp_params()
  }

  /// Returns a mutable reference to the [`JwkParamsOkp`] in this inner JWK if it is of type `Okp`.
  pub fn try_okp_params_mut(&mut self) -> Result<&mut JwkParamsOkp> {
    self.0.try_okp_params_mut()
  }

  // ===========================================================================
  // Thumbprint
  // ===========================================================================

  /// Creates a Thumbprint of the JSON Web Key according to [RFC7638](https://tools.ietf.org/html/rfc7638).
  ///
  /// `SHA2-256` is used as the hash function *H*.
  ///
  /// The thumbprint is returned as a base64url-encoded string.
  pub fn thumbprint_sha256_b64(&self) -> String {
    self.0.thumbprint_sha256_b64()
  }

  /// Creates a Thumbprint of the JSON Web Key according to [RFC7638](https://tools.ietf.org/html/rfc7638).
  ///
  /// `SHA2-256` is used as the hash function *H*.
  ///
  /// The thumbprint is returned as an unencoded array of bytes.
  pub fn thumbprint_sha256(&self) -> JwkThumbprintSha256 {
    self.0.thumbprint_sha256()
  }

  /// Creates the JSON string of the JSON Web Key according to [RFC7638](https://tools.ietf.org/html/rfc7638),
  /// which is used as the input for the JWK thumbprint hashing procedure.
  /// This can be used as input for a custom hash function.
  pub fn thumbprint_hash_input(&self) -> String {
    self.0.thumbprint_hash_input()
  }

  // ===========================================================================
  // Validations
  // ===========================================================================

  /// Checks if the `alg` claim of the JWK is equal to `expected`.
  pub fn check_alg(&self, expected: impl AsRef<str>) -> Result<()> {
    self.0.check_alg(expected)
  }

  /// Returns `true` if _all_ private key components of the key are unset, `false` otherwise.
  pub fn is_public(&self) -> bool {
    self.0.is_public()
  }

  /// Returns `true` if _all_ private key components of the key are set, `false` otherwise.
  pub fn is_private(&self) -> bool {
    self.0.is_private()
  }

  /// Returns a clone of the TraditionalJwk with _all_ private key components unset.
  ///
  /// The `None` variant is returned when `kty = oct` as this key type is not considered public by this library.
  pub fn to_public(&self) -> Option<TraditionalJwk> {
    self.0.to_public()
      .map(|jwk| TraditionalJwk(jwk))
  }

}

impl Drop for TraditionalJwk {
  fn drop(&mut self) {
    self.zeroize();
  }
}

impl TryFrom<Jwk> for TraditionalJwk {
  type Error = Error;

  fn try_from(value: Jwk) -> Result<Self> {
    if value.kty == JwkType::Akp {
      return Err(Error::KeyError("TraditionalJwk can only be created from a Jwk different from JwkType::Akp"));
    }
    Ok(Self(value))
  }
}

impl Into<Jwk> for &TraditionalJwk {
  fn into(self) -> Jwk {
    self.0.clone()
  }
}