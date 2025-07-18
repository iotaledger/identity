// Copyright 2020-2025 IOTA Stiftung, Fondazione LINKS
// SPDX-License-Identifier: Apache-2.0

use std::ops::Deref;
use std::str::FromStr;

use identity_core::common::Url;

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
use crate::jwk::JwkType;
use crate::jwk::JwkUse;
use crate::jws::JwsAlgorithm;

/// A post-quantum key encoded as JWK.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct PostQuantumJwk(Jwk);

impl PostQuantumJwk {
  /// Creates a new `[PostQuantumJwk]`.
  pub fn new(paramsakp: JwkParamsAkp) -> Self {
    Self(Jwk {
      kty: JwkType::Akp,
      use_: None,
      key_ops: None,
      alg: None,
      kid: None,
      x5u: None,
      x5c: None,
      x5t: None,
      x5t_s256: None,
      params: JwkParams::Akp(paramsakp),
    })
  }

  /// Creates a new `[PostQuantumJwk]` from the given kty.
  pub fn from_kty(kty: impl Into<JwkType>) -> Result<Self> {
    let kty: JwkType = kty.into();
    if kty != JwkType::Akp {
      return Err(Error::KeyError("PostQuantumJwk can only be created with JwkType::Akp"));
    }

    Ok(Self(Jwk {
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
    }))
  }

  /// Creates a new `[PostQuantumJwk]` from the given params.
  pub fn from_params(params: impl Into<JwkParams>) -> Result<Self> {
    let params: JwkParams = params.into();

    if params.kty() != JwkType::Akp {
      return Err(Error::KeyError(
        "PostQuantumJwk can only be created from a JwkParamsAkp",
      ));
    }

    Ok(Self(Jwk {
      kty: params.kty(),
      use_: None,
      key_ops: None,
      alg: None,
      kid: None,
      x5u: None,
      x5c: None,
      x5t: None,
      x5t_s256: None,
      params,
    }))
  }

  /// Sets a value for the key use parameter (use).
  pub fn set_use(&mut self, value: impl Into<JwkUse>) {
    self.0.set_use(value)
  }

  /// Sets values for the key operations parameter (key_ops).
  pub fn set_key_ops(&mut self, value: impl IntoIterator<Item = impl Into<JwkOperation>>) {
    self.0.set_key_ops(value);
  }

  /// Sets a value for the algorithm property (alg).
  pub fn set_alg(&mut self, value: impl Into<String>) -> Result<()> {
    let alg = JwsAlgorithm::from_str(&value.into()).map_err(|_| Error::InvalidParam("Invalid JWS algorithm"))?;
    if !is_post_quantum(&alg) {
      return Err(Error::InvalidParam(
        "PostQuantumJwk can only be created with a post-quantum JWS algorithm",
      ));
    }
    self.0.set_alg(alg.to_string());
    Ok(())
  }

  /// Sets a value for the key ID property (kid).
  pub fn set_kid(&mut self, value: impl Into<String>) {
    self.0.set_kid(value);
  }

  /// Sets a value for the X.509 URL property (x5u).
  pub fn set_x5u(&mut self, value: impl Into<Url>) {
    self.0.set_x5u(value);
  }

  /// Sets values for the X.509 certificate chain property (x5c).
  pub fn set_x5c(&mut self, value: impl IntoIterator<Item = impl Into<String>>) {
    self.0.set_x5c(value);
  }

  /// Sets a value for the X.509 certificate SHA-1 thumbprint property (x5t).
  pub fn set_x5t(&mut self, value: impl Into<String>) {
    self.0.set_x5t(value);
  }

  /// Sets a value for the X.509 certificate SHA-256 thumbprint property
  /// (x5t#S256).
  pub fn set_x5t_s256(&mut self, value: impl Into<String>) {
    self.0.set_x5t_s256(value);
  }

  /// Sets the value of the custom inner JWK properties. Only for `Akp` keys.
  pub fn set_params(&mut self, params: impl Into<JwkParams>) -> Result<()> {
    let params: JwkParams = params.into();
    if params.kty() != JwkType::Akp {
      return Err(Error::InvalidParam("`params` type does not match `Akp`"));
    }
    self.0.set_params_unchecked(params);
    Ok(())
  }

  /// Returns the [`JwkParamsAkp`] in this JWK.
  pub fn akp_params(&self) -> &JwkParamsAkp {
    self
      .0
      .try_akp_params()
      .expect("PostQuantumJwk must have JwkParamsAkp as params")
  }

  /// Returns a mutable reference to the [`JwkParamsAkp`] in this JWK.
  pub fn akp_params_mut(&mut self) -> &mut JwkParamsAkp {
    self
      .0
      .try_akp_params_mut()
      .expect("PostQuantumJwk must have JwkParamsAkp as params")
  }

  /// Removes all private key components.
  #[inline(always)]
  pub fn strip_private(&mut self) {
    self.0.params_mut().strip_private();
  }

  /// Returns this key with _all_ private key components unset.
  pub fn into_public(mut self) -> Option<Self> {
    self.0.params.strip_private();
    Some(self)
  }
}

impl Deref for PostQuantumJwk {
  type Target = Jwk;

  fn deref(&self) -> &Self::Target {
    &self.0
  }
}

impl TryFrom<Jwk> for PostQuantumJwk {
  type Error = Error;

  fn try_from(value: Jwk) -> Result<Self> {
    let alg = JwsAlgorithm::from_str(value.alg().ok_or(Error::KeyError("Missing JWK algorithm"))?)?;
    if value.kty != JwkType::Akp && !is_post_quantum(&alg) {
      return Err(Error::KeyError(
        "PostQuantumJwk can only be created from a post quantum Jwk",
      ));
    }

    Ok(Self(value))
  }
}

impl AsRef<Jwk> for PostQuantumJwk {
  fn as_ref(&self) -> &Jwk {
    &self.0
  }
}

impl From<PostQuantumJwk> for Jwk {
  fn from(value: PostQuantumJwk) -> Self {
    value.0
  }
}

/// Wrapper to the [`Jwk`] structure to enforce the exclusive use of traditional JWK encoded keys in the
/// [`CompositeJwk`]
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct TraditionalJwk(Jwk);

impl TraditionalJwk {
  /// Creates a new `[TraditionalJwk]` from a `[JwkParamsOkp]`.
  pub fn new(kty: JwkParamsOkp) -> Self {
    Self(Jwk {
      kty: JwkType::Okp,
      use_: None,
      key_ops: None,
      alg: None,
      kid: None,
      x5u: None,
      x5c: None,
      x5t: None,
      x5t_s256: None,
      params: JwkParams::Okp(kty),
    })
  }

  /// Creates a new `[TraditionalJwk]` from the given kty.
  pub fn from_kty(kty: JwkType) -> Result<Self> {
    if kty == JwkType::Akp {
      return Err(Error::KeyError(
        "TraditionalJwk can only be created with different from JwkType::Akp",
      ));
    }

    Ok(Self(Jwk {
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
    }))
  }

  /// Creates a new `[TraditionalJwk]` from the given params.
  pub fn from_params(params: impl Into<JwkParams>) -> Result<Self> {
    let params: JwkParams = params.into();

    if params.kty() == JwkType::Akp {
      return Err(Error::KeyError(
        "TraditionalJwk can only be created with different from JwkType::Akp",
      ));
    }

    Ok(Self(Jwk {
      kty: params.kty(),
      use_: None,
      key_ops: None,
      alg: None,
      kid: None,
      x5u: None,
      x5c: None,
      x5t: None,
      x5t_s256: None,
      params,
    }))
  }

  /// Sets a value for the key use parameter (use).
  pub fn set_use(&mut self, value: impl Into<JwkUse>) {
    self.0.set_use(value)
  }

  /// Sets values for the key operations parameter (key_ops).
  pub fn set_key_ops(&mut self, value: impl IntoIterator<Item = impl Into<JwkOperation>>) {
    self.0.set_key_ops(value);
  }

  /// Sets a value for the algorithm property (alg).
  pub fn set_alg(&mut self, value: impl Into<String>) -> Result<()> {
    let alg = JwsAlgorithm::from_str(&value.into()).map_err(|_| Error::InvalidParam("Invalid JWS algorithm"))?;
    if is_post_quantum(&alg) {
      return Err(Error::InvalidParam(
        "TraditionalJwk can only be created with a traditional JWS algorithm",
      ));
    }
    self.0.set_alg(alg.to_string());
    Ok(())
  }

  /// Sets a value for the key ID property (kid).
  pub fn set_kid(&mut self, value: impl Into<String>) {
    self.0.set_kid(value);
  }

  /// Sets a value for the X.509 URL property (x5u).
  pub fn set_x5u(&mut self, value: impl Into<Url>) {
    self.0.set_x5u(value);
  }

  /// Sets values for the X.509 certificate chain property (x5c).
  pub fn set_x5c(&mut self, value: impl IntoIterator<Item = impl Into<String>>) {
    self.0.set_x5c(value);
  }

  /// Sets a value for the X.509 certificate SHA-1 thumbprint property (x5t).
  pub fn set_x5t(&mut self, value: impl Into<String>) {
    self.0.set_x5t(value);
  }

  /// Sets a value for the X.509 certificate SHA-256 thumbprint property
  /// (x5t#S256).
  pub fn set_x5t_s256(&mut self, value: impl Into<String>) {
    self.0.set_x5t_s256(value);
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

  /// Returns a mutable reference to the [`JwkParamsEc`] in this inner JWK if it is of type `Ec`.
  pub fn try_ec_params_mut(&mut self) -> Result<&mut JwkParamsEc> {
    self.0.try_ec_params_mut()
  }

  /// Returns a mutable reference to the [`JwkParamsRsa`] in this inner JWK if it is of type `Rsa`.
  pub fn try_rsa_params_mut(&mut self) -> Result<&mut JwkParamsRsa> {
    self.0.try_rsa_params_mut()
  }

  /// Returns a mutable reference to the [`JwkParamsOct`] in this JWK if it is of type `Oct`.
  pub fn try_oct_params_mut(&mut self) -> Result<&mut JwkParamsOct> {
    self.0.try_oct_params_mut()
  }

  /// Returns a mutable reference to the [`JwkParamsOkp`] in this inner JWK if it is of type `Okp`.
  pub fn try_okp_params_mut(&mut self) -> Result<&mut JwkParamsOkp> {
    self.0.try_okp_params_mut()
  }

  /// Removes all private key components.
  /// In the case of [JwkParams::Oct], this method does nothing.
  #[inline(always)]
  pub fn strip_private(&mut self) {
    self.0.params_mut().strip_private();
  }

  /// Returns this key with _all_ private key components unset.
  /// In the case of [JwkParams::Oct], this method returns [None].
  pub fn into_public(mut self) -> Option<Self> {
    if matches!(&self.params, JwkParams::Oct(_)) {
      None
    } else {
      self.0.params.strip_private();
      Some(self)
    }
  }
}

impl Deref for TraditionalJwk {
  type Target = Jwk;

  fn deref(&self) -> &Self::Target {
    &self.0
  }
}

impl TryFrom<Jwk> for TraditionalJwk {
  type Error = Error;

  fn try_from(value: Jwk) -> Result<Self> {
    let alg = JwsAlgorithm::from_str(value.alg().ok_or(Error::KeyError("Missing JWK algorithm"))?)?;
    if value.kty == JwkType::Akp && is_post_quantum(&alg) {
      return Err(Error::KeyError(
        "TraditionalJwk can only be created from a traditional Jwk",
      ));
    }
    Ok(Self(value))
  }
}

impl AsRef<Jwk> for TraditionalJwk {
  fn as_ref(&self) -> &Jwk {
    &self.0
  }
}

impl From<TraditionalJwk> for Jwk {
  fn from(value: TraditionalJwk) -> Self {
    value.0
  }
}

fn is_post_quantum(alg: &JwsAlgorithm) -> bool {
  matches!(
    alg,
    JwsAlgorithm::FALCON1024
      | JwsAlgorithm::FALCON512
      | JwsAlgorithm::ML_DSA_44
      | JwsAlgorithm::ML_DSA_65
      | JwsAlgorithm::ML_DSA_87
      | JwsAlgorithm::SLH_DSA_SHA2_128s
      | JwsAlgorithm::SLH_DSA_SHAKE_128s
      | JwsAlgorithm::SLH_DSA_SHA2_128f
      | JwsAlgorithm::SLH_DSA_SHAKE_128f
      | JwsAlgorithm::SLH_DSA_SHA2_192s
      | JwsAlgorithm::SLH_DSA_SHAKE_192s
      | JwsAlgorithm::SLH_DSA_SHA2_192f
      | JwsAlgorithm::SLH_DSA_SHAKE_192f
      | JwsAlgorithm::SLH_DSA_SHA2_256s
      | JwsAlgorithm::SLH_DSA_SHAKE_256s
      | JwsAlgorithm::SLH_DSA_SHA2_256f
      | JwsAlgorithm::SLH_DSA_SHAKE_256f
  )
}
