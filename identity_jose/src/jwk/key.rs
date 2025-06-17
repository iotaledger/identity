// Copyright 2020-2025 IOTA Stiftung, Fondazione LINKS
// SPDX-License-Identifier: Apache-2.0

use crypto::hashes::sha::SHA256;
use crypto::hashes::sha::SHA256_LEN;
use identity_core::common::Url;
use zeroize::Zeroize;

use crate::error::Error;
use crate::error::Result;
use crate::jwk::EcCurve;
use crate::jwk::EcxCurve;
use crate::jwk::EdCurve;
use crate::jwk::JwkOperation;
use crate::jwk::JwkParams;
use crate::jwk::JwkParamsEc;
use crate::jwk::JwkParamsOct;
use crate::jwk::JwkParamsOkp;
use crate::jwk::JwkParamsRsa;
use crate::jwk::JwkParamsAkp;
use crate::jwk::JwkType;
use crate::jwk::JwkUse;
use crate::jwu::encode_b64;

/// A SHA256 JSON Web Key Thumbprint.
pub type JwkThumbprintSha256 = [u8; SHA256_LEN];

/// JSON Web Key.
///
/// [More Info](https://tools.ietf.org/html/rfc7517#section-4)
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Jwk {
  /// Key Type.
  ///
  /// Identifies the cryptographic algorithm family used with the key.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7517#section-4.1)
  pub(super) kty: JwkType,
  /// Public Key Use.
  ///
  /// Identifies the intended use of the public key.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7517#section-4.2)
  #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
  pub(super) use_: Option<JwkUse>,
  /// Key Operations.
  ///
  /// Identifies the operation(s) for which the key is intended to be used.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7517#section-4.3)
  #[serde(skip_serializing_if = "Option::is_none")]
  pub(super) key_ops: Option<Vec<JwkOperation>>,
  /// Algorithm.
  ///
  /// Identifies the algorithm intended for use with the key.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7517#section-4.4)
  #[serde(skip_serializing_if = "Option::is_none")]
  pub(super) alg: Option<String>,
  /// Key ID.
  ///
  /// Used to match a specific key among a set of keys within a JWK Set.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7517#section-4.5)
  #[serde(skip_serializing_if = "Option::is_none")]
  pub(super) kid: Option<String>,
  /// X.509 URL.
  ///
  /// A URI that refers to a resource for an X.509 public key certificate or
  /// certificate chain.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7517#section-4.6)
  #[serde(skip_serializing_if = "Option::is_none")]
  pub(super) x5u: Option<Url>,
  /// X.509 Certificate Chain.
  ///
  /// Contains a chain of one or more PKIX certificates.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7517#section-4.7)
  #[serde(skip_serializing_if = "Option::is_none")]
  pub(super) x5c: Option<Vec<String>>,
  /// X.509 Certificate SHA-1 Thumbprint.
  ///
  /// A base64url-encoded SHA-1 thumbprint of the DER encoding of an X.509
  /// certificate.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7517#section-4.8)
  #[serde(skip_serializing_if = "Option::is_none")]
  pub(super) x5t: Option<String>,
  /// X.509 Certificate SHA-256 Thumbprint.
  ///
  /// A base64url-encoded SHA-256 thumbprint of the DER encoding of an X.509
  /// certificate.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7517#section-4.9)
  #[serde(rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
  pub(super) x5t_s256: Option<String>,
  /// Type-Specific Key Properties.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7517#section-4)
  #[serde(flatten)]
  pub(super) params: JwkParams,
}

impl Jwk {
  /// Creates a new `Jwk` with the given `kty` parameter.
  pub const fn new(kty: JwkType) -> Self {
    Self {
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
  }

  /// Creates a new `Jwk` from the given params.
  pub fn from_params(params: impl Into<JwkParams>) -> Self {
    let params: JwkParams = params.into();

    Self {
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
    }
  }

  /// Returns the value for the key type parameter (kty).
  pub fn kty(&self) -> JwkType {
    self.kty
  }

  /// Sets a value for the key type parameter (kty).
  ///
  /// Removes any previously set `params`.
  pub fn set_kty(&mut self, value: impl Into<JwkType>) {
    self.kty = value.into();
    self.params = JwkParams::new(self.kty);
  }

  /// Returns the value for the use property (use).
  pub fn use_(&self) -> Option<JwkUse> {
    self.use_
  }

  /// Sets a value for the key use parameter (use).
  pub fn set_use(&mut self, value: impl Into<JwkUse>) {
    self.use_ = Some(value.into());
  }

  /// Returns the value for the key operations parameter (key_ops).
  pub fn key_ops(&self) -> Option<&[JwkOperation]> {
    self.key_ops.as_deref()
  }

  /// Sets values for the key operations parameter (key_ops).
  pub fn set_key_ops(&mut self, value: impl IntoIterator<Item = impl Into<JwkOperation>>) {
    self.key_ops = Some(value.into_iter().map(Into::into).collect());
  }

  /// Returns the value for the algorithm property (alg).
  pub fn alg(&self) -> Option<&str> {
    self.alg.as_deref()
  }

  /// Sets a value for the algorithm property (alg).
  pub fn set_alg(&mut self, value: impl Into<String>) {
    self.alg = Some(value.into());
  }

  /// Returns the value of the key ID property (kid).
  pub fn kid(&self) -> Option<&str> {
    self.kid.as_deref()
  }

  /// Sets a value for the key ID property (kid).
  pub fn set_kid(&mut self, value: impl Into<String>) {
    self.kid = Some(value.into());
  }

  /// Returns the value of the X.509 URL property (x5u).
  pub fn x5u(&self) -> Option<&Url> {
    self.x5u.as_ref()
  }

  /// Sets a value for the X.509 URL property (x5u).
  pub fn set_x5u(&mut self, value: impl Into<Url>) {
    self.x5u = Some(value.into());
  }

  /// Returns the value of the X.509 certificate chain property (x5c).
  pub fn x5c(&self) -> Option<&[String]> {
    self.x5c.as_deref()
  }

  /// Sets values for the X.509 certificate chain property (x5c).
  pub fn set_x5c(&mut self, value: impl IntoIterator<Item = impl Into<String>>) {
    self.x5c = Some(value.into_iter().map(Into::into).collect());
  }

  /// Returns the value of the X.509 certificate SHA-1 thumbprint property
  /// (x5t).
  pub fn x5t(&self) -> Option<&str> {
    self.x5t.as_deref()
  }

  /// Sets a value for the X.509 certificate SHA-1 thumbprint property (x5t).
  pub fn set_x5t(&mut self, value: impl Into<String>) {
    self.x5t = Some(value.into());
  }

  /// Returns the value of the X.509 certificate SHA-256 thumbprint property
  /// (x5t#S256).
  pub fn x5t_s256(&self) -> Option<&str> {
    self.x5t_s256.as_deref()
  }

  /// Sets a value for the X.509 certificate SHA-256 thumbprint property
  /// (x5t#S256).
  pub fn set_x5t_s256(&mut self, value: impl Into<String>) {
    self.x5t_s256 = Some(value.into());
  }

  /// Returns a reference to the custom JWK properties.
  pub fn params(&self) -> &JwkParams {
    &self.params
  }

  /// Returns a mutable reference to the custom JWK properties.
  pub fn params_mut(&mut self) -> &mut JwkParams {
    &mut self.params
  }

  /// Sets the value of the custom JWK properties.
  ///
  /// The passed `params` must be appropriate for the key type (`kty`), an error is returned otherwise.
  ///
  /// If you want to set `params` unchecked, use [`set_params_unchecked`](Self::set_params_unchecked).
  pub fn set_params(&mut self, params: impl Into<JwkParams>) -> Result<()> {
    match (self.kty, params.into()) {
      (JwkType::Ec, value @ JwkParams::Ec(_)) => {
        self.set_params_unchecked(value);
      }
      (JwkType::Rsa, value @ JwkParams::Rsa(_)) => {
        self.set_params_unchecked(value);
      }
      (JwkType::Oct, value @ JwkParams::Oct(_)) => {
        self.set_params_unchecked(value);
      }
      (JwkType::Okp, value @ JwkParams::Okp(_)) => {
        self.set_params_unchecked(value);
      }
      (_, _) => {
        return Err(Error::InvalidParam("`params` type does not match `kty`"));
      }
    }
    Ok(())
  }

  /// Sets the value of the custom JWK properties.
  ///
  /// Does not check whether the passed params are appropriate for the set key type (`kty`).
  pub fn set_params_unchecked(&mut self, value: impl Into<JwkParams>) {
    self.params = value.into();
  }

  /// Returns the [`JwkParamsEc`] in this JWK if it is of type `Ec`.
  pub fn try_ec_params(&self) -> Result<&JwkParamsEc> {
    match self.params() {
      JwkParams::Ec(params) => Ok(params),
      _ => Err(Error::KeyError("Ec")),
    }
  }

  /// Returns a mutable reference to the [`JwkParamsEc`] in this JWK if it is of type `Ec`.
  pub fn try_ec_params_mut(&mut self) -> Result<&mut JwkParamsEc> {
    match self.params_mut() {
      JwkParams::Ec(params) => Ok(params),
      _ => Err(Error::KeyError("Ec")),
    }
  }

  /// Returns the [`JwkParamsRsa`] in this JWK if it is of type `Rsa`.
  pub fn try_rsa_params(&self) -> Result<&JwkParamsRsa> {
    match self.params() {
      JwkParams::Rsa(params) => Ok(params),
      _ => Err(Error::KeyError("Rsa")),
    }
  }

  /// Returns a mutable reference to the [`JwkParamsRsa`] in this JWK if it is of type `Rsa`.
  pub fn try_rsa_params_mut(&mut self) -> Result<&mut JwkParamsRsa> {
    match self.params_mut() {
      JwkParams::Rsa(params) => Ok(params),
      _ => Err(Error::KeyError("Rsa")),
    }
  }

  /// Returns the [`JwkParamsOct`] in this JWK if it is of type `Oct`.
  pub fn try_oct_params(&self) -> Result<&JwkParamsOct> {
    match self.params() {
      JwkParams::Oct(params) => Ok(params),
      _ => Err(Error::KeyError("Oct")),
    }
  }

  /// Returns a mutable reference to the [`JwkParamsOct`] in this JWK if it is of type `Oct`.
  pub fn try_oct_params_mut(&mut self) -> Result<&mut JwkParamsOct> {
    match self.params_mut() {
      JwkParams::Oct(params) => Ok(params),
      _ => Err(Error::KeyError("Oct")),
    }
  }

  /// Returns the [`JwkParamsOkp`] in this JWK if it is of type `Okp`.
  pub fn try_okp_params(&self) -> Result<&JwkParamsOkp> {
    match self.params() {
      JwkParams::Okp(params) => Ok(params),
      _ => Err(Error::KeyError("Okp")),
    }
  }

  /// Returns a mutable reference to the [`JwkParamsOkp`] in this JWK if it is of type `Okp`.
  pub fn try_okp_params_mut(&mut self) -> Result<&mut JwkParamsOkp> {
    match self.params_mut() {
      JwkParams::Okp(params) => Ok(params),
      _ => Err(Error::KeyError("Okp")),
    }
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
    encode_b64(self.thumbprint_sha256())
  }

  /// Creates a Thumbprint of the JSON Web Key according to [RFC7638](https://tools.ietf.org/html/rfc7638).
  ///
  /// `SHA2-256` is used as the hash function *H*.
  ///
  /// The thumbprint is returned as an unencoded array of bytes.
  pub fn thumbprint_sha256(&self) -> JwkThumbprintSha256 {
    let json: String = self.thumbprint_hash_input();

    let mut out: JwkThumbprintSha256 = Default::default();

    SHA256(json.as_bytes(), &mut out);

    out
  }

  /// Creates the JSON string of the JSON Web Key according to [RFC7638](https://tools.ietf.org/html/rfc7638),
  /// which is used as the input for the JWK thumbprint hashing procedure.
  /// This can be used as input for a custom hash function.
  pub fn thumbprint_hash_input(&self) -> String {
    let kty: &str = self.kty.name();

    match self.params() {
      JwkParams::Ec(JwkParamsEc { crv, x, y, .. }) => {
        format!(r#"{{"crv":"{crv}","kty":"{kty}","x":"{x}","y":"{y}"}}"#)
      }
      JwkParams::Rsa(JwkParamsRsa { e, n, .. }) => {
        format!(r#"{{"e":"{e}","kty":"{kty}","n":"{n}"}}"#)
      }
      JwkParams::Oct(JwkParamsOct { k }) => {
        format!(r#"{{"k":"{k}","kty":"{kty}"}}"#)
      }
      // Implementation according to https://www.rfc-editor.org/rfc/rfc8037#section-2.
      JwkParams::Okp(JwkParamsOkp { crv, x, .. }) => {
        format!(r#"{{"crv":"{crv}","kty":"{kty}","x":"{x}"}}"#)
      }
      JwkParams::Akp(JwkParamsAkp { public, .. }) => {
        format!(r#"{{"kty":"{kty}","pub":"{public}"}}"#)
      }
    }
  }

  // ===========================================================================
  // Validations
  // ===========================================================================

  /// Checks if the `alg` claim of the JWK is equal to `expected`.
  pub fn check_alg(&self, expected: impl AsRef<str>) -> Result<()> {
    match self.alg() {
      Some(value) if value == expected.as_ref() => Ok(()),
      Some(_) => Err(Error::InvalidClaim("alg")),
      None => Ok(()),
    }
  }

  /// Returns the [`EcCurve`] of this JWK if it is of type `Ec`.
  pub fn try_ec_curve(&self) -> Result<EcCurve> {
    match self.params() {
      JwkParams::Ec(inner) => inner.try_ec_curve(),
      _ => Err(Error::KeyError("Ec Curve")),
    }
  }

  /// Returns the [`EdCurve`] of this JWK if it is of type `Okp`.
  pub fn try_ed_curve(&self) -> Result<EdCurve> {
    match self.params() {
      JwkParams::Okp(inner) => inner.try_ed_curve(),
      _ => Err(Error::KeyError("Ed Curve")),
    }
  }

  /// Returns the [`EcxCurve`] of this JWK if it is of type `Okp`.
  pub fn try_ecx_curve(&self) -> Result<EcxCurve> {
    match self.params() {
      JwkParams::Okp(inner) => inner.try_ecx_curve(),
      _ => Err(Error::KeyError("Ecx Curve")),
    }
  }

  /// Returns `true` if _all_ private key components of the key are unset, `false` otherwise.
  pub fn is_public(&self) -> bool {
    self.params.is_public()
  }

  /// Returns `true` if _all_ private key components of the key are set, `false` otherwise.
  pub fn is_private(&self) -> bool {
    match self.params() {
      JwkParams::Ec(params) => params.is_private(),
      JwkParams::Rsa(params) => params.is_private(),
      JwkParams::Oct(_) => true,
      JwkParams::Okp(params) => params.is_private(),
      JwkParams::Akp(params) => params.is_private(),
    }
  }

  /// Returns a clone of the Jwk with _all_ private key components unset.
  ///
  /// The `None` variant is returned when `kty = oct` as this key type is not considered public by this library.
  pub fn to_public(&self) -> Option<Jwk> {
    let mut public: Jwk = Jwk::from_params(self.params().to_public()?);

    if let Some(value) = self.use_() {
      public.set_use(value);
    }

    if let Some(value) = self.key_ops() {
      public.set_key_ops(value.iter().map(|op| op.invert()));
    }

    if let Some(value) = self.alg() {
      public.set_alg(value);
    }

    if let Some(value) = self.kid() {
      public.set_kid(value);
    }

    Some(public)
  }

  /// Removes all private key components.
  /// In the case of [JwkParams::Oct], this method does nothing.
  #[inline(always)]
  pub fn strip_private(&mut self) {
    self.params_mut().strip_private();
  }

  /// Returns this key with _all_ private key components unset.
  /// In the case of [JwkParams::Oct], this method returns [None].
  pub fn into_public(mut self) -> Option<Self> {
    if matches!(&self.params, JwkParams::Oct(_)) {
      None
    } else {
      self.params.strip_private();
      Some(self)
    }
  }
}

impl Zeroize for Jwk {
  fn zeroize(&mut self) {
    self.params.zeroize();
  }
}

impl Drop for Jwk {
  fn drop(&mut self) {
    self.zeroize();
  }
}

#[cfg(test)]
mod tests {
  use identity_core::convert::FromJson;

  use super::Jwk;

  #[test]
  fn into_public_and_to_public_return_the_same() {
    let priv_jwk = Jwk::from_json_slice(
      r#"
      {
        "kty": "OKP",
        "crv": "Ed25519",
        "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
      }
    "#,
    )
    .unwrap();

    assert_eq!(priv_jwk.to_public(), priv_jwk.into_public());
  }
}
