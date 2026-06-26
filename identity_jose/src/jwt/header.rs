// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_core::common::Url;

use crate::jose::JoseHeader;
use crate::jwk::Jwk;

/// JSON Web Token JOSE Header.
///
/// [More Info (JWS)](https://tools.ietf.org/html/rfc7515#section-4)
/// [More Info (JWE)](https://tools.ietf.org/html/rfc7516#section-4)
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct JwtHeader {
  /// JWK Set URL.
  ///
  /// Refers to a resource for a set of JSON-encoded public keys, one of which
  /// corresponds to the key used to digitally sign the JWS.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7515#section-4.1.2)
  #[serde(skip_serializing_if = "Option::is_none")]
  jku: Option<Url>,
  /// JSON Web Key.
  ///
  /// The public key that corresponds to the key used to digitally sign the JWS.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7515#section-4.1.3)
  #[serde(skip_serializing_if = "Option::is_none")]
  jwk: Option<Jwk>,
  /// Key ID.
  ///
  /// A hint indicating which key was used to secure the JWS.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7515#section-4.1.4)
  #[serde(skip_serializing_if = "Option::is_none")]
  kid: Option<String>,
  /// X.509 URL.
  ///
  /// A URI that refers to a resource for the X.509 public key certificate or
  /// certificate chain corresponding to the key used to digitally sign the JWS.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7515#section-4.1.5)
  #[serde(skip_serializing_if = "Option::is_none")]
  x5u: Option<Url>,
  /// X.509 Certificate Chain.
  ///
  /// Contains the X.509 public key certificate or certificate chain
  /// corresponding to the key used to digitally sign the JWS.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7515#section-4.1.6)
  #[serde(skip_serializing_if = "Option::is_none")]
  x5c: Option<Vec<String>>,
  /// X.509 Certificate SHA-1 Thumbprint.
  ///
  /// A base64url-encoded SHA-1 thumbprint of the DER encoding of the X.509
  /// certificate corresponding to the key used to digitally sign the JWS.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7515#section-4.1.7)
  #[serde(skip_serializing_if = "Option::is_none")]
  x5t: Option<String>,
  /// X.509 Certificate SHA-256 Thumbprint.
  ///
  /// A base64url-encoded SHA-256 thumbprint of the DER encoding of the X.509
  /// certificate corresponding to the key used to digitally sign the JWS.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7515#section-4.1.8)
  #[serde(rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
  x5t_s256: Option<String>,
  /// Type.
  ///
  /// Used by JWS applications to declare the media type of this complete JWS.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7515#section-4.1.9)
  #[serde(skip_serializing_if = "Option::is_none")]
  typ: Option<String>,
  /// Content Type.
  ///
  /// Used by JWS applications to declare the media type of the secured content.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7515#section-4.1.10)
  #[serde(skip_serializing_if = "Option::is_none")]
  cty: Option<String>,
  /// Critical.
  ///
  /// Indicates that JWS extensions are being used that MUST be understood and
  /// processed.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc7515#section-4.1.11)
  #[serde(skip_serializing_if = "Option::is_none")]
  crit: Option<Vec<String>>,
  /// URL.
  ///
  /// Specifies the URL to which this JWS object is directed.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc8555#section-6.4.1)
  #[serde(skip_serializing_if = "Option::is_none")]
  url: Option<Url>,
  /// Nonce.
  ///
  /// Provides a unique value that enables the verifier of a JWS to recognize
  /// when replay has occurred.
  ///
  /// [More Info](https://tools.ietf.org/html/rfc8555#section-6.5.2)
  #[serde(skip_serializing_if = "Option::is_none")]
  nonce: Option<String>,
}

impl Default for JwtHeader {
  fn default() -> Self {
    Self::new()
  }
}

impl JwtHeader {
  /// Create a new `JwtHeader`.
  pub const fn new() -> Self {
    Self {
      jku: None,
      jwk: None,
      kid: None,
      x5u: None,
      x5c: None,
      x5t: None,
      x5t_s256: None,
      typ: None,
      cty: None,
      crit: None,
      url: None,
      nonce: None,
    }
  }

  /// Returns the value of the JWK Set URL claim (jku).
  pub fn jku(&self) -> Option<&Url> {
    self.jku.as_ref()
  }

  /// Sets a value for the JWK Set URL claim (jku).
  pub fn set_jku(&mut self, value: impl Into<Url>) {
    self.jku = Some(value.into());
  }

  /// Returns the value of the JWK claim (jwk).
  pub fn jwk(&self) -> Option<&Jwk> {
    self.jwk.as_ref()
  }

  /// Sets a value for the JWK claim (jwk).
  pub fn set_jwk(&mut self, value: impl Into<Jwk>) {
    self.jwk = Some(value.into());
  }

  /// Returns the value of the key ID claim (kid).
  pub fn kid(&self) -> Option<&str> {
    self.kid.as_deref()
  }

  /// Sets a value for the key ID claim (kid).
  pub fn set_kid(&mut self, value: impl Into<String>) {
    self.kid = Some(value.into());
  }

  /// Returns the value of the X.509 URL claim (x5u).
  pub fn x5u(&self) -> Option<&Url> {
    self.x5u.as_ref()
  }

  /// Sets a value for the X.509 URL claim (x5u).
  pub fn set_x5u(&mut self, value: impl Into<Url>) {
    self.x5u = Some(value.into());
  }

  /// Returns the value of the X.509 certificate chain claim (x5c).
  pub fn x5c(&self) -> Option<&[String]> {
    self.x5c.as_deref()
  }

  /// Sets values for the X.509 certificate chain claim (x5c).
  pub fn set_x5c(&mut self, value: impl IntoIterator<Item = impl Into<String>>) {
    self.x5c = Some(value.into_iter().map(Into::into).collect());
  }

  /// Returns the value of the X.509 certificate SHA-1 thumbprint claim (x5t).
  pub fn x5t(&self) -> Option<&str> {
    self.x5t.as_deref()
  }

  /// Sets a value for the X.509 certificate SHA-1 thumbprint claim (x5t).
  pub fn set_x5t(&mut self, value: impl Into<String>) {
    self.x5t = Some(value.into());
  }

  /// Returns the value of the X.509 certificate SHA-256 thumbprint claim
  /// (x5t#S256).
  pub fn x5t_s256(&self) -> Option<&str> {
    self.x5t_s256.as_deref()
  }

  /// Sets a value for the X.509 certificate SHA-256 thumbprint claim
  /// (x5t#S256).
  pub fn set_x5t_s256(&mut self, value: impl Into<String>) {
    self.x5t_s256 = Some(value.into());
  }

  /// Returns the value of the token type claim (typ).
  pub fn typ(&self) -> Option<&str> {
    self.typ.as_deref()
  }

  /// Sets a value for the token type claim (typ).
  pub fn set_typ(&mut self, value: impl Into<String>) {
    self.typ = Some(value.into());
  }

  /// Returns the value of the content type claim (cty).
  pub fn cty(&self) -> Option<&str> {
    self.cty.as_deref()
  }

  /// Sets a value for the content type claim (cty).
  pub fn set_cty(&mut self, value: impl Into<String>) {
    self.cty = Some(value.into());
  }

  /// Returns the value of the critical claim (crit).
  pub fn crit(&self) -> Option<&[String]> {
    self.crit.as_deref()
  }

  /// Sets values for the critical claim (crit).
  pub fn set_crit(&mut self, value: impl IntoIterator<Item = impl Into<String>>) {
    self.crit = Some(value.into_iter().map(Into::into).collect());
  }

  /// Returns the value of the url claim (url).
  pub fn url(&self) -> Option<&Url> {
    self.url.as_ref()
  }

  /// Sets a value for the url claim (url).
  pub fn set_url(&mut self, value: impl Into<Url>) {
    self.url = Some(value.into());
  }

  /// Returns the value of the nonce claim (nonce).
  pub fn nonce(&self) -> Option<&str> {
    self.nonce.as_deref()
  }

  /// Sets a value for the nonce claim (nonce).
  pub fn set_nonce(&mut self, value: impl Into<String>) {
    self.nonce = Some(value.into());
  }

  /// Returns `true` if the header contains the given `claim`, `false` otherwise.
  pub fn has(&self, claim: &str) -> bool {
    match claim {
      "jku" => self.jku().is_some(),
      "jwk" => self.jwk().is_some(),
      "kid" => self.kid().is_some(),
      "x5u" => self.x5u().is_some(),
      "x5c" => self.x5c().is_some(),
      "x5t" => self.x5t().is_some(),
      "x5t#S256" => self.x5t_s256().is_some(),
      "typ" => self.typ().is_some(),
      "cty" => self.cty().is_some(),
      "crit" => self.crit().is_some(),
      "url" => self.url().is_some(),
      "nonce" => self.nonce().is_some(),
      _ => false,
    }
  }

  /// Returns `true` if none of the fields are set in both `self` and `other`.
  pub fn is_disjoint(&self, other: &JwtHeader) -> bool {
    let has_duplicate: bool = self.jku.is_some() && other.jku.is_some()
      || self.jwk.is_some() && other.jwk.is_some()
      || self.kid.is_some() && other.kid.is_some()
      || self.x5u.is_some() && other.x5u.is_some()
      || self.x5c.is_some() && other.x5c.is_some()
      || self.x5t.is_some() && other.x5t.is_some()
      || self.x5t_s256.is_some() && other.x5t_s256.is_some()
      || self.typ.is_some() && other.typ.is_some()
      || self.cty.is_some() && other.cty.is_some()
      || self.crit.is_some() && other.crit.is_some()
      || self.url.is_some() && other.url.is_some()
      || self.nonce.is_some() && other.nonce.is_some();

    !has_duplicate
  }
}

impl JoseHeader for JwtHeader {
  fn common(&self) -> &JwtHeader {
    self
  }

  fn has_claim(&self, claim: &str) -> bool {
    self.has(claim)
  }
}
