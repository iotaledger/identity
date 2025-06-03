// Copyright 2020-2025 IOTA Stiftung, Fondazione LINKS
// SPDX-License-Identifier: Apache-2.0

use core::fmt::Display;
use core::fmt::Formatter;
use std::borrow::Cow;

use identity_did::DIDCompositeJwk;
use identity_did::DIDJwk;
use identity_jose::jwk::CompositeJwk;
use identity_jose::jwk::Jwk;
use serde::de;
use serde::Deserialize;
use serde::Serialize;

use identity_core::common::KeyComparable;
use identity_core::common::Object;
use identity_core::convert::FmtJson;

use crate::error::Error;
use crate::error::Result;
use crate::verification_method::MethodBuilder;
use crate::verification_method::MethodData;
use crate::verification_method::MethodRef;
use crate::verification_method::MethodType;
use crate::CustomMethodData;
use identity_did::CoreDID;
use identity_did::DIDUrl;
use identity_did::DID;

/// A DID Document Verification Method.
///
/// [Specification](https://www.w3.org/TR/did-core/#verification-method-properties)
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(from = "_VerificationMethod")]
pub struct VerificationMethod {
  pub(crate) id: DIDUrl,
  pub(crate) controller: CoreDID,
  #[serde(rename = "type")]
  pub(crate) type_: MethodType,
  #[serde(flatten)]
  pub(crate) data: MethodData,
  #[serde(flatten)]
  pub(crate) properties: Object,
}

/// Deserializes an [`DIDUrl`] while enforcing that its fragment is non-empty.
fn deserialize_id_with_fragment<'de, D>(deserializer: D) -> Result<DIDUrl, D::Error>
where
  D: de::Deserializer<'de>,
{
  let did_url: DIDUrl = DIDUrl::deserialize(deserializer)?;
  if did_url.fragment().unwrap_or_default().is_empty() {
    return Err(de::Error::custom("method id missing fragment"));
  }
  Ok(did_url)
}

impl VerificationMethod {
  // ===========================================================================
  // Builder
  // ===========================================================================

  /// Creates a `MethodBuilder` to configure a new `Method`.
  ///
  /// This is the same as `MethodBuilder::new()`.
  pub fn builder(properties: Object) -> MethodBuilder {
    MethodBuilder::new(properties)
  }

  /// Returns a new `Method` based on the `MethodBuilder` configuration.
  pub fn from_builder(builder: MethodBuilder) -> Result<Self> {
    let id: DIDUrl = builder.id.ok_or(Error::InvalidMethod("missing id"))?;
    if id.fragment().unwrap_or_default().is_empty() {
      return Err(Error::InvalidMethod("empty id fragment"));
    }

    if let Some(MethodData::PublicKeyJwk(ref jwk)) = builder.data {
      if !jwk.is_public() {
        return Err(crate::error::Error::PrivateKeyMaterialExposed);
      }
    };

    Ok(VerificationMethod {
      id,
      controller: builder.controller.ok_or(Error::InvalidMethod("missing controller"))?,
      type_: builder.type_.ok_or(Error::InvalidMethod("missing type"))?,
      data: builder.data.ok_or(Error::InvalidMethod("missing data"))?,
      properties: builder.properties,
    })
  }

  // ===========================================================================
  // Properties
  // ===========================================================================

  /// Returns a reference to the `VerificationMethod` id.
  pub fn id(&self) -> &DIDUrl {
    &self.id
  }

  /// Sets the `VerificationMethod` id.
  ///
  /// # Errors
  /// [`Error::MissingIdFragment`] if there is no fragment on the [`DIDUrl`].
  pub fn set_id(&mut self, id: DIDUrl) -> Result<()> {
    if id.fragment().unwrap_or_default().is_empty() {
      return Err(Error::MissingIdFragment);
    }
    self.id = id;
    Ok(())
  }

  /// Returns a reference to the `VerificationMethod` controller.
  pub fn controller(&self) -> &CoreDID {
    &self.controller
  }

  /// Returns a mutable reference to the `VerificationMethod` controller.
  pub fn controller_mut(&mut self) -> &mut CoreDID {
    &mut self.controller
  }

  /// Returns a reference to the `VerificationMethod` type.
  pub fn type_(&self) -> &MethodType {
    &self.type_
  }

  /// Returns a mutable reference to the `VerificationMethod` type.
  pub fn type_mut(&mut self) -> &mut MethodType {
    &mut self.type_
  }

  /// Returns a reference to the `VerificationMethod` data.
  pub fn data(&self) -> &MethodData {
    &self.data
  }

  /// Returns a mutable reference to the `VerificationMethod` data.
  pub fn data_mut(&mut self) -> &mut MethodData {
    &mut self.data
  }

  /// Returns a reference to the custom `VerificationMethod` properties.
  pub fn properties(&self) -> &Object {
    &self.properties
  }

  /// Returns a mutable reference to the custom `VerificationMethod` properties.
  pub fn properties_mut(&mut self) -> &mut Object {
    &mut self.properties
  }

  /// Creates a new [`MethodRef`] from `self`.
  pub fn into_method_ref(self) -> MethodRef {
    MethodRef::Embed(self)
  }

  /// Maps the [`VerificationMethod`] by applying a function `f` to
  /// the [`CoreDID`] components of id and controller. Useful when working with DID methods where the identifier
  /// is not known before publishing.
  pub fn map<F>(self, mut f: F) -> VerificationMethod
  where
    F: FnMut(CoreDID) -> CoreDID,
  {
    VerificationMethod {
      id: self.id.map(&mut f),
      controller: f(self.controller),
      type_: self.type_,
      data: self.data,
      properties: self.properties,
    }
  }

  /// Fallible version of [`VerificationMethod::map`].
  pub fn try_map<F, E>(self, mut f: F) -> Result<VerificationMethod, E>
  where
    F: FnMut(CoreDID) -> Result<CoreDID, E>,
  {
    Ok(VerificationMethod {
      id: self.id.try_map(&mut f)?,
      controller: f(self.controller)?,
      type_: self.type_,
      data: self.data,
      properties: self.properties,
    })
  }
}

impl VerificationMethod {
  // ===========================================================================
  // Constructors
  // ===========================================================================

  /// Creates a new [`VerificationMethod`] from the given `did` and [`Jwk`]. If `fragment` is not given
  /// the `kid` value of the given `key` will be used, if present, otherwise an error is returned.
  ///
  /// # Recommendations
  /// The following recommendations are essentially taken from the `publicKeyJwk` description from
  /// the [DID specification](https://www.w3.org/TR/did-core/#dfn-publickeyjwk):
  /// - It is recommended that verification methods that use [`Jwks`](Jwk) to represent their public keys use the value
  ///   of `kid` as their fragment identifier. This is done automatically if `None` is passed in as the fragment.
  /// - It is recommended that [`Jwk`] kid values are set to the public key fingerprint. See
  ///   [`Jwk::thumbprint_sha256_b64`](Jwk::thumbprint_sha256_b64).
  pub fn new_from_jwk<D: DID>(did: D, key: Jwk, fragment: Option<&str>) -> Result<Self> {
    // If a fragment is given use that, otherwise use the JWK's `kid` if it is set.
    let fragment: Cow<'_, str> = {
      let given_fragment: &str = fragment
        .or_else(|| key.kid())
        .ok_or(crate::error::Error::InvalidMethod(
          "an explicit fragment or JWK kid is required",
        ))?;
      // Make sure the fragment starts with "#"
      if given_fragment.starts_with('#') {
        Cow::Borrowed(given_fragment)
      } else {
        Cow::Owned(format!("#{given_fragment}"))
      }
    };

    let id: DIDUrl = did.to_url().join(fragment).map_err(Error::DIDUrlConstructionError)?;

    MethodBuilder::default()
      .id(id)
      .controller(did.into())
      .type_(MethodType::JSON_WEB_KEY_2020)
      .data(MethodData::PublicKeyJwk(key))
      .build()
  }
}


impl VerificationMethod {
  // ===========================================================================
  // Constructors
  // ===========================================================================

  /// Creates a new [`VerificationMethod`] from the given `did` and [`CompositeJwk`]. If `fragment` is not given
  /// the `kid` value of the given `key` will be used, if present, otherwise an error is returned.
  pub fn new_from_compositejwk<D: DID>(did: D, key: CompositeJwk, fragment: Option<&str>) -> Result<Self> {
    let composite_fragment = key.traditional_public_key()
    .kid()
    .map(|s| s.to_string())
    .or_else(|| key.pq_public_key().kid().map(|s| s.to_string()))
    .map(|s| {
      if let (Some(str1), Some(str2)) = (key.traditional_public_key().kid(), key.pq_public_key().kid()) {
        format!("{}~{}", str1, str2)
      } else {
        s
      }
    });


    let fragment: Cow<'_, str> = {
      let given_fragment: &str = fragment
        .or(composite_fragment.as_deref())
        .ok_or(Error::InvalidMethod(
          "an explicit fragment or kid is required",
        ))?;
      // Make sure the fragment starts with "#"
      if given_fragment.starts_with('#') {
        Cow::Borrowed(given_fragment)
      } else {
        Cow::Owned(format!("#{given_fragment}"))
      }
    };

    let id: DIDUrl = did.to_url().join(fragment).map_err(Error::DIDUrlConstructionError)?;

    MethodBuilder::default()
      .id(id)
      .type_(MethodType::custom("CompositeJsonWebKey"))
      .controller(did.into())
      .data(MethodData::CompositeJwk(key))
      .build()
  }
}

impl Display for VerificationMethod {
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    self.fmt_json(f)
  }
}

impl AsRef<DIDUrl> for VerificationMethod {
  fn as_ref(&self) -> &DIDUrl {
    self.id()
  }
}

impl KeyComparable for VerificationMethod {
  type Key = DIDUrl;

  #[inline]
  fn key(&self) -> &Self::Key {
    self.id()
  }
}

impl TryFrom<DIDJwk> for VerificationMethod {
  type Error = Error;
  fn try_from(did: DIDJwk) -> Result<Self, Self::Error> {
    let jwk = did.jwk();
    Self::new_from_jwk(did, jwk, Some("0"))
  }
}

impl TryFrom<DIDCompositeJwk> for VerificationMethod {
  type Error = Error;
  fn try_from(did: DIDCompositeJwk) -> Result<Self, Self::Error> {
    let jwk = did.composite_jwk();
    Self::new_from_compositejwk(did, jwk, Some("0"))
  }
}

// Horrible workaround for a tracked serde issue https://github.com/serde-rs/serde/issues/2200. Serde doesn't "consume"
// the input when deserializing flattened enums (MethodData in this case) causing duplication of data (in this case
// it ends up in the properties object). This workaround simply removes the duplication.
#[derive(Deserialize)]
struct _VerificationMethod {
  #[serde(deserialize_with = "deserialize_id_with_fragment")]
  pub(crate) id: DIDUrl,
  pub(crate) controller: CoreDID,
  #[serde(rename = "type")]
  pub(crate) type_: MethodType,
  #[serde(flatten)]
  pub(crate) data: MethodData,
  #[serde(flatten)]
  pub(crate) properties: Object,
}

impl From<_VerificationMethod> for VerificationMethod {
  fn from(value: _VerificationMethod) -> Self {
    let _VerificationMethod {
      id,
      controller,
      type_,
      data,
      mut properties,
    } = value;
    let key = match &data {
      MethodData::PublicKeyBase58(_) => "publicKeyBase58",
      MethodData::PublicKeyJwk(_) => "publicKeyJwk",
      MethodData::PublicKeyMultibase(_) => "publicKeyMultibase",
      MethodData::CompositeJwk(_) => "compositePublicKey",
      MethodData::Custom(CustomMethodData { name, .. }) => name.as_str(),
    };
    properties.remove(key);

    VerificationMethod {
      id,
      controller,
      type_,
      data,
      properties,
    }
  }
}
