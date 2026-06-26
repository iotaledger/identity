// Copyright 2020-2025 IOTA Stiftung, Fondazione LINKS
// SPDX-License-Identifier: Apache-2.0

use identity_core::convert::ToJson;
use identity_verification::MethodData;
use identity_verification::VerificationMethod;
use seahash::SeaHasher;
use std::fmt::Display;
use std::hash::Hasher;

use super::KeyIdStorageError;

/// Error that may occur when constructing a [`MethodDigest`].
pub type MethodDigestConstructionError = identity_core::common::SingleStructError<MethodDigestConstructionErrorKind>;

/// Characterization of the underlying cause of a [`MethodDigestConstructionError`].
#[derive(Debug)]
#[non_exhaustive]
pub enum MethodDigestConstructionErrorKind {
  /// Caused by a missing id on a verification method.
  ///
  /// This error should be impossible but exists for safety reasons.
  MissingIdFragment,
  /// Caused by a failure to decode a method's [key material](identity_verification::MethodData).
  DataDecodingFailure,
}

impl Display for MethodDigestConstructionErrorKind {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str("method digest construction failure: ")?;
    match self {
      MethodDigestConstructionErrorKind::MissingIdFragment => f.write_str("missing id fragment"),
      MethodDigestConstructionErrorKind::DataDecodingFailure => f.write_str("data decoding failure"),
    }
  }
}

/// Unique identifier of a [`VerificationMethod`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MethodDigest {
  /// Version of hashing.
  version: u8,
  /// Hash value.
  value: u64,
}

impl MethodDigest {
  /// Creates a new [`MethodDigest`].
  pub fn new(verification_method: &VerificationMethod) -> Result<Self, MethodDigestConstructionError> {
    // Method digest version 0 formula: SeaHash(<fragment><JWK thumbprint if JWK else decoded public key>)
    use MethodDigestConstructionErrorKind::*;
    let mut hasher: SeaHasher = SeaHasher::new();
    let fragment: &str = verification_method.id().fragment().ok_or(MissingIdFragment)?;
    let method_data: &MethodData = verification_method.data();

    hasher.write(fragment.as_bytes());

    match method_data {
      MethodData::PublicKeyJwk(jwk) => hasher.write(jwk.thumbprint_sha256().as_ref()),
      MethodData::CompositeJwk(composite) => {
        let algid = composite
          .alg_id()
          .to_json_vec()
          .map_err(|err| MethodDigestConstructionError::new(DataDecodingFailure).with_source(err))?;
        hasher.write(&algid);
        hasher.write(composite.traditional_public_key().thumbprint_sha256().as_ref());
        hasher.write(composite.pq_public_key().thumbprint_sha256().as_ref());
      }
      _ => hasher.write(
        &method_data
          .try_decode()
          .map_err(|err| MethodDigestConstructionError::new(DataDecodingFailure).with_source(err))?,
      ),
    };

    let key_hash: u64 = hasher.finish();

    Ok(Self {
      version: 0,
      value: key_hash,
    })
  }

  /// Packs [`MethodDigest`] into bytes.
  pub fn pack(&self) -> Vec<u8> {
    let mut pack: Vec<u8> = vec![self.version];
    pack.append(&mut self.value.to_le_bytes().to_vec());
    pack
  }

  /// Unpacks bytes into [`MethodDigest`].
  pub fn unpack(bytes: Vec<u8>) -> crate::key_id_storage::KeyIdStorageResult<Self> {
    if bytes.len() != 9 {
      return Err(KeyIdStorageError::new(super::KeyIdStorageErrorKind::SerializationError));
    }
    let version: u8 = bytes[0];
    if version != 0 {
      return Err(KeyIdStorageError::new(super::KeyIdStorageErrorKind::SerializationError));
    }
    let value_le_bytes: [u8; 8] = bytes[1..9]
      .try_into()
      .map_err(|_| KeyIdStorageError::new(super::KeyIdStorageErrorKind::SerializationError))?;
    let value: u64 = u64::from_le_bytes(value_le_bytes);
    Ok(Self { version, value })
  }
}

#[cfg(test)]
mod test {
  use crate::key_id_storage::KeyIdStorageError;
  use crate::key_id_storage::KeyIdStorageErrorKind;
  use identity_core::convert::FromJson;
  use identity_core::json;
  use identity_verification::VerificationMethod;
  use serde_json::Value;

  use super::MethodDigest;

  #[test]
  fn hash() {
    // These values should be tested in the bindings too.
    let a: Value = json!(
      {
        "id": "did:example:HHoh9NQC9AUsK15Jyyq53VTujxEUizKDXRXd7zbT1B5u#frag_1",
        "controller": "did:example:HHoh9NQC9AUsK15Jyyq53VTujxEUizKDXRXd7zbT1B5u",
        "type": "Ed25519VerificationKey2018",
        "publicKeyMultibase": "zHHoh9NQC9AUsK15Jyyq53VTujxEUizKDXRXd7zbT1B5u"
      }
    );
    let verification_method: VerificationMethod = VerificationMethod::from_json_value(a).unwrap();
    let method_digest: MethodDigest = MethodDigest::new(&verification_method).unwrap();
    let method_digest_expected: MethodDigest = MethodDigest {
      version: 0,
      value: 9634551232492878922,
    };
    assert_eq!(method_digest, method_digest_expected);

    let packed: Vec<u8> = method_digest.pack();
    let packed_expected: Vec<u8> = vec![0, 74, 60, 10, 199, 76, 205, 180, 133];
    assert_eq!(packed, packed_expected);
  }

  #[test]
  fn pack() {
    let verification_method: VerificationMethod = crate::storage::tests::test_utils::create_verification_method();
    let method_digest: MethodDigest = MethodDigest::new(&verification_method).unwrap();
    let packed: Vec<u8> = method_digest.pack();
    let method_digest_unpacked: MethodDigest = MethodDigest::unpack(packed).unwrap();
    assert_eq!(method_digest, method_digest_unpacked);
  }

  #[test]
  fn unpack() {
    let packed: Vec<u8> = vec![0, 255, 212, 82, 63, 57, 19, 134, 193];
    let method_digest_unpacked: MethodDigest = MethodDigest::unpack(packed).unwrap();
    let method_digest_expected: MethodDigest = MethodDigest {
      version: 0,
      value: 13944854432795776255,
    };
    assert_eq!(method_digest_unpacked, method_digest_expected);
  }

  #[test]
  fn invalid_unpack() {
    let packed: Vec<u8> = vec![1, 255, 212, 82, 63, 57, 19, 134, 193];
    let method_digest_unpacked = MethodDigest::unpack(packed).unwrap_err();
    let _expected_error = KeyIdStorageError::new(KeyIdStorageErrorKind::SerializationError);
    assert!(matches!(method_digest_unpacked, _expected_error));

    // Vec size > 9.
    let packed: Vec<u8> = vec![1, 255, 212, 82, 63, 57, 19, 134, 193, 200];
    let method_digest_unpacked = MethodDigest::unpack(packed).unwrap_err();
    let _expected_error = KeyIdStorageError::new(KeyIdStorageErrorKind::SerializationError);
    assert!(matches!(method_digest_unpacked, _expected_error));

    // Vec size < 9.
    let packed: Vec<u8> = vec![1, 255, 212, 82, 63, 57, 19, 134];
    let method_digest_unpacked = MethodDigest::unpack(packed).unwrap_err();
    let _expected_error = KeyIdStorageError::new(KeyIdStorageErrorKind::SerializationError);
    assert!(matches!(method_digest_unpacked, _expected_error));

    // Vec size 0;
    let packed: Vec<u8> = vec![];
    let method_digest_unpacked = MethodDigest::unpack(packed).unwrap_err();
    let _expected_error = KeyIdStorageError::new(KeyIdStorageErrorKind::SerializationError);
    assert!(matches!(method_digest_unpacked, _expected_error));
  }
}
