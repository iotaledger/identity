// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use identity_verification::jwk::FromJwk as _;
use identity_verification::jwk::Jwk;
use identity_verification::jwk::ToJwk as _;
use identity_verification::jws::JwsAlgorithm;
use iota_interaction::types::base_types::IotaAddress;
use iota_interaction::types::crypto::IotaKeyPair;
use iota_interaction::types::crypto::SignatureScheme;
use iota_interaction::KeytoolStorage;

use super::JwkGenOutput;
use super::JwkStorage;
use super::KeyId;
use super::KeyStorageError;
use super::KeyStorageErrorKind;
use super::KeyStorageResult;
use super::KeyType;

#[cfg_attr(feature = "send-sync-storage", async_trait)]
#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
impl JwkStorage for KeytoolStorage {
  async fn generate(&self, key_type: KeyType, alg: JwsAlgorithm) -> KeyStorageResult<JwkGenOutput> {
    let key_scheme = match key_type.as_str() {
      "ed25519" => SignatureScheme::ED25519,
      "secp256r1" => SignatureScheme::Secp256r1,
      "secp256k1" => SignatureScheme::Secp256k1,
      _ => return Err(KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType)),
    };

    check_key_alg_compatibility(&key_type, &alg)?;

    let (pk, _alias) = self
      .generate_key(key_scheme)
      .map_err(|e| KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_source(e))?;

    let address = IotaAddress::from(&pk);
    let mut jwk = pk
      .to_jwk()
      .map_err(|e| KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_source(e))?;
    jwk.set_kid(jwk.thumbprint_sha256_b64());

    Ok(JwkGenOutput {
      key_id: KeyId::new(address.to_string()),
      jwk,
    })
  }

  async fn insert(&self, jwk: Jwk) -> KeyStorageResult<KeyId> {
    let sk = IotaKeyPair::from_jwk(&jwk)
      .map_err(|e| KeyStorageError::new(KeyStorageErrorKind::RetryableIOFailure).with_source(e))?;
    let pk = sk.public();
    let _alias = self
      .insert_key(sk)
      .map_err(|e| KeyStorageError::new(KeyStorageErrorKind::RetryableIOFailure).with_source(e))?;

    let address = IotaAddress::from(&pk);
    Ok(KeyId::new(address.to_string()))
  }

  async fn sign(&self, key_id: &KeyId, data: &[u8], _pk_jwk: &Jwk) -> KeyStorageResult<Vec<u8>> {
    let iota_address = key_id.as_str().parse().map_err(|_| {
      KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_custom_message("invalid IOTA address")
    })?;

    self
      .sign_raw(iota_address, data)
      .map_err(|e| KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_source(e))
  }

  async fn delete(&self, _key_id: &KeyId) -> KeyStorageResult<()> {
    Err(
      KeyStorageError::new(KeyStorageErrorKind::Unspecified)
        .with_custom_message("IOTA Keytool doesn't support key deletion"),
    )
  }

  async fn exists(&self, key_id: &KeyId) -> KeyStorageResult<bool> {
    let iota_address = key_id.as_str().parse().map_err(|_| {
      KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_custom_message("invalid IOTA address")
    })?;
    let exists = self
      .get_key(iota_address)
      .map_err(|e| KeyStorageError::new(KeyStorageErrorKind::RetryableIOFailure).with_source(e))?
      .is_some();

    Ok(exists)
  }
}

/// Check that the key type can be used with the algorithm.
fn check_key_alg_compatibility(key_type: &KeyType, alg: &JwsAlgorithm) -> KeyStorageResult<()> {
  match (key_type.as_str(), alg) {
    ("ed25519", JwsAlgorithm::EdDSA) => Ok(()),
    ("secp256r1", JwsAlgorithm::ES256) => Ok(()),
    ("secp256k1", JwsAlgorithm::ES256K) => Ok(()),
    (key_type, alg) => Err(
      KeyStorageError::new(crate::key_storage::KeyStorageErrorKind::KeyAlgorithmMismatch)
        .with_custom_message(format!("`cannot use key type `{key_type}` with algorithm `{alg}`")),
    ),
  }
}
#[cfg(test)]
mod tests {
  use crate::JwkDocumentExt as _;
  use crate::JwsSignatureOptions;
  use crate::KeyIdStorage as _;
  use crate::KeyType;
  use crate::KeytoolStorage;
  use crate::MethodDigest;
  use anyhow::anyhow;
  use identity_credential::credential::CredentialBuilder;
  use identity_credential::credential::Subject;
  use identity_credential::validator::FailFast;
  use identity_credential::validator::JwtCredentialValidationOptions;
  use identity_credential::validator::JwtCredentialValidator;
  use identity_did::DID;
  use identity_ecdsa_verifier::EcDSAJwsVerifier;
  use identity_iota_core::IotaDocument;
  use identity_verification::jws::JwsAlgorithm;
  use identity_verification::MethodScope;
  use iota_interaction::KeytoolStorage as Keytool;
  use product_common::network_name::NetworkName;
  use serde_json::Value;

  fn make_storage() -> KeytoolStorage {
    let keytool = Keytool::default();
    KeytoolStorage::new(keytool.clone(), keytool)
  }

  #[tokio::test]
  async fn keytool_storage_works() -> anyhow::Result<()> {
    let storage = make_storage();

    let mut did_doc = IotaDocument::new(&NetworkName::try_from("iota".to_string())?);
    let fragment = did_doc
      .generate_method(
        &storage,
        KeyType::from_static_str("secp256r1"),
        JwsAlgorithm::ES256,
        None,
        MethodScope::VerificationMethod,
      )
      .await?;
    let vm = did_doc.resolve_method(&fragment, None).expect("just created it");

    let address_of_vm_key = storage
      .key_id_storage()
      .get_key_id(&MethodDigest::new(vm)?)
      .await?
      .as_str()
      .parse()?;

    let (_pk, alias) = storage
      .key_storage()
      .get_key(address_of_vm_key)?
      .ok_or_else(|| anyhow!("something wrong with the new VM key!!"))?;

    assert!(alias.starts_with("identity__"));

    let credential = CredentialBuilder::new(Value::default())
      .id("https://example.com/credentials/42".parse()?)
      .issuer(did_doc.id().to_url())
      .subject(Subject::with_id("https://example.com/users/123".parse()?))
      .build()?;

    let jwt = did_doc
      .create_credential_jwt(&credential, &storage, &fragment, &JwsSignatureOptions::default(), None)
      .await?;

    let validator = JwtCredentialValidator::with_signature_verifier(EcDSAJwsVerifier::default());
    validator.validate::<IotaDocument, Value>(
      &jwt,
      &did_doc,
      &JwtCredentialValidationOptions::default(),
      FailFast::FirstError,
    )?;

    Ok(())
  }
}
