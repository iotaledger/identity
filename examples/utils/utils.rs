// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use identity_iota::iota::IotaDocument;
use identity_iota::iota_interaction::OptionalSync;
use identity_iota::storage::JwkDocumentExt;
use identity_iota::storage::JwkMemStore;
use identity_iota::storage::KeyIdMemstore;
use identity_iota::storage::Storage;
use identity_iota::verification::jws::JwsAlgorithm;
use identity_iota::verification::MethodScope;

use identity_iota::iota::rebased::client::IdentityClient;
use identity_iota::iota::rebased::client::IdentityClientReadOnly;
use identity_iota::iota::rebased::client::IotaKeySignature;
use identity_iota::iota::rebased::utils::request_funds;
use identity_storage::JwkStorage;
use identity_storage::KeyIdStorage;
use identity_storage::KeyType;
use identity_storage::StorageSigner;
use identity_stronghold::StrongholdStorage;
use iota_sdk::types::base_types::IotaAddress;
use iota_sdk::IotaClientBuilder;
use iota_sdk::IOTA_LOCAL_NETWORK_URL;
use iota_sdk_legacy::client::secret::stronghold::StrongholdSecretManager;
use iota_sdk_legacy::client::Password;
use rand::distributions::DistString;
use secret_storage::Signer;
use serde_json::Value;

pub const TEST_GAS_BUDGET: u64 = 50_000_000;

pub type MemStorage = Storage<JwkMemStore, KeyIdMemstore>;

pub async fn create_did_document<K, I, S>(
  identity_client: &IdentityClient<S>,
  storage: &Storage<K, I>,
) -> anyhow::Result<(IotaDocument, String)>
where
  K: identity_storage::JwkStorage,
  I: identity_storage::KeyIdStorage,
  S: Signer<IotaKeySignature> + OptionalSync,
{
  // Create a new DID document with a placeholder DID.
  let mut unpublished: IotaDocument = IotaDocument::new(identity_client.network());
  let verification_method_fragment = unpublished
    .generate_method(
      storage,
      JwkMemStore::ED25519_KEY_TYPE,
      JwsAlgorithm::EdDSA,
      None,
      MethodScope::VerificationMethod,
    )
    .await?;

  let document = identity_client
    .publish_did_document(unpublished)
    .with_gas_budget(TEST_GAS_BUDGET)
    .build_and_execute(identity_client)
    .await?
    .output;

  Ok((document, verification_method_fragment))
}

/// Creates a random stronghold path in the temporary directory, whose exact location is OS-dependent.
pub fn random_stronghold_path() -> PathBuf {
  let mut file = std::env::temp_dir();
  file.push("test_strongholds");
  file.push(rand::distributions::Alphanumeric.sample_string(&mut rand::thread_rng(), 32));
  file.set_extension("stronghold");
  file.to_owned()
}

pub async fn get_read_only_client() -> anyhow::Result<IdentityClientReadOnly> {
  let api_endpoint = std::env::var("API_ENDPOINT").unwrap_or_else(|_| IOTA_LOCAL_NETWORK_URL.to_string());
  let iota_client = IotaClientBuilder::default()
    .build(&api_endpoint)
    .await
    .map_err(|err| anyhow::anyhow!(format!("failed to connect to network; {}", err)))?;
  let package_id = std::env::var("IOTA_IDENTITY_PKG_ID")
    .map_err(|e| {
      anyhow::anyhow!("env variable IOTA_IDENTITY_PKG_ID must be set in order to run the examples").context(e)
    })
    .and_then(|pkg_str| pkg_str.parse().context("invalid package id"))?;

  IdentityClientReadOnly::new_with_pkg_id(iota_client, package_id)
    .await
    .context("failed to create a read-only IdentityClient")
}

pub async fn get_funded_client<K, I>(
  storage: &Storage<K, I>,
) -> Result<IdentityClient<StorageSigner<K, I>>, anyhow::Error>
where
  K: JwkStorage,
  I: KeyIdStorage,
{
  // generate new key
  let generate = storage
    .key_storage()
    .generate(KeyType::new("Ed25519"), JwsAlgorithm::EdDSA)
    .await?;
  let public_key_jwk = generate.jwk.to_public().expect("public components should be derivable");
  let signer = StorageSigner::new(storage, generate.key_id, public_key_jwk);
  let sender_address = IotaAddress::from(&Signer::public_key(&signer).await?);

  request_funds(&sender_address).await?;

  let read_only_client = get_read_only_client().await?;
  let identity_client = IdentityClient::new(read_only_client, signer).await?;

  Ok(identity_client)
}

pub fn get_memstorage() -> Result<MemStorage, anyhow::Error> {
  Ok(MemStorage::new(JwkMemStore::new(), KeyIdMemstore::new()))
}

pub fn get_stronghold_storage(
  path: Option<PathBuf>,
) -> Result<Storage<StrongholdStorage, StrongholdStorage>, anyhow::Error> {
  // Stronghold snapshot path.
  let path = path.unwrap_or_else(random_stronghold_path);

  // Stronghold password.
  let password = Password::from("secure_password".to_owned());

  let stronghold = StrongholdSecretManager::builder()
    .password(password.clone())
    .build(path.clone())?;

  // Create a `StrongholdStorage`.
  // `StrongholdStorage` creates internally a `SecretManager` that can be
  // referenced to avoid creating multiple instances around the same stronghold snapshot.
  let stronghold_storage = StrongholdStorage::new(stronghold);

  Ok(Storage::new(stronghold_storage.clone(), stronghold_storage.clone()))
}

pub fn pretty_print_json(label: &str, value: &str) {
  let data: Value = serde_json::from_str(value).unwrap();
  let pretty_json = serde_json::to_string_pretty(&data).unwrap();
  println!("--------------------------------------");
  println!("{label}:");
  println!("--------------------------------------");
  println!("{pretty_json} \n");
}
