// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use anyhow::anyhow;
use anyhow::Context;
use fastcrypto::ed25519::Ed25519PublicKey;
use fastcrypto::traits::ToFromBytes;
use identity_iota::iota::IotaDocument;
use identity_iota::iota::NetworkName;
use identity_iota::verification::jws::JwsAlgorithm;
use identity_iota::verification::MethodScope;
use identity_jose::jwk::Jwk;
use identity_storage::key_id_storage::KeyIdMemstore;
use identity_storage::key_storage::JwkMemStore;
use identity_storage::JwkDocumentExt;
use identity_storage::JwkStorage;
use identity_storage::KeyId;
use identity_storage::KeyIdStorage;
use identity_storage::KeyType;
use identity_storage::Storage;
use identity_storage::StorageSigner;
use identity_stronghold::StrongholdStorage;
use identity_iota::iota::rebased::client::IdentityClient;
use identity_iota::iota::rebased::client::IdentityClientReadOnly;
use identity_iota::iota::rebased::transaction::Transaction;
use iota_sdk_legacy::client::secret::stronghold::StrongholdSecretManager;
use iota_sdk_legacy::client::stronghold::StrongholdAdapter;
use iota_sdk_legacy::client::Password;
use iota_sdk::types::base_types::IotaAddress;
use iota_sdk::types::base_types::ObjectID;
use iota_sdk::IotaClient;
use iota_sdk::IotaClientBuilder;
use jsonpath_rust::JsonPathQuery;
use rand::distributions::Alphanumeric;
use rand::distributions::DistString;
use rand::thread_rng;
use serde_json::Value;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::sync::OnceCell;
use tokio::task::JoinHandle;
use tonic::transport::Uri;
const TEST_GAS_BUDGET: u64 = 50_000_000;

type MemStorage = Storage<JwkMemStore, KeyIdMemstore>;

const FAUCET_ENDPOINT: &str = "http://localhost:9123/gas";

static PACKAGE_ID: OnceCell<ObjectID> = OnceCell::const_new();

const SCRIPT_DIR: &str = concat!(
  env!("CARGO_MANIFEST_DIR"),
  "/../../",
  "identity_iota_core",
  "/scripts"
);
const CACHED_PKG_ID: &str = "/tmp/identity_iota_pkg_id.txt";

pub struct TestServer {
  client: IdentityClientReadOnly,
  addr: SocketAddr,
  _handle: JoinHandle<Result<(), tonic::transport::Error>>,
}

impl TestServer {
  pub async fn new() -> Self {
    let stronghold = StrongholdSecretManager::builder()
      .password(random_password(18))
      .build(random_stronghold_path())
      .map(StrongholdStorage::new)
      .expect("Failed to create temporary stronghold");

    Self::new_with_stronghold(stronghold).await
  }

  pub async fn new_with_stronghold(stronghold: StrongholdStorage) -> Self {
    let _ = tracing::subscriber::set_global_default(tracing_subscriber::fmt().compact().finish());

    let listener = TcpListener::bind("127.0.0.1:0")
      .await
      .expect("Failed to bind to random OS's port");
    let addr = listener.local_addr().unwrap();

    let iota_client = IotaClientBuilder::default()
      .build_localnet()
      .await
      .expect("Failed to connect to API's endpoint");

    let identity_pkg_id = PACKAGE_ID
      .get_or_try_init(|| init(&iota_client))
      .await
      .copied()
      .expect("failed to publish package ID");

    let identity_client = IdentityClientReadOnly::new(iota_client, identity_pkg_id)
      .await
      .expect("Failed to build Identity client");

    let server = identity_grpc::server::GRpcServer::new(identity_client.clone(), stronghold)
      .into_router()
      .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener));
    TestServer {
      _handle: tokio::spawn(server),
      addr,
      client: identity_client,
    }
  }

  pub fn endpoint(&self) -> Uri {
    format!("https://{}", self.addr)
      .parse()
      .expect("Failed to parse server's URI")
  }

  pub fn client(&self) -> &IdentityClientReadOnly {
    &self.client
  }
}

pub async fn create_did<K, I>(
  client: &IdentityClientReadOnly,
  storage: &Storage<K, I>,
) -> anyhow::Result<(IotaAddress, IotaDocument, KeyId, String)>
where
  K: JwkStorage,
  I: KeyIdStorage,
{
  let (address, key_id, pub_key_jwk) = get_address(storage).await.context("failed to get address with funds")?;

  // Fund the account
  request_faucet_funds(address, FAUCET_ENDPOINT).await?;

  let signer = StorageSigner::new(storage, key_id.clone(), pub_key_jwk);

  let identity_client = IdentityClient::new(client.clone(), signer).await?;

  let network_name = client.network();
  let (document, fragment): (IotaDocument, String) = create_did_document(network_name, storage).await?;

  let document = identity_client
    .publish_did_document(document)
    .execute(&identity_client)
    .await?
    .output;

  Ok((address, document, key_id, fragment))
}

/// Creates an example DID document with the given `network_name`.
///
/// Its functionality is equivalent to the "create DID" example
/// and exists for convenient calling from the other examples.
pub async fn create_did_document<K, I>(
  network_name: &NetworkName,
  storage: &Storage<K, I>,
) -> anyhow::Result<(IotaDocument, String)>
where
  I: KeyIdStorage,
  K: JwkStorage,
{
  let mut document: IotaDocument = IotaDocument::new(network_name);

  let fragment: String = document
    .generate_method(
      storage,
      JwkMemStore::ED25519_KEY_TYPE,
      JwsAlgorithm::EdDSA,
      None,
      MethodScope::VerificationMethod,
    )
    .await?;

  Ok((document, fragment))
}

/// Generates a new Ed25519 key pair
pub async fn get_address<I, K>(storage: &Storage<K, I>) -> anyhow::Result<(IotaAddress, KeyId, Jwk)>
where
  K: JwkStorage,
  I: KeyIdStorage,
{
  let generated_key = storage
    .key_storage()
    .generate(KeyType::new("Ed25519"), JwsAlgorithm::EdDSA)
    .await?;

  let key_id = generated_key.key_id;

  let pub_key_jwt = generated_key.jwk.to_public().expect("should not fail");
  let pub_key_bytes = pub_key_jwt
    .try_okp_params()
    .map(|key| identity_jose::jwu::decode_b64(key.x.clone()).expect("should be decodeable"))?;

  let address = Ed25519PublicKey::from_bytes(&pub_key_bytes)?;

  Ok((IotaAddress::from(&address), key_id, pub_key_jwt))
}

/// Requests funds from the faucet for the given `address`.
async fn request_faucet_funds(address: IotaAddress, faucet_endpoint: &str) -> anyhow::Result<()> {
  let output = Command::new("iota")
    .arg("client")
    .arg("faucet")
    .arg("--address")
    .arg(address.to_string())
    .arg("--url")
    .arg(faucet_endpoint)
    .arg("--json")
    .output()
    .await
    .context("Failed to execute command")?;

  // Check if the output is success
  if !output.status.success() {
    anyhow::bail!(
      "Failed to request funds from faucet: {}",
      std::str::from_utf8(&output.stderr).unwrap()
    );
  }

  Ok(())
}

pub struct Entity<K, I> {
  storage: Storage<K, I>,
  did: Option<(IotaAddress, IotaDocument, KeyId, String)>,
}

pub fn random_password(len: usize) -> Password {
  let mut rng = thread_rng();
  Alphanumeric.sample_string(&mut rng, len).into()
}

pub fn random_stronghold_path() -> PathBuf {
  let mut file = std::env::temp_dir();
  file.push("test_strongholds");
  file.push(rand::distributions::Alphanumeric.sample_string(&mut rand::thread_rng(), 32));
  file.set_extension("stronghold");
  file.to_owned()
}

impl Default for Entity<JwkMemStore, KeyIdMemstore> {
  fn default() -> Self {
    let storage = MemStorage::new(JwkMemStore::new(), KeyIdMemstore::new());

    Self { storage, did: None }
  }
}

impl Entity<JwkMemStore, KeyIdMemstore> {
  pub fn new() -> Self {
    Self::default()
  }
}

impl Entity<StrongholdStorage, StrongholdStorage> {
  pub fn new_with_stronghold(s: StrongholdStorage) -> Self {
    let storage = Storage::new(s.clone(), s);

    Self { storage, did: None }
  }
}

impl<K: JwkStorage, I: KeyIdStorage> Entity<K, I> {
  pub async fn create_did(&mut self, client: &IdentityClientReadOnly) -> anyhow::Result<()> {
    let Entity { storage, did, .. } = self;

    *did = Some(create_did(client, storage).await?);

    Ok(())
  }

  pub fn storage(&self) -> &Storage<K, I> {
    &self.storage
  }

  pub fn document(&self) -> Option<&IotaDocument> {
    self.did.as_ref().map(|(_, doc, _, _)| doc)
  }

  pub fn fragment(&self) -> Option<&str> {
    self.did.as_ref().map(|(_, _, _, frag)| frag.as_ref())
  }
}

impl Entity<StrongholdStorage, StrongholdStorage> {
  pub async fn update_document<F>(&mut self, client: &IdentityClientReadOnly, f: F) -> anyhow::Result<()>
  where
    F: FnOnce(IotaDocument) -> Option<IotaDocument>,
  {
    let (address, doc, key_id, fragment) = self.did.take().context("Missing doc")?;
    let mut new_doc = f(doc.clone());
    if let Some(doc) = new_doc.take() {
      let Entity { storage, .. } = self;

      let public_key = storage.key_id_storage().get_public_key(&key_id).await?;
      let signer = StorageSigner::new(storage, key_id.clone(), public_key);

      let identity_client = IdentityClient::new(client.clone(), signer).await?;

      new_doc = Some(
        identity_client
          .publish_did_document_update(doc, TEST_GAS_BUDGET)
          .await?,
      );
    }

    self.did = Some((address, new_doc.unwrap_or(doc), key_id, fragment));

    Ok(())
  }
}

pub fn make_stronghold() -> StrongholdAdapter {
  StrongholdAdapter::builder()
    .password(random_password(18))
    .build(random_stronghold_path())
    .expect("Failed to create temporary stronghold")
}

async fn get_active_address() -> anyhow::Result<IotaAddress> {
  Command::new("iota")
    .arg("client")
    .arg("active-address")
    .arg("--json")
    .output()
    .await
    .context("Failed to execute command")
    .and_then(|output| Ok(serde_json::from_slice::<IotaAddress>(&output.stdout)?))
}

async fn init(iota_client: &IotaClient) -> anyhow::Result<ObjectID> {
  let network_id = iota_client.read_api().get_chain_identifier().await?;
  let address = get_active_address().await?;

  // Request Funds

  request_faucet_funds(address, FAUCET_ENDPOINT).await.unwrap();

  if let Ok(id) = std::env::var("IDENTITY_IOTA_PKG_ID").or(get_cached_id(&network_id).await) {
    std::env::set_var("IDENTITY_IOTA_PKG_ID", id.clone());
    id.parse().context("failed to parse object id from str")
  } else {
    publish_package(address).await
  }
}

async fn get_cached_id(network_id: &str) -> anyhow::Result<String> {
  let cache = tokio::fs::read_to_string(CACHED_PKG_ID).await?;
  let (cached_id, cached_network_id) = cache.split_once(';').ok_or(anyhow!("Invalid or empty cached data"))?;

  if cached_network_id == network_id {
    Ok(cached_id.to_owned())
  } else {
    Err(anyhow!("A network change has invalidated the cached data"))
  }
}

async fn publish_package(active_address: IotaAddress) -> anyhow::Result<ObjectID> {
  let output = Command::new("sh")
    .current_dir(SCRIPT_DIR)
    .arg("publish_identity_package.sh")
    .output()
    .await?;
  let stdout = std::str::from_utf8(&output.stdout).unwrap();

  if !output.status.success() {
    let stderr = std::str::from_utf8(&output.stderr).unwrap();
    anyhow::bail!("Failed to publish move package: \n\n{stdout}\n\n{stderr}");
  }

  let package_id: ObjectID = {
    let stdout_trimmed = stdout.trim();
    ObjectID::from_str(stdout_trimmed).with_context(|| {
      let stderr = std::str::from_utf8(&output.stderr).unwrap();
      format!("failed to find IDENTITY_IOTA_PKG_ID in response from: '{stdout_trimmed}'; {stderr}")
    })?
  };

  // Persist package ID in order to avoid publishing the package for every test.
  let package_id_str = package_id.to_string();
  std::env::set_var("IDENTITY_IOTA_PKG_ID", package_id_str.as_str());
  let mut file = std::fs::File::create(CACHED_PKG_ID)?;
  write!(&mut file, "{};{}", package_id_str, active_address)?;

  Ok(package_id)
}
