// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
#![allow(dead_code)]

use anyhow::anyhow;
use anyhow::Context;
use async_trait::async_trait;
use identity_iota_core::rebased::client::IdentityClient;
use identity_iota_core::rebased::keytool::KeytoolSigner;
use identity_iota_core::rebased::utils::request_funds;
use identity_iota_core::rebased::Error;
use identity_iota_core::IotaDID;
use identity_jose::jwk::Jwk;
use identity_jose::jwk::ToJwk as _;
use identity_jose::jws::JwsAlgorithm;
use identity_storage::JwkMemStore;
use identity_storage::JwkStorage;
use identity_storage::KeyId;
use identity_storage::KeyIdMemstore;
use identity_storage::KeyIdStorage;
use identity_storage::KeyType;
use identity_storage::MethodDigest;
use identity_storage::Storage;
use identity_storage::StorageSigner;
use identity_verification::VerificationMethod;
use iota_interaction::rpc_types::IotaTransactionBlockEffectsAPI;
use iota_interaction::types::transaction::ProgrammableTransaction;
use iota_interaction::IotaKeySignature;
use iota_interaction::IotaTransactionBlockEffectsMutAPI;
use iota_interaction::OptionalSync;
use iota_interaction_rust::IotaClientAdapter;
use iota_sdk::rpc_types::IotaObjectDataOptions;
use iota_sdk::rpc_types::IotaObjectResponse;
use iota_sdk::rpc_types::IotaTransactionBlockEffects;
use iota_sdk::types::base_types::IotaAddress;
use iota_sdk::types::base_types::ObjectID;
use iota_sdk::types::crypto::PublicKey;
use iota_sdk::types::crypto::SignatureScheme;
use iota_sdk::types::object::Owner;
use iota_sdk::types::programmable_transaction_builder::ProgrammableTransactionBuilder;
use product_common::core_client::CoreClient;
use product_common::core_client::CoreClientReadOnly;
use product_common::network_name::NetworkName;

use iota_interaction::IotaClientTrait;
use iota_sdk::types::TypeTag;
use iota_sdk::types::IOTA_FRAMEWORK_PACKAGE_ID;
use iota_sdk::IotaClient;
use iota_sdk::IotaClientBuilder;
use iota_sdk::IOTA_LOCAL_NETWORK_URL;
use lazy_static::lazy_static;
use move_core_types::ident_str;
use move_core_types::language_storage::StructTag;
use product_common::transaction::transaction_builder::Transaction;
use product_common::transaction::transaction_builder::TransactionBuilder;
use secret_storage::Signer;
use serde::Deserialize;
use serde_json::Value;
use std::io::Write;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use tokio::process::Command;
use tokio::sync::OnceCell;
pub type MemStorage = Storage<JwkMemStore, KeyIdMemstore>;
pub type MemSigner<'s> = StorageSigner<'s, JwkMemStore, KeyIdMemstore>;

static PACKAGE_ID: OnceCell<ObjectID> = OnceCell::const_new();
static CLIENT: OnceCell<TestClient> = OnceCell::const_new();
const SCRIPT_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/");
const CACHED_PKG_ID: &str = "/tmp/iota_identity_pkg_id.txt";

pub const TEST_GAS_BUDGET: u64 = 50_000_000;
pub const TEST_DOC: &[u8] = &[
  68, 73, 68, 1, 0, 131, 1, 123, 34, 100, 111, 99, 34, 58, 123, 34, 105, 100, 34, 58, 34, 100, 105, 100, 58, 48, 58,
  48, 34, 44, 34, 118, 101, 114, 105, 102, 105, 99, 97, 116, 105, 111, 110, 77, 101, 116, 104, 111, 100, 34, 58, 91,
  123, 34, 105, 100, 34, 58, 34, 100, 105, 100, 58, 48, 58, 48, 35, 79, 115, 55, 95, 66, 100, 74, 120, 113, 86, 119,
  101, 76, 107, 56, 73, 87, 45, 76, 71, 83, 111, 52, 95, 65, 115, 52, 106, 70, 70, 86, 113, 100, 108, 74, 73, 99, 48,
  45, 100, 50, 49, 73, 34, 44, 34, 99, 111, 110, 116, 114, 111, 108, 108, 101, 114, 34, 58, 34, 100, 105, 100, 58, 48,
  58, 48, 34, 44, 34, 116, 121, 112, 101, 34, 58, 34, 74, 115, 111, 110, 87, 101, 98, 75, 101, 121, 34, 44, 34, 112,
  117, 98, 108, 105, 99, 75, 101, 121, 74, 119, 107, 34, 58, 123, 34, 107, 116, 121, 34, 58, 34, 79, 75, 80, 34, 44,
  34, 97, 108, 103, 34, 58, 34, 69, 100, 68, 83, 65, 34, 44, 34, 107, 105, 100, 34, 58, 34, 79, 115, 55, 95, 66, 100,
  74, 120, 113, 86, 119, 101, 76, 107, 56, 73, 87, 45, 76, 71, 83, 111, 52, 95, 65, 115, 52, 106, 70, 70, 86, 113, 100,
  108, 74, 73, 99, 48, 45, 100, 50, 49, 73, 34, 44, 34, 99, 114, 118, 34, 58, 34, 69, 100, 50, 53, 53, 49, 57, 34, 44,
  34, 120, 34, 58, 34, 75, 119, 99, 54, 89, 105, 121, 121, 65, 71, 79, 103, 95, 80, 116, 118, 50, 95, 49, 67, 80, 71,
  52, 98, 86, 87, 54, 102, 89, 76, 80, 83, 108, 115, 57, 112, 122, 122, 99, 78, 67, 67, 77, 34, 125, 125, 93, 125, 44,
  34, 109, 101, 116, 97, 34, 58, 123, 34, 99, 114, 101, 97, 116, 101, 100, 34, 58, 34, 50, 48, 50, 52, 45, 48, 53, 45,
  50, 50, 84, 49, 50, 58, 49, 52, 58, 51, 50, 90, 34, 44, 34, 117, 112, 100, 97, 116, 101, 100, 34, 58, 34, 50, 48, 50,
  52, 45, 48, 53, 45, 50, 50, 84, 49, 50, 58, 49, 52, 58, 51, 50, 90, 34, 125, 125,
];

lazy_static! {
  pub static ref TEST_COIN_TYPE: StructTag = "0x2::coin::Coin<bool>".parse().unwrap();
}

pub async fn get_funded_test_client() -> anyhow::Result<TestClient> {
  TestClient::new().await
}

async fn init(iota_client: &IotaClient) -> anyhow::Result<ObjectID> {
  let network_id = iota_client.read_api().get_chain_identifier().await?;
  let address = get_active_address().await?;

  if let Ok(id) = std::env::var("IOTA_IDENTITY_PKG_ID").or(get_cached_id(&network_id).await) {
    std::env::set_var("IOTA_IDENTITY_PKG_ID", id.clone());
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
  write!(&mut file, "{active_address};{active_address}")?;

  Ok(package_id)
}

pub async fn get_key_data() -> Result<(Storage<JwkMemStore, KeyIdMemstore>, KeyId, Jwk, Vec<u8>), anyhow::Error> {
  let storage = Storage::<JwkMemStore, KeyIdMemstore>::new(JwkMemStore::new(), KeyIdMemstore::new());
  let generate = storage
    .key_storage()
    .generate(KeyType::new("Ed25519"), JwsAlgorithm::EdDSA)
    .await?;
  let public_key_jwk = generate.jwk.to_public().expect("public components should be derivable");
  let public_key_bytes = get_public_key_bytes(&public_key_jwk)?;
  // let sender_address = convert_to_address(&public_key_bytes)?;

  Ok((storage, generate.key_id, public_key_jwk, public_key_bytes))
}

fn get_public_key_bytes(sender_public_jwk: &Jwk) -> Result<Vec<u8>, anyhow::Error> {
  let public_key_base_64 = &sender_public_jwk
    .try_okp_params()
    .map_err(|err| anyhow!("key not of type `Okp`; {err}"))?
    .x;

  identity_jose::jwu::decode_b64(public_key_base_64).map_err(|err| anyhow!("could not decode base64 public key; {err}"))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GasObjectHelper {
  nanos_balance: u64,
}

async fn get_balance(address: IotaAddress) -> anyhow::Result<u64> {
  let output = Command::new("iota")
    .arg("client")
    .arg("gas")
    .arg("--json")
    .arg(address.to_string())
    .output()
    .await?;

  if !output.status.success() {
    let error_msg = String::from_utf8(output.stderr)?;
    anyhow::bail!("failed to get balance: {error_msg}");
  }

  let balance = serde_json::from_slice::<Vec<GasObjectHelper>>(&output.stdout)?
    .into_iter()
    .map(|gas_info| gas_info.nanos_balance)
    .sum();

  Ok(balance)
}

#[derive(Clone)]
pub struct TestClient {
  client: Arc<IdentityClient<KeytoolSigner>>,
  storage: Arc<MemStorage>,
}

impl Deref for TestClient {
  type Target = IdentityClient<KeytoolSigner>;
  fn deref(&self) -> &Self::Target {
    &self.client
  }
}

impl TestClient {
  pub async fn new() -> anyhow::Result<Self> {
    let active_address = get_active_address().await?;
    Self::new_from_address(active_address).await
  }

  pub async fn new_from_address(address: IotaAddress) -> anyhow::Result<Self> {
    let api_endpoint = std::env::var("API_ENDPOINT").unwrap_or_else(|_| IOTA_LOCAL_NETWORK_URL.to_string());
    let client = IotaClientBuilder::default().build(&api_endpoint).await?;
    let package_id = PACKAGE_ID.get_or_try_init(|| init(&client)).await.copied()?;

    let balance = get_balance(address).await?;
    if balance < TEST_GAS_BUDGET {
      request_funds(&address).await?;
    }

    let storage = Arc::new(Storage::new(JwkMemStore::new(), KeyIdMemstore::new()));
    let signer = KeytoolSigner::builder().build()?;
    let client = IdentityClient::from_iota_client(client, package_id)
      .await?
      .set_signer(signer)
      .await?;

    Ok(TestClient {
      client: Arc::new(client),
      storage,
    })
  }

  pub async fn new_with_key_type(key_type: SignatureScheme) -> anyhow::Result<Self> {
    let address = make_address(key_type).await?;
    Self::new_from_address(address).await
  }
  // Sets the current address to the address controller by this client.
  async fn switch_address(&self) -> anyhow::Result<()> {
    let output = Command::new("iota")
      .arg("client")
      .arg("switch")
      .arg("--address")
      .arg(self.client.sender_address().to_string())
      .output()
      .await?;

    if !output.status.success() {
      anyhow::bail!(
        "Failed to switch address: {}",
        std::str::from_utf8(&output.stderr).unwrap()
      );
    }

    Ok(())
  }

  pub fn package_id(&self) -> ObjectID {
    self.client.package_id()
  }

  pub fn signer(&self) -> &KeytoolSigner {
    self.client.signer()
  }

  pub async fn store_key_id_for_verification_method(
    &self,
    identity_client: IdentityClient<StorageSigner<'_, JwkMemStore, KeyIdMemstore>>,
    did: IotaDID,
  ) -> anyhow::Result<()> {
    let public_key = identity_client.signer().public_key();
    let key_id = identity_client.signer().key_id();
    let fragment = key_id.as_str();
    let method = VerificationMethod::new_from_jwk(did, public_key.await?.to_jwk()?, Some(fragment))?;
    let method_digest: MethodDigest = MethodDigest::new(&method)?;

    self
      .storage
      .key_id_storage()
      .insert_key_id(method_digest, key_id.clone())
      .await?;

    Ok(())
  }

  pub async fn new_user_client(&self) -> anyhow::Result<IdentityClient<MemSigner<'_>>> {
    let generate = self
      .storage
      .key_storage()
      .generate(KeyType::new("Ed25519"), JwsAlgorithm::EdDSA)
      .await?;
    let public_key_jwk = generate.jwk.to_public().expect("public components should be derivable");
    let signer = StorageSigner::new(&self.storage, generate.key_id, public_key_jwk);

    #[allow(deprecated)]
    let user_client = IdentityClient::new((*self.client).clone(), signer).await?;

    request_funds(&user_client.sender_address()).await?;

    Ok(user_client)
  }
}

impl CoreClientReadOnly for TestClient {
  fn package_id(&self) -> ObjectID {
    self.client.package_id()
  }

  fn network_name(&self) -> &NetworkName {
    self.client.network_name()
  }

  fn client_adapter(&self) -> &IotaClientAdapter {
    self.client.client_adapter()
  }
}

impl CoreClient<KeytoolSigner> for TestClient {
  fn signer(&self) -> &KeytoolSigner {
    self.client.signer()
  }

  fn sender_address(&self) -> IotaAddress {
    self.client.sender_address()
  }

  fn sender_public_key(&self) -> &PublicKey {
    self.client.sender_public_key()
  }
}

pub async fn get_test_coin<S>(recipient: IotaAddress, client: &IdentityClient<S>) -> anyhow::Result<ObjectID>
where
  S: Signer<IotaKeySignature> + OptionalSync,
{
  TransactionBuilder::new(GetTestCoin { recipient })
    .build_and_execute(client)
    .await
    .context("failed to get test coins")
    .map(|tx_output| tx_output.output)
}

pub async fn make_address(key_type: SignatureScheme) -> anyhow::Result<IotaAddress> {
  if !matches!(
    key_type,
    SignatureScheme::ED25519 | SignatureScheme::Secp256k1 | SignatureScheme::Secp256r1
  ) {
    anyhow::bail!("key type {key_type} is not supported");
  }

  let output = Command::new("iota")
    .arg("client")
    .arg("new-address")
    .arg("--key-scheme")
    .arg(key_type.to_string())
    .arg("--json")
    .output()
    .await?;
  let new_address = {
    let stdout = std::str::from_utf8(&output.stdout).unwrap();
    let start_of_json = stdout.find('{').ok_or_else(|| {
      let stderr = std::str::from_utf8(&output.stderr).unwrap();
      anyhow!("No json in output: '{stdout}'; {stderr}",)
    })?;
    let json_result = serde_json::from_str::<Value>(stdout[start_of_json..].trim())?;
    let address_str = json_result
      .get("address")
      .context("no address in JSON output")?
      .as_str()
      .context("address is not a JSON string")?;

    address_str.parse()?
  };

  request_funds(&new_address).await?;

  Ok(new_address)
}

struct GetTestCoin {
  recipient: IotaAddress,
}

#[async_trait]
impl Transaction for GetTestCoin {
  type Output = ObjectID;

  type Error = Error;

  async fn build_programmable_transaction<C>(&self, _client: &C) -> Result<ProgrammableTransaction, Self::Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    let mut ptb = ProgrammableTransactionBuilder::new();
    let coin = ptb.programmable_move_call(
      IOTA_FRAMEWORK_PACKAGE_ID,
      ident_str!("coin").into(),
      ident_str!("zero").into(),
      vec![TypeTag::Bool],
      vec![],
    );
    ptb.transfer_args(self.recipient, vec![coin]);
    Ok(ptb.finish())
  }

  async fn apply<C>(self, effects: &mut IotaTransactionBlockEffects, client: &C) -> Result<Self::Output, Self::Error>
  where
    C: CoreClientReadOnly + OptionalSync,
  {
    let created_objects = effects
      .created()
      .iter()
      .enumerate()
      .filter(|(_, obj)| matches!(obj.owner, Owner::AddressOwner(address) if address == self.recipient))
      .map(|(i, obj_ref)| (i, obj_ref.object_id()));

    let is_target_coin =
      |obj_info: &IotaObjectResponse| obj_info.data.as_ref().unwrap().type_.as_ref().unwrap().is_coin();

    let mut i = None;
    let mut id = None;
    for (pos, obj) in created_objects {
      let coin_info = client
        .client_adapter()
        .read_api()
        .get_object_with_options(obj, IotaObjectDataOptions::new().with_type())
        .await;
      match coin_info {
        Ok(info) if is_target_coin(&info) => {
          i = Some(pos);
          id = Some(obj);
          break;
        }
        _ => continue,
      }
    }

    if let (Some(i), Some(id)) = (i, id) {
      effects.created_mut().swap_remove(i);
      Ok(id)
    } else {
      Err(Error::TransactionUnexpectedResponse(format!(
        "transaction didn't create any coins for address {}",
        self.recipient
      )))
    }
  }
}
