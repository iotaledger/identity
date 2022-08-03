// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_core::crypto::KeyPair;
use identity_core::crypto::KeyType;
use identity_did::verification::MethodScope;
use identity_stardust::NetworkName;
use identity_stardust::StardustClientExt;
use identity_stardust::StardustDocument;
use identity_stardust::StardustVerificationMethod;

use iota_client::block::address::Address;
use iota_client::block::output::AliasOutput;
use iota_client::block::output::Output;
use iota_client::constants::SHIMMER_TESTNET_BECH32_HRP;
use iota_client::crypto::keys::bip39;
use iota_client::node_api::indexer::query_parameters::QueryParameter;
use iota_client::secret::mnemonic::MnemonicSecretManager;
use iota_client::secret::SecretManager;
use iota_client::Client;

static ENDPOINT: &str = "https://api.testnet.shimmer.network/";
static FAUCET_URL: &str = "https://faucet.testnet.shimmer.network/api/enqueue";

/// Demonstrate how to create a DID Document and publish it in a new Alias Output.
pub async fn run() -> anyhow::Result<(Client, Address, SecretManager, StardustDocument)> {
  // Create a client and an address with funds from the testnet faucet.
  let client: Client = Client::builder().with_primary_node(ENDPOINT, None)?.finish()?;
  let (address, secret_manager): (Address, SecretManager) = get_address_with_funds(&client).await?;

  // Get the BECH32 HRP identifier of the network.
  let network_name: NetworkName = client.network_name().await?;

  // Create a new document with a placeholder DID and add a verification method.
  // The placeholder will be replaced during publication, since the DID is derived from the id of the output
  // that creates the Alias Output.
  let mut document: StardustDocument = StardustDocument::new(&network_name);

  // Create a new key pair that we'll use to create a verification method.
  let keypair: KeyPair = KeyPair::new(KeyType::Ed25519)?;

  // Create a new verification method based on the previously created key pair.
  let method: StardustVerificationMethod =
    StardustVerificationMethod::new(document.id().clone(), keypair.type_(), keypair.public(), "#key-1")?;

  // Insert the method into the document.
  document.insert_method(method, MethodScope::VerificationMethod)?;

  // Construct an Alias Output containing the DID document, with `address` set as both the state controller and
  // governor.
  let alias_output: AliasOutput = client.new_did_output(address, document, None).await?;

  // Publish the output and get the published document.
  let document: StardustDocument = client.publish_did_output(&secret_manager, alias_output).await?;

  println!("Published DID document: {:#?}", document);

  Ok((client, address, secret_manager, document))
}

/// Creates a new address and SecretManager with funds from the testnet faucet.
async fn get_address_with_funds(client: &Client) -> anyhow::Result<(Address, SecretManager)> {
  let keypair = identity_core::crypto::KeyPair::new(KeyType::Ed25519)?;
  let mnemonic =
    iota_client::crypto::keys::bip39::wordlist::encode(keypair.private().as_ref(), &bip39::wordlist::ENGLISH)
      .map_err(|err| anyhow::anyhow!(format!("{err:?}")))?;

  let secret_manager = SecretManager::Mnemonic(MnemonicSecretManager::try_from_mnemonic(&mnemonic)?);

  let address = client.get_addresses(&secret_manager).with_range(0..1).get_raw().await?[0];

  request_faucet_funds(client, address).await?;

  Ok((address, secret_manager))
}

/// Requests funds from the testnet faucet for the given `address`.
async fn request_faucet_funds(client: &Client, address: Address) -> anyhow::Result<()> {
  let address_bech32 = address.to_bech32(SHIMMER_TESTNET_BECH32_HRP);

  iota_client::request_funds_from_faucet(FAUCET_URL, &address_bech32).await?;

  tokio::time::timeout(std::time::Duration::from_secs(30), async {
    loop {
      tokio::time::sleep(std::time::Duration::from_secs(5)).await;

      let balance = get_address_balance(client, &address_bech32).await?;
      if balance > 0 {
        break;
      }
    }
    Ok::<(), anyhow::Error>(())
  })
  .await??;

  Ok(())
}

/// Returns the balance of the given bech32-encoded `address`.
async fn get_address_balance(client: &Client, address: &str) -> anyhow::Result<u64> {
  let output_ids = client
    .basic_output_ids(vec![
      QueryParameter::Address(address.to_owned()),
      QueryParameter::HasExpirationCondition(false),
      QueryParameter::HasTimelockCondition(false),
      QueryParameter::HasStorageReturnCondition(false),
    ])
    .await?;

  let outputs_responses = client.get_outputs(output_ids).await?;

  let mut total_amount = 0;
  for output_response in outputs_responses {
    let output = Output::try_from(&output_response.output)?;
    total_amount += output.amount();
  }

  Ok(total_amount)
}

#[allow(dead_code)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
  run().await.map(|_| ())
}
