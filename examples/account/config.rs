// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! cargo run --example account_config

use identity::account::Account;
use identity::account::AccountBuilder;
use identity::account::AccountStorage;
use identity::account::AutoSave;
use identity::account::IdentitySetup;
use identity::account::Result;
use identity::iota::ExplorerUrl;
use identity::iota::IotaDID;
use identity::iota::Network;

#[tokio::main]
async fn main() -> Result<()> {
  pretty_env_logger::init();

  // Set-up for a private Tangle
  // You can use https://github.com/iotaledger/one-click-tangle for a local setup.
  // The `network_name` needs to match the id of the network or a part of it.
  // As an example we are treating the devnet as a private tangle, so we use `dev`.
  // When running the local setup, we can use `tangle` since the id of the one-click
  // private tangle is `private-tangle`, but we can only use 6 characters.
  // Keep in mind, there are easier ways to change to devnet via `Network::Devnet`
  let network_name = "dev";
  let network = Network::try_from_name(network_name)?;

  // If you deployed an explorer locally this would usually be `http://127.0.0.1:8082`
  let explorer = ExplorerUrl::parse("https://explorer.iota.org/devnet")?;

  // In a locally running one-click tangle, this would often be `http://127.0.0.1:14265`
  let private_node_url = "https://api.lb-0.h.chrysalis-devnet.iota.cafe";

  // Create a new Account with explicit configuration
  let mut builder: AccountBuilder = Account::builder()
    .autosave(AutoSave::Never) // never auto-save. rely on the drop save
    .autosave(AutoSave::Every) // save immediately after every action
    .autosave(AutoSave::Batch(10)) // save after every 10 actions
    .autopublish(true) // publish to the tangle automatically on every update
    .milestone(4) // save a snapshot every 4 actions
    .storage(AccountStorage::Memory) // use the default in-memory storage
    // configure a mainnet Tangle client with node and permanode
    .client(Network::Mainnet, |builder| {
      builder
        // Manipulate this in order to manually appoint nodes
        .node("https://chrysalis-nodes.iota.org")
        .unwrap() // unwrap is safe, we provided a valid node URL
        // Set a permanode from the same network (Important)
        .permanode("https://chrysalis-chronicle.iota.org/api/mainnet/", None, None)
        .unwrap() // unwrap is safe, we provided a valid permanode URL
    })
    // Configure a client for the private network, here `dev`
    // Also set the URL that points to the REST API of the node
    .client(network.clone(), |builder| {
      // unwrap is safe, we provided a valid node URL
      builder.node(private_node_url).unwrap()
    });

  // Create an identity specifically on the devnet by passing `network_name`
  // The same applies if we wanted to create an identity on a private tangle
  let identity_setup: IdentitySetup = IdentitySetup::new().network(network_name)?;

  let identity: Account = match builder.create_identity(identity_setup).await {
    Ok(identity) => identity,
    Err(err) => {
      eprintln!("[Example] Error: {:?}", err);
      eprintln!("[Example] Is your Tangle node listening on {}?", private_node_url);
      return Ok(());
    }
  };

  // Prints the Identity Resolver Explorer URL.
  // The entire history can be observed on this page by clicking "Loading History".
  let iota_did: &IotaDID = identity.did();
  println!(
    "[Example] Explore the DID Document = {}",
    explorer.resolver_url(iota_did)?
  );

  Ok(())
}
