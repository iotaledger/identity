// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use examples::get_funded_client;
use examples::get_memstorage;
use identity_iota::iota::rebased::migration::get_identity;
use identity_iota::iota::IotaDocument;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  // Create a new client with enough funds.
  let storage = get_memstorage()?;
  let identity_client = get_funded_client(&storage).await?;

  // Create a base identity.
  let mut identity = identity_client
    .create_identity(IotaDocument::new(identity_client.network()))
    .finish()
    .build_and_execute(&identity_client)
    .await?
    .output;

  println!("Created Identity `{}`", identity.did_document().id());

  // Create a sub-Identity owned by the previously created Identity.
  let mut sub_identity = identity_client
    .create_identity(IotaDocument::new(identity_client.network()))
    .controller(identity.id().into(), 1)
    .finish()
    .build_and_execute(&identity_client)
    .await?
    .output;

  println!(
    "Created Identity `{}` owned by Identity `{}`",
    sub_identity.did_document().id(),
    identity.did_document().id()
  );

  // As a controller of `identity` we perform an action on `sub_identity` through `identity`.
  let identity_token = identity
    .get_controller_token(&identity_client)
    .await?
    .expect("current address is a controller of identity");
  let client_ref = &identity_client;
  identity
    .access_sub_identity(&mut sub_identity, &identity_token)
    .to_perform(|sub_identity, sub_identity_token| async move {
      sub_identity
        .deactivate_did(&sub_identity_token)
        .finish(client_ref)
        .await
    })
    .finish(&identity_client)
    .await?
    .build_and_execute(&identity_client)
    .await?;

  assert!(sub_identity.did_document().metadata.deactivated == Some(true));
  // Local `sub_identity`` reflects its on-chain Identity object.
  let synced_sub_identity = get_identity(&identity_client, sub_identity.id()).await?.unwrap();
  assert_eq!(sub_identity.did_document(), synced_sub_identity.did_document());

  println!(
    "Successfully deactivated Identity `{}`",
    sub_identity.did_document().id()
  );

  Ok(())
}
