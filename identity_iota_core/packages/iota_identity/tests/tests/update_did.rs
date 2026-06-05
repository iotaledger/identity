use aa_enabled_identity::identity::{Controller, TransactionProposalResult, create_identity, get_identity};
use iota_sdk::{
  crypto::ed25519::Ed25519PrivateKey,
  graphql_client::{Client, faucet::FaucetClient},
};

#[tokio::test]
async fn simple_update_did() -> anyhow::Result<()> {
  let sk = Ed25519PrivateKey::generate(rand::thread_rng());
  let pk = sk.public_key();

  let client = Client::new_localnet();
  // Fund the sender account.
  let faucet_client = FaucetClient::new_localnet();
  faucet_client
    .request_and_wait_for_finalized(pk.derive_address(), &client)
    .await?;

  let mut identity = create_identity(
    pk.derive_address(),
    b"DID".as_slice(),
    &[Controller {
      address: pk.derive_address(),
      weight: 1,
      permissions: u64::MAX,
    }],
    1,
    &sk,
    &client,
  )
  .await?;

  // Fund the identity with some tokens to be able to pay for transactions.
  faucet_client
    .request_and_wait_for_finalized(*identity.id.as_address(), &client)
    .await?;

  identity
    .update_did_document(b"new_did_document".as_slice(), &sk, &client)
    .await?;
  assert_eq!(
    identity.document_metadata.document.as_slice(),
    b"new_did_document".as_slice()
  );

  Ok(())
}

#[tokio::test]
async fn update_did_multiple_controllers() -> anyhow::Result<()> {
  let controller_a_sk = Ed25519PrivateKey::generate(rand::thread_rng());
  let controller_a = controller_a_sk.public_key().derive_address();
  let controller_b_sk = Ed25519PrivateKey::generate(rand::thread_rng());
  let controller_b = controller_b_sk.public_key().derive_address();

  let client = Client::new_localnet();
  // Fund the sender account.
  let faucet_client = FaucetClient::new_localnet();
  faucet_client
    .request_and_wait_for_finalized(controller_a_sk.public_key().derive_address(), &client)
    .await?;

  let mut identity = create_identity(
    controller_a,
    b"DID".as_slice(),
    &[
      Controller {
        address: controller_a,
        weight: 1,
        permissions: u64::MAX,
      },
      Controller {
        address: controller_b,
        weight: 1,
        permissions: u64::MAX,
      },
    ],
    2,
    &controller_a_sk,
    &client,
  )
  .await?;

  faucet_client
    .request_and_wait_for_finalized(*identity.id.as_address(), &client)
    .await?;

  let TransactionProposalResult::Pending(tx) = identity
    .update_did_document(b"new_did_document", &controller_a_sk, &client)
    .await?
  else {
    unreachable!("controller_a alone cannot execute a tx directly");
  };

  let effects = identity.execute_tx(tx, &controller_b_sk, &client).await?;
  assert!(effects.as_v1().status.is_success());

  identity = get_identity(&client, identity.id).await?;
  assert_eq!(
    identity.document_metadata.document.as_slice(),
    b"new_did_document".as_slice()
  );

  Ok(())
}

#[tokio::test]
async fn cannot_update_did_without_permission_to_do_so() -> anyhow::Result<()> {
  let sk = Ed25519PrivateKey::generate(rand::thread_rng());
  let pk = sk.public_key();

  let client = Client::new_localnet();
  // Fund the sender account.
  let faucet_client = FaucetClient::new_localnet();
  faucet_client
    .request_and_wait_for_finalized(pk.derive_address(), &client)
    .await?;

  let mut identity = create_identity(
    pk.derive_address(),
    b"DID".as_slice(),
    &[Controller {
      address: pk.derive_address(),
      weight: 1,
      permissions: u64::MAX & !(1 << 63 | 1 << 3), // All permissions but ADMIN and CAN_UPDATE_DID.
    }],
    1,
    &sk,
    &client,
  )
  .await?;

  // Fund the identity with some tokens to be able to pay for transactions.
  faucet_client
    .request_and_wait_for_finalized(*identity.id.as_address(), &client)
    .await?;

  let err = identity
    .update_did_document(b"new_did_document".as_slice(), &sk, &client)
    .await
    .unwrap_err();

  assert!(format!("{err:?}").contains("assert_permissions"));

  Ok(())
}
