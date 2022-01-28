// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::pin::Pin;
use std::sync::Arc;

use futures::Future;

use identity_core::common::Timestamp;
use identity_core::common::Url;
use identity_core::crypto::SignatureOptions;
use identity_did::utils::Queryable;
use identity_did::verification::MethodScope;
use identity_iota::chain::DocumentChain;
use identity_iota::did::IotaDID;
use identity_iota::diff::DiffMessage;
use identity_iota::document::IotaDocument;
use identity_iota::tangle::Client;
use identity_iota::tangle::ClientBuilder;
use identity_iota::tangle::MessageId;
use identity_iota::tangle::MessageIdExt;
use identity_iota::tangle::Network;

use crate::account::Account;
use crate::account::AccountBuilder;
use crate::account::AccountConfig;
use crate::account::AccountSetup;
use crate::account::AccountStorage;
use crate::account::AutoSave;
use crate::account::PublishOptions;
use crate::identity::ChainState;
use crate::identity::IdentitySetup;
use crate::identity::IdentityState;
use crate::storage::MemStore;
use crate::Error;
use crate::Result;

#[tokio::test]
async fn test_account_builder() -> Result<()> {
  let mut builder: AccountBuilder = AccountBuilder::default().testmode(true);

  let account1: Account = builder.create_identity(IdentitySetup::default()).await?;

  builder = builder.autopublish(false);

  let account2: Account = builder.create_identity(IdentitySetup::default()).await?;

  assert!(account1.autopublish());
  assert!(!account2.autopublish());

  let did1 = account1.did().to_owned();
  let did2 = account2.did().to_owned();
  account2.delete_identity().await?;

  assert!(matches!(
    builder.load_identity(did2).await.unwrap_err(),
    crate::Error::IdentityNotFound
  ));

  // Relase the lease on did1.
  std::mem::drop(account1);

  assert!(builder.load_identity(did1).await.is_ok());

  Ok(())
}

#[tokio::test]
async fn test_account_did_lease() -> Result<()> {
  let mut builder: AccountBuilder = AccountBuilder::default().testmode(true);

  let did: IotaDID = {
    let account: Account = builder.create_identity(IdentitySetup::default()).await?;
    account.did().to_owned()
  }; // <-- Lease released here.

  // Lease is not in-use
  let _account = builder.load_identity(did.clone()).await.unwrap();

  // Lease is in-use
  assert!(matches!(
    builder.load_identity(did).await.unwrap_err(),
    crate::Error::IdentityInUse
  ));

  Ok(())
}

#[tokio::test]
async fn test_account_chain_state() -> Result<()> {
  let mut builder: AccountBuilder = AccountBuilder::default().testmode(true);

  let mut account: Account = builder.create_identity(IdentitySetup::default()).await?;

  let last_int_id = *account.chain_state().last_integration_message_id();

  assert_ne!(last_int_id, MessageId::null());

  // Assert that the last_diff_message_id is still null.
  assert_eq!(account.chain_state().last_diff_message_id(), &MessageId::null());

  // A diff update.
  account
    .update_identity()
    .create_service()
    .fragment("my-service-1")
    .type_("MyCustomService")
    .endpoint(Url::parse("https://example.com")?)
    .apply()
    .await?;

  // A diff update does not overwrite the int message id.
  assert_eq!(&last_int_id, account.chain_state().last_integration_message_id());

  // Assert that the last_diff_message_id was set.
  assert_ne!(account.chain_state().last_diff_message_id(), &MessageId::null());

  account
    .update_identity()
    .create_method()
    .fragment("my-new-key")
    .scope(MethodScope::capability_invocation())
    .apply()
    .await?;

  // Int message id was overwritten.
  assert_ne!(&last_int_id, account.chain_state().last_integration_message_id());

  Ok(())
}

#[tokio::test]
async fn test_account_autopublish() -> Result<()> {
  // ===========================================================================
  // Create, update and "publish" an identity
  // ===========================================================================

  let config = AccountConfig::default().autopublish(false).testmode(true);
  let client = ClientBuilder::new().node_sync_disabled().build().await?;
  let account_setup = AccountSetup::new(Arc::new(MemStore::new()), Arc::new(client), config);

  let mut account = Account::create_identity(account_setup, IdentitySetup::new()).await?;

  account
    .update_identity()
    .create_service()
    .fragment("my-service")
    .type_("LinkedDomains")
    .endpoint(Url::parse("https://example.org").unwrap())
    .apply()
    .await?;

  account
    .update_identity()
    .create_service()
    .fragment("my-other-service")
    .type_("LinkedDomains")
    .endpoint(Url::parse("https://example.org").unwrap())
    .apply()
    .await?;

  assert!(account.chain_state().last_integration_message_id().is_null());
  assert!(account.chain_state().last_diff_message_id().is_null());

  account.publish().await?;

  let last_int_message_id = *account.chain_state().last_integration_message_id();

  assert!(!last_int_message_id.is_null());
  assert!(account.chain_state().last_diff_message_id().is_null());

  // ===========================================================================
  // Service assertions
  // ===========================================================================

  let doc = account.document();

  assert_eq!(doc.methods().count(), 1);
  assert_eq!(doc.service().len(), 2);

  for service in ["my-service", "my-other-service"] {
    assert!(doc.service().query(service).is_some());
  }

  // ===========================================================================
  // More updates to the identity
  // ===========================================================================

  account
    .update_identity()
    .delete_service()
    .fragment("my-service")
    .apply()
    .await?;

  account
    .update_identity()
    .delete_service()
    .fragment("my-other-service")
    .apply()
    .await?;

  account
    .update_identity()
    .create_method()
    .fragment("new-method")
    .apply()
    .await?;

  account.publish().await?;

  // No integration message was published
  assert_eq!(
    &last_int_message_id,
    account.chain_state().last_integration_message_id()
  );

  let last_diff_message_id = *account.chain_state().last_diff_message_id();
  assert!(!last_diff_message_id.is_null());

  // ===========================================================================
  // Second round of assertions
  // ===========================================================================

  let doc = account.document();

  assert_eq!(doc.service().len(), 0);
  assert_eq!(doc.methods().count(), 2);

  for method in ["sign-0", "new-method"] {
    assert!(doc.resolve_method(method).is_some());
  }

  // ===========================================================================
  // More updates to the identity
  // ===========================================================================

  account
    .update_identity()
    .create_method()
    .fragment("signing-key")
    // Forces an integration update by adding a method able to update the document.
    .scope(MethodScope::capability_invocation())
    .apply()
    .await?;

  account.publish().await?;

  // Another int update was published.
  assert_ne!(
    &last_int_message_id,
    account.chain_state().last_integration_message_id()
  );

  // Diff message id was reset.
  assert!(account.chain_state().last_diff_message_id().is_null());

  Ok(())
}

#[tokio::test]
async fn test_account_publish_options_sign_with() -> Result<()> {
  let config = AccountConfig::default().autopublish(false).testmode(true);
  let client = ClientBuilder::new().node_sync_disabled().build().await?;
  let account_config = AccountSetup::new(Arc::new(MemStore::new()), Arc::new(client), config);

  let auth_method = "auth-method";
  let signing_method = "singing-method-2";

  let mut account = Account::create_identity(account_config, IdentitySetup::new()).await?;

  account
    .update_identity()
    .create_method()
    .fragment(auth_method)
    .scope(MethodScope::authentication())
    .apply()
    .await?;

  account
    .update_identity()
    .create_method()
    .fragment(signing_method)
    .scope(MethodScope::capability_invocation())
    .apply()
    .await?;

  assert!(matches!(
    account
      .publish_with_options(PublishOptions::default().sign_with("non-existent-method"))
      .await
      .unwrap_err(),
    Error::IotaError(identity_iota::Error::InvalidDoc(identity_did::Error::MethodNotFound))
  ));

  assert!(matches!(
    account
      .publish_with_options(PublishOptions::default().sign_with(auth_method))
      .await
      .unwrap_err(),
    Error::IotaError(identity_iota::Error::InvalidDoc(identity_did::Error::MethodNotFound))
  ));

  // TODO: Once implemented, add a merkle key collection method with capability invocation relationship and test for
  // Error::IotaError(identity_iota::Error::InvalidDocumentSigningMethodType).

  assert!(account
    .publish_with_options(PublishOptions::default().sign_with(signing_method))
    .await
    .is_ok());

  Ok(())
}

#[tokio::test]
async fn test_account_publish_options_force_integration() -> Result<()> {
  let config = AccountConfig::default().autopublish(false).testmode(true);
  let client = ClientBuilder::new().node_sync_disabled().build().await?;
  let account_setup = AccountSetup::new(Arc::new(MemStore::new()), Arc::new(client), config);
  let mut account = Account::create_identity(account_setup, IdentitySetup::new()).await?;

  account.publish().await.unwrap();

  let last_int_id = *account.chain_state().last_integration_message_id();

  account
    .update_identity()
    .create_method()
    .fragment("test-auth")
    .scope(MethodScope::authentication())
    .apply()
    .await?;

  account
    .publish_with_options(PublishOptions::default().force_integration_update(true))
    .await
    .unwrap();

  // Ensure update was published on integration chain.
  assert_ne!(account.chain_state().last_integration_message_id(), &last_int_id);
  assert_eq!(account.chain_state().last_diff_message_id(), &MessageId::null());

  Ok(())
}

#[tokio::test]
async fn test_account_sync_no_changes() -> Result<()> {
  network_resilient_test(2, |n| {
    Box::pin(async move {
      let network = if n % 2 == 0 { Network::Devnet } else { Network::Mainnet };
      let mut account = create_account(network).await;

      // Case 0: Since nothing has been published to the tangle, read_document must return DID not found
      assert!(account.fetch_state().await.is_err());

      // Case 1: Tangle and account are synched
      account.publish().await.unwrap();
      let old_state: IdentityState = account.state().clone();
      let old_chain_state: ChainState = account.chain_state().clone();
      account.fetch_state().await.unwrap();
      assert_eq!(old_state.document(), account.state().document());
      assert_eq!(&old_chain_state, account.chain_state());

      // Case 2: Local state is ahead of the tangle
      account
        .update_identity()
        .create_service()
        .fragment("my-other-service")
        .type_("LinkedDomains")
        .endpoint(Url::parse("https://example.org").unwrap())
        .apply()
        .await?;
      let old_state: IdentityState = account.state().clone();
      let old_chain_state: ChainState = account.chain_state().clone();
      account.fetch_state().await.unwrap();
      assert_eq!(old_state.document(), account.state().document());
      assert_eq!(&old_chain_state, account.chain_state());
      Ok(())
    })
  })
  .await?;
  Ok(())
}

#[tokio::test]
async fn test_account_sync_integration_msg_update() -> Result<()> {
  network_resilient_test(2, |n| {
    Box::pin(async move {
      let network = if n % 2 == 0 { Network::Devnet } else { Network::Mainnet };
      let mut account = create_account(network.clone()).await;
      account.publish().await.unwrap();

      let client: Client = Client::from_network(network).await.unwrap();
      let mut new_doc: IotaDocument = account.document().clone();
      new_doc.properties_mut().insert("foo".into(), 123.into());
      new_doc.properties_mut().insert("bar".into(), 456.into());
      new_doc.metadata.previous_message_id = *account.chain_state().last_integration_message_id();
      new_doc.metadata.updated = Timestamp::now_utc();
      account
        .sign(
          IotaDocument::DEFAULT_METHOD_FRAGMENT,
          &mut new_doc,
          SignatureOptions::default(),
        )
        .await
        .unwrap();
      client.publish_document(&new_doc).await.unwrap();
      let chain: DocumentChain = client.read_document_chain(account.did()).await.unwrap();

      account.fetch_state().await.unwrap();
      assert!(account.state().document().properties().contains_key("foo"));
      assert!(account.state().document().properties().contains_key("bar"));
      assert_eq!(
        account.chain_state().last_integration_message_id(),
        chain.integration_message_id()
      );
      assert_eq!(account.chain_state().last_diff_message_id(), chain.diff_message_id());
      // Ensure state was written into storage.
      let storage_state: IdentityState = account.load_state().await?;
      assert_eq!(&storage_state, account.state());
      Ok(())
    })
  })
  .await?;
  Ok(())
}

#[tokio::test]
async fn test_account_sync_diff_msg_update() -> Result<()> {
  network_resilient_test(2, |n| {
    Box::pin(async move {
      let network = if n % 2 == 0 { Network::Devnet } else { Network::Mainnet };
      let mut account = create_account(network.clone()).await;
      account.publish().await.unwrap();

      let client: Client = Client::from_network(network).await.unwrap();
      let mut new_doc: IotaDocument = account.document().clone();
      new_doc.properties_mut().insert("foo".into(), 123.into());
      new_doc.properties_mut().insert("bar".into(), 456.into());
      new_doc.metadata.updated = Timestamp::now_utc();
      let mut diff_msg: DiffMessage = DiffMessage::new(
        account.document(),
        &new_doc,
        *account.chain_state().last_integration_message_id(),
      )
      .unwrap();
      account
        .sign(
          IotaDocument::DEFAULT_METHOD_FRAGMENT,
          &mut diff_msg,
          SignatureOptions::default(),
        )
        .await
        .unwrap();
      client
        .publish_diff(&*account.chain_state().last_integration_message_id(), &diff_msg)
        .await
        .unwrap();
      let chain: DocumentChain = client.read_document_chain(account.did()).await.unwrap();

      let old_chain_state: ChainState = account.chain_state().clone();
      account.fetch_state().await.unwrap();
      assert!(account.state().document().properties().contains_key("foo"));
      assert!(account.state().document().properties().contains_key("bar"));
      assert_eq!(
        old_chain_state.last_integration_message_id(),
        account.chain_state().last_integration_message_id()
      );
      assert_eq!(account.chain_state().last_diff_message_id(), chain.diff_message_id());
      // Ensure state was written into storage.
      let storage_state: IdentityState = account.load_state().await?;
      assert_eq!(&storage_state, account.state());
      Ok(())
    })
  })
  .await?;
  Ok(())
}

async fn create_account(network: Network) -> Account {
  Account::builder()
    .storage(AccountStorage::Stronghold(
      "./example-strong.hodl".into(),
      Some("my-password".into()),
      None,
    ))
    .autopublish(false)
    .autosave(AutoSave::Every)
    .client_builder(ClientBuilder::new().network(network.clone()))
    .create_identity(IdentitySetup::default())
    .await
    .unwrap()
}

// Repeats the test in the closure `test_runs` number of times.
// Network problems, i.e. a ClientError trigger a re-run.
// Other errors end the test immediately.
async fn network_resilient_test(
  test_runs: u32,
  f: impl Fn(u32) -> Pin<Box<dyn Future<Output = Result<()>>>>,
) -> Result<()> {
  for test_run in 0..test_runs {
    let test_attempt = f(test_run).await;

    match test_attempt {
      error @ Err(Error::IotaError(identity_iota::Error::ClientError(_))) => {
        eprintln!("test run {} errored with {:?}", test_run, error);

        if test_run == test_runs - 1 {
          return error;
        }
      }
      other => return other,
    }
  }
  Ok(())
}
