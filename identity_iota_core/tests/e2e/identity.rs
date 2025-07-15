// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
use crate::common;
use crate::common::get_funded_test_client;
use crate::common::get_key_data;
use crate::common::TestClient;
use crate::common::TEST_COIN_TYPE;
use crate::common::TEST_GAS_BUDGET;
use identity_iota_core::rebased::client::get_object_id_from_did;
use identity_iota_core::rebased::migration::has_previous_version;
use identity_iota_core::rebased::migration::ControllerToken;
use identity_iota_core::rebased::migration::DelegationToken;
use identity_iota_core::rebased::migration::Identity;
use identity_iota_core::rebased::proposals::ProposalResult;
use identity_iota_core::IotaDID;
use identity_iota_core::IotaDocument;
use identity_jose::jwk::ToJwk as _;
use identity_verification::MethodScope;
use identity_verification::VerificationMethod;
use iota_sdk::rpc_types::IotaObjectData;
use iota_sdk::rpc_types::IotaTransactionBlockEffectsAPI;
use iota_sdk::types::base_types::ObjectID;
use iota_sdk::types::base_types::SequenceNumber;
use iota_sdk::types::object::Owner;
use iota_sdk::types::transaction::ObjectArg;
use iota_sdk::types::TypeTag;
use iota_sdk::types::IOTA_FRAMEWORK_PACKAGE_ID;
use move_core_types::ident_str;
use product_common::core_client::CoreClient;
use product_common::core_client::CoreClientReadOnly;
use secret_storage::Signer as _;

#[tokio::test]
async fn identity_deactivation_works() -> anyhow::Result<()> {
  let test_client = get_funded_test_client().await?;
  let identity_client = test_client.new_user_client().await?;

  let mut identity = identity_client
    .create_identity(IotaDocument::new(identity_client.network()))
    .finish()
    .build_and_execute(&identity_client)
    .await?
    .output;

  let controller_token = identity
    .get_controller_token(&identity_client)
    .await?
    .expect("this address is a controller");

  identity
    .deactivate_did(&controller_token)
    .finish(&identity_client)
    .await?
    .build_and_execute(&identity_client)
    .await?;

  assert!(identity.did_document().metadata.deactivated == Some(true));

  Ok(())
}

#[tokio::test]
async fn updating_onchain_identity_did_doc_with_single_controller_works() -> anyhow::Result<()> {
  let test_client = get_funded_test_client().await?;
  let identity_client = test_client.new_user_client().await?;

  let mut newly_created_identity = identity_client
    .create_identity(IotaDocument::new(identity_client.network()))
    .finish()
    .with_gas_budget(TEST_GAS_BUDGET)
    .build_and_execute(&identity_client)
    .await?
    .output;

  let updated_did_doc = {
    let did = IotaDID::parse(format!("did:iota:{}", newly_created_identity.id()))?;
    let mut doc = IotaDocument::new_with_id(did.clone());
    doc.insert_method(
      VerificationMethod::new_from_jwk(
        did,
        identity_client.signer().public_key().await?.to_jwk()?,
        Some(identity_client.signer().key_id().as_str()),
      )?,
      MethodScope::VerificationMethod,
    )?;
    doc
  };

  let controller_token = newly_created_identity
    .get_controller_token(&identity_client)
    .await?
    .expect("this address is a controller");

  newly_created_identity
    .update_did_document(updated_did_doc, &controller_token)
    .finish(&identity_client)
    .await?
    .build_and_execute(&identity_client)
    .await?;

  Ok(())
}

#[tokio::test]
async fn approving_proposal_works() -> anyhow::Result<()> {
  let test_client = get_funded_test_client().await?;
  let alice_client = test_client.new_user_client().await?;
  let bob_client = test_client.new_user_client().await?;

  let mut identity = alice_client
    .create_identity(IotaDocument::new(alice_client.network()))
    .controller(alice_client.sender_address(), 1)
    .controller(bob_client.sender_address(), 1)
    .threshold(2)
    .finish()
    .build_and_execute(&alice_client)
    .await?
    .output;
  let did_doc = {
    let did = IotaDID::parse(format!("did:iota:{}", identity.id()))?;
    let mut doc = IotaDocument::new_with_id(did.clone());
    doc.insert_method(
      VerificationMethod::new_from_jwk(
        did,
        alice_client.signer().public_key().await?.to_jwk()?,
        Some(alice_client.signer().key_id().as_str()),
      )?,
      MethodScope::VerificationMethod,
    )?;
    doc
  };

  let alice_token = identity
    .get_controller_token(&alice_client)
    .await?
    .expect("alice is a controller");
  let ProposalResult::Pending(mut proposal) = identity
    .update_did_document(did_doc, &alice_token)
    .finish(&alice_client)
    .await?
    .build_and_execute(&alice_client)
    .await?
    .output
  else {
    anyhow::bail!("the proposal is executed");
  };
  let bob_token = identity
    .get_controller_token(&bob_client)
    .await?
    .expect("bob is a controller");
  proposal
    .approve(&identity, &bob_token)?
    .build_and_execute(&bob_client)
    .await?;

  assert_eq!(proposal.votes(), 2);

  Ok(())
}

#[tokio::test]
async fn adding_controller_works() -> anyhow::Result<()> {
  let test_client = get_funded_test_client().await?;
  let alice_client = test_client.new_user_client().await?;
  let bob_client = test_client.new_user_client().await?;

  let mut identity = alice_client
    .create_identity(IotaDocument::new(alice_client.network()))
    .finish()
    .build_and_execute(&alice_client)
    .await?
    .output;

  let alice_token = identity
    .get_controller_token(&alice_client)
    .await?
    .expect("alice is a controller");
  // Alice proposes to add Bob as a controller. Since Alice has enough voting power the proposal
  // is executed directly after creation.
  identity
    .update_config(&alice_token)
    .add_controller(bob_client.sender_address(), 1)
    .finish(&alice_client)
    .await?
    .build_and_execute(&alice_client)
    .await?;

  let _bob_token = identity
    .get_controller_token(&bob_client)
    .await?
    .expect("bob is a controller");

  Ok(())
}

#[tokio::test]
async fn can_get_historical_identity_data() -> anyhow::Result<()> {
  let test_client = get_funded_test_client().await?;
  let identity_client = test_client.new_user_client().await?;

  let mut newly_created_identity = identity_client
    .create_identity(IotaDocument::new(identity_client.network()))
    .finish()
    .with_gas_budget(TEST_GAS_BUDGET)
    .build_and_execute(&identity_client)
    .await?
    .output;

  let did = IotaDID::parse(format!("did:iota:{}", newly_created_identity.id()))?;
  let updated_did_doc = {
    let mut doc = IotaDocument::new_with_id(did.clone());
    let (_, key_id, public_key_jwk, _) = get_key_data().await?;
    doc.insert_method(
      VerificationMethod::new_from_jwk(did.clone(), public_key_jwk, Some(key_id.as_str()))?,
      MethodScope::VerificationMethod,
    )?;
    doc
  };

  let token = newly_created_identity
    .get_controller_token(&identity_client)
    .await?
    .expect("is a controller");
  newly_created_identity
    .update_did_document(updated_did_doc, &token)
    .finish(&identity_client)
    .await?
    .with_gas_budget(TEST_GAS_BUDGET)
    .build_and_execute(&identity_client)
    .await?;

  let Identity::FullFledged(updated_identity) = identity_client.get_identity(get_object_id_from_did(&did)?).await?
  else {
    anyhow::bail!("resolved identity should be an onchain identity");
  };

  let history = updated_identity.get_history(&identity_client, None, None).await?;

  // test check for previous version
  let has_previous_version_responses: Vec<bool> = history
    .iter()
    .map(has_previous_version)
    .collect::<Result<Vec<bool>, identity_iota_core::rebased::Error>>()?;
  assert_eq!(has_previous_version_responses, vec![true, false]);

  let versions: Vec<SequenceNumber> = history.iter().map(|elem| elem.version).collect();
  let version_numbers: Vec<usize> = versions.iter().map(|v| (*v).into()).collect();

  // Check that we have 2 versions (original and updated)
  assert_eq!(version_numbers.len(), 2);
  // Check that versions are in descending order (newest to oldest)
  assert!(
    version_numbers[0] > version_numbers[1],
    "versions should be in descending order"
  );

  // paging:
  //   you can either loop until no result is returned
  let mut result_index = 0;
  let mut current_item: Option<&IotaObjectData> = None;
  let mut history: Vec<IotaObjectData>;
  loop {
    history = updated_identity
      .get_history(&identity_client, current_item, Some(1))
      .await?;
    if history.is_empty() {
      break;
    }
    current_item = history.first();
    assert_eq!(current_item.unwrap().version, *versions.get(result_index).unwrap());
    result_index += 1;
  }

  //   or check before fetching next page
  let mut result_index = 0;
  let mut current_item: Option<&IotaObjectData> = None;
  let mut history: Vec<IotaObjectData>;
  loop {
    history = updated_identity
      .get_history(&identity_client, current_item, Some(1))
      .await?;

    current_item = history.first();
    assert_eq!(current_item.unwrap().version, *versions.get(result_index).unwrap());
    result_index += 1;

    if !has_previous_version(current_item.unwrap())? {
      break;
    }
  }

  Ok(())
}

#[tokio::test]
async fn send_proposal_works() -> anyhow::Result<()> {
  let test_client = get_funded_test_client().await?;
  let identity_client = test_client.new_user_client().await?;

  let mut identity = identity_client
    .create_identity(IotaDocument::new(identity_client.network()))
    .finish()
    .with_gas_budget(TEST_GAS_BUDGET)
    .build_and_execute(&identity_client)
    .await?
    .output;
  let identity_address = identity.id().into();
  let token = identity
    .get_controller_token(&identity_client)
    .await?
    .expect("is a controller");

  // Let's give the identity 2 coins in order to have something to move.
  let coin1 = common::get_test_coin(identity_address, &identity_client).await?;
  let coin2 = common::get_test_coin(identity_address, &identity_client).await?;

  // Let's propose the send of those two coins to the identity_client's address.
  let ProposalResult::Executed(_) = identity
    .send_assets(&token)
    .object(coin1, identity_client.sender_address())
    .object(coin2, identity_client.sender_address())
    .finish(&identity_client)
    .await?
    .build_and_execute(&identity_client)
    .await?
    .output
  else {
    panic!("the controller has enough voting power and the proposal should have been executed");
  };

  // Assert that identity_client's address now owns those coins.
  identity_client
    .find_owned_ref(TEST_COIN_TYPE.clone(), |obj| obj.object_id == coin1)
    .await?
    .expect("coin1 was transfered to this address");

  identity_client
    .find_owned_ref(TEST_COIN_TYPE.clone(), |obj| obj.object_id == coin2)
    .await?
    .expect("coin2 was transfered to this address");

  Ok(())
}

#[tokio::test]
async fn borrow_proposal_works() -> anyhow::Result<()> {
  let test_client = get_funded_test_client().await?;
  let identity_client = test_client.new_user_client().await?;

  let mut identity = identity_client
    .create_identity(IotaDocument::new(identity_client.network()))
    .finish()
    .build_and_execute(&identity_client)
    .await?
    .output;
  let identity_address = identity.id().into();

  let token = identity
    .get_controller_token(&identity_client)
    .await?
    .expect("is a controller");

  let coin1 = common::get_test_coin(identity_address, &identity_client).await?;
  let coin2 = common::get_test_coin(identity_address, &identity_client).await?;

  // Let's propose the borrow of those two coins to the identity_client's address.
  let ProposalResult::Executed(_) = identity
    .borrow_assets(&token)
    .borrow(coin1)
    .borrow(coin2)
    .with_intent(move |ptb, objs| {
      ptb.programmable_move_call(
        IOTA_FRAMEWORK_PACKAGE_ID,
        ident_str!("coin").into(),
        ident_str!("value").into(),
        vec![TypeTag::Bool],
        vec![objs.get(&coin1).expect("coin1 data is borrowed").0],
      );
    })
    .finish(&identity_client)
    .await?
    .build_and_execute(&identity_client)
    .await?
    .output
  else {
    panic!("controller has enough voting power and proposal should have been executed");
  };

  Ok(())
}

#[tokio::test]
async fn controller_execution_works() -> anyhow::Result<()> {
  let test_client = get_funded_test_client().await?;
  let identity_client = test_client.new_user_client().await?;

  let mut identity = identity_client
    .create_identity(IotaDocument::new(identity_client.network()))
    .finish()
    .build_and_execute(&identity_client)
    .await?
    .output;
  let identity_address = identity.id().into();

  // Create a second identity owned by the first.
  let identity2 = identity_client
    .create_identity(IotaDocument::new(identity_client.network()))
    .controller(identity_address, 1)
    .threshold(1)
    .finish()
    .build_and_execute(&identity_client)
    .await?
    .output;

  // Let's find identity's controller cap for identity2.
  let controller_cap = identity_client
    .find_owned_ref_for_address(
      identity_address,
      format!("{}::controller::ControllerCap", identity_client.package_id()).parse()?,
      |_| true,
    )
    .await?
    .expect("identity is a controller of identity2");

  let identity2_ref = identity_client.get_object_ref_by_id(identity2.id()).await?.unwrap();
  let Owner::Shared { initial_shared_version } = identity2_ref.owner else {
    panic!("identity2 is shared")
  };

  let token = identity
    .get_controller_token(&identity_client)
    .await?
    .expect("is a controller");
  // Perform an action on `identity2` as a controller of `identity`.
  let result = identity
    .controller_execution(controller_cap.0, &token)
    .with_intent(|ptb, controller_cap| {
      let identity2 = ptb
        .obj(ObjectArg::SharedObject {
          id: identity2_ref.object_id(),
          initial_shared_version,
          mutable: true,
        })
        .unwrap();

      let token_to_revoke = ptb.pure(ObjectID::ZERO).unwrap();

      ptb.programmable_move_call(
        identity_client.package_id(),
        ident_str!("identity").into(),
        ident_str!("revoke_token").into(),
        vec![],
        vec![identity2, *controller_cap, token_to_revoke],
      );
    })
    .finish(&identity_client)
    .await?
    .build_and_execute(&identity_client)
    .await?;

  assert!(result.response.status_ok().unwrap());
  assert!(matches!(result.output, ProposalResult::Executed(_)));

  Ok(())
}

#[tokio::test]
async fn identity_delete_did_works() -> anyhow::Result<()> {
  let client = get_funded_test_client().await?;
  let mut identity = client
    .create_identity(IotaDocument::new(client.network()))
    .finish()
    .build_and_execute(&client)
    .await?
    .output;
  let did = identity.did_document().id().clone();
  let controller_token = identity.get_controller_token(&client).await?.expect("is a controller");

  let ProposalResult::Executed(_) = identity
    .delete_did(&controller_token)
    .finish(&client)
    .await?
    .build_and_execute(&client)
    .await?
    .output
  else {
    anyhow::bail!("proposal should have been executed right away!");
  };

  assert!(identity.has_deleted_did());
  assert_eq!(identity.did_document().metadata.deactivated, Some(true));

  // Trying to update a deleted DID Document must fail.
  let err = identity
    .update_did_document(IotaDocument::new(client.network()), &controller_token)
    .finish(&client)
    .await;
  assert!(matches!(err, Err(identity_iota_core::rebased::Error::Identity(_))));

  // Resolution of the DID document through its DID must fail.
  let err = client.resolve_did(&did).await.unwrap_err();
  assert!(matches!(err, identity_iota_core::rebased::Error::DIDResolutionError(_)));

  Ok(())
}

#[tokio::test]
async fn controller_delegation_works() -> anyhow::Result<()> {
  let test_client = TestClient::new().await?;
  let alice_client = test_client.new_user_client().await?;
  let bob_client = test_client.new_user_client().await?;

  // We create an identity with two controllers, one can delegate the other cannot.
  let mut identity = alice_client
    .create_identity(IotaDocument::new(test_client.network()))
    .controller(alice_client.sender_address(), 1)
    .controller_with_delegation(bob_client.sender_address(), 1)
    .threshold(2)
    .finish()
    .build_and_execute(&alice_client)
    .await?
    .output;

  let alice_token = identity
    .get_controller_token(&alice_client)
    .await?
    .expect("alice is a controller");
  assert!(!alice_token.as_controller().unwrap().can_delegate());
  let bob_token = identity
    .get_controller_token(&bob_client)
    .await?
    .expect("bob is a controller");
  assert!(bob_token.as_controller().unwrap().can_delegate());

  // Bob delegates its token with full-permissions to Alice.
  let bobs_delegation_token = bob_token
    .as_controller()
    .expect("bob's token is a controller cap")
    .delegate(alice_client.sender_address(), None)
    .expect("bob can delegate its token")
    .build_and_execute(&bob_client)
    .await?
    .output;
  assert!(
    bobs_delegation_token.controller() == bob_token.id() && bobs_delegation_token.controller_of() == identity.id()
  );
  // Ensure Alice is the owner of bob's delegation token.
  let delegation_token_owner = test_client
    .get_object_ref_by_id(bobs_delegation_token.id())
    .await?
    .expect("delegation token exists")
    .owner;
  assert_eq!(
    delegation_token_owner.get_owner_address()?,
    alice_client.sender_address()
  );

  // Alice can interact with the Identity in Bob's stead.
  let bobs_delegation_token = ControllerToken::Delegate(bobs_delegation_token);
  let res = identity
    .update_did_document(IotaDocument::new(test_client.network()), &bobs_delegation_token)
    .finish(&alice_client)
    .await?
    .build_and_execute(&alice_client)
    .await?
    .response;
  assert!(res.effects.unwrap().status().is_ok());

  // Bob can revoke its delegation token anytime.
  identity
    .revoke_delegation_token(
      bob_token.as_controller().expect("bob is a controller"),
      bobs_delegation_token.as_delegate().expect("is a delegation token"),
    )?
    .build_and_execute(&bob_client)
    .await?;

  // Once revoked whoever is holding it won't be able to act in bob's stead.
  let res = identity
    .update_did_document(IotaDocument::new(test_client.network()), &bobs_delegation_token)
    .finish(&alice_client)
    .await?
    .build_and_execute(&alice_client)
    .await;
  assert!(res.is_err());

  // A revoked token can be unrevoked too.
  identity
    .unrevoke_delegation_token(
      bob_token.as_controller().expect("bob is a controller"),
      bobs_delegation_token.as_delegate().expect("is a delegation token"),
    )?
    .build_and_execute(&bob_client)
    .await?;

  // Making the token valid again.
  let res = identity
    .update_did_document(IotaDocument::new(test_client.network()), &bobs_delegation_token)
    .finish(&alice_client)
    .await?
    .build_and_execute(&alice_client)
    .await?
    .output;
  assert!(matches!(res, ProposalResult::Pending(_)));

  // The owner of the token can delete it whenever.
  let bobs_delegation_token_id = bobs_delegation_token.id();
  identity
    .delete_delegation_token(bobs_delegation_token.try_delegate().unwrap())?
    .build_and_execute(&alice_client)
    .await?;

  let maybe_obj = alice_client
    .get_object_by_id::<DelegationToken>(bobs_delegation_token_id)
    .await;
  assert!(maybe_obj.is_err());

  Ok(())
}
