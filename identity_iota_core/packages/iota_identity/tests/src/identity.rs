use std::collections::HashSet;

use super::{FromMoveViewCallResult, init};
use anyhow::{Context as _, anyhow};
use iota_sdk::{
  crypto::{Signer, ed25519::Ed25519PrivateKey},
  graphql_client::{Client, WaitForTx},
  transaction_builder::{MoveAuthenticatorBuilder, Shared, SharedMut, TransactionBuilder, TransactionSigner},
  types::{Address, Ed25519Signature, ObjectId, PublicKeyExt as _, Transaction, TransactionEffects, TypeTag},
};
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct Identity {
  pub id: ObjectId,
  pub document_metadata: DidDocumentMetadata,
  pub config: IdentityConfig,
  pub legacy_id: Option<ObjectId>,
}

impl Identity {
  pub async fn update_did_document(
    &mut self,
    did_document: &[u8],
    sk: &Ed25519PrivateKey,
    client: &Client,
  ) -> anyhow::Result<TransactionProposalResult<()>> {
    let invoking_controller = self.invoking_controller(sk).context("not a controller")?;
    let update_did_tx = self.prepare_update_did_document_tx(did_document, client).await?;

    if invoking_controller.weight >= self.config.threshold {
      let effects = self.execute_tx(update_did_tx, sk, client).await?;
      if effects.as_v1().status.is_success() {
        *self = get_identity(client, self.id).await?;
      } else {
        anyhow::bail!("Failed to update DID: {:?}", effects.as_v1().status);
      }

      Ok(TransactionProposalResult::Executed(()))
    } else {
      let pending_tx = self.propose_tx(update_did_tx, sk, client).await?;
      Ok(TransactionProposalResult::Pending(pending_tx))
    }
  }

  pub async fn prepare_update_did_document_tx(
    &self,
    did_document: &[u8],
    client: &Client,
  ) -> anyhow::Result<Transaction> {
    let config = init();
    let update_did_tx = {
      let mut tx_builder = TransactionBuilder::new(*self.id.as_address()).with_client(client.clone());
      tx_builder
        .move_call(config.identity_pkg_id, "identity_v2", "update_did_document")
        .arguments((
          SharedMut(self.id),
          did_document,
          Shared(ObjectId::from_address(Address::CLOCK)),
        ));
      tx_builder.finish().await?
    };

    Ok(update_did_tx)
  }

  pub async fn execute_tx(
    &self,
    tx: Transaction,
    sk: impl Into<Option<&Ed25519PrivateKey>>,
    client: &Client,
  ) -> anyhow::Result<TransactionEffects> {
    let call_args = if let Some(sk) = sk.into() {
      let controller_sig: Ed25519Signature = Signer::sign(sk, tx.digest().as_bytes());
      let controller_pk = sk.public_key().to_flagged_bytes();

      (Some(controller_sig.as_bytes().to_vec()), Some(controller_pk))
    } else {
      (None, None)
    };

    let authenticator_params = MoveAuthenticatorBuilder::new(self.id)
      .call_args(call_args)
      .finish(&client)
      .await?;

    Ok(
      TransactionBuilder::try_from(tx)?
        .with_client(client.clone())
        .execute(&authenticator_params, WaitForTx::Finalized)
        .await?,
    )
  }

  async fn propose_tx(&self, tx: Transaction, sk: &Ed25519PrivateKey, client: &Client) -> anyhow::Result<Transaction> {
    let config = init();
    // Add a command for the removal of this proposal once it's executed.
    let mut tx_builder = TransactionBuilder::try_from(tx)?.with_client(client.clone());
    tx_builder
      .move_call(config.identity_pkg_id, "identity_v2", "remove_tx")
      .arguments([SharedMut(self.id)]);
    let tx = tx_builder.finish().await?;

    let mut tx_builder = TransactionBuilder::new(sk.public_key().derive_address()).with_client(client.clone());
    tx_builder
      .move_call(config.identity_pkg_id, "identity_v2", "propose_tx")
      .arguments((SharedMut(self.id), tx.digest()));
    let effects = tx_builder.execute(sk, WaitForTx::Finalized).await?;

    if effects.as_v1().status.is_success() {
      Ok(tx)
    } else {
      anyhow::bail!("Failed to update DID: {:?}", effects.as_v1().status);
    }
  }

  pub async fn propose_tx_to_sub_identity(
    &self,
    sub_identity: &Self,
    tx: Transaction,
    sk: &Ed25519PrivateKey,
    client: &Client,
  ) -> anyhow::Result<(TransactionProposalResult<()>, Transaction)> {
    let config = init();
    let mut tx_builder = TransactionBuilder::try_from(tx)?.with_client(client.clone());
    tx_builder
      .move_call(config.identity_pkg_id, "identity_v2", "remove_tx_execution_receipt")
      .arguments([SharedMut(sub_identity.id)]);
    let tx = tx_builder.finish().await?;

    let mut tx_builder = TransactionBuilder::new(*self.id.as_address()).with_client(client.clone());
    tx_builder
      .move_call(config.identity_pkg_id, "identity_v2", "add_tx_execution_receipt")
      .arguments((Shared(self.id), SharedMut(sub_identity.id), tx.digest()));
    let make_receipt_tx = tx_builder.finish().await?;
    let invoking_controller = self.invoking_controller(sk).context("not a controller")?;
    if invoking_controller.weight >= self.config.threshold {
      let effects = self.execute_tx(make_receipt_tx, sk, client).await?;
      if effects.as_v1().status.is_success() {
        Ok((TransactionProposalResult::Executed(()), tx))
      } else {
        anyhow::bail!("Failed to create tx execution receipt: {:?}", effects.as_v1().status);
      }
    } else {
      Ok((TransactionProposalResult::Pending(make_receipt_tx), tx))
    }
  }

  fn invoking_controller(&self, sk: &Ed25519PrivateKey) -> Option<&Controller> {
    self
      .config
      .controllers
      .iter()
      .find(|c| c.address == sk.public_key().derive_address())
  }
}

pub async fn get_identity(client: &Client, id: ObjectId) -> anyhow::Result<Identity> {
  let config = init();
  let res = client
    .move_view_call(
      format!("{}::identity_v2::borrow_parts_v1", config.identity_pkg_id),
      None,
      [&id],
    )
    .await?;

  let Some(mut results) = res.results else {
    return Err(anyhow!(res.error.unwrap()).context("move view call failed"));
  };

  let document_metadata =
    DidDocumentMetadata::from_move_view_call_result(results.first_mut().unwrap().get_mut("fields").unwrap())?;
  let config = IdentityConfig::from_move_view_call_result(results.get_mut(1).unwrap().get_mut("fields").unwrap())?;

  Ok(Identity {
    id,
    document_metadata,
    config,
    legacy_id: None,
  })
}

pub async fn create_identity(
  sender_address: Address,
  did_document: &[u8],
  controllers: &[Controller],
  threshold: u64,
  signer: &impl TransactionSigner,
  client: &Client,
) -> anyhow::Result<Identity> {
  let config = init();
  let mut tx_builder = TransactionBuilder::new(sender_address).with_client(client.clone());
  let auth_fn = tx_builder
    .move_call(
      Address::FRAMEWORK,
      "authenticator_function",
      "create_auth_function_ref_v1",
    )
    .arguments((config.package_metadata_id, "identity_v2", "authenticate_v1"))
    .type_tags([format!("{}::identity_v2::IdentityV2", config.identity_pkg_id).parse::<TypeTag>()?])
    .arg();
  let addresses = controllers.iter().map(|c| c.address).collect::<Vec<_>>();
  let weights = controllers.iter().map(|c| c.weight).collect::<Vec<_>>();
  let permissions = controllers.iter().map(|c| c.permissions).collect::<Vec<_>>();

  tx_builder
    .move_call(config.identity_pkg_id, "identity_v2", "new_with_config")
    .arguments((
      did_document,
      addresses,
      weights,
      permissions,
      threshold,
      auth_fn,
      Shared(ObjectId::from_address(Address::CLOCK)),
    ));
  let effects = tx_builder.execute(signer, WaitForTx::Finalized).await?;

  if effects.as_v1().status.is_failure() {
    anyhow::bail!("Failed to create identity: {:?}", effects.as_v1().status);
  }

  let identity_id = effects
    .as_v1()
    .changed_objects
    .iter()
    .find(|obj| {
      obj.id_operation.is_created()
        && obj
          .output_state
          .object_owner_opt()
          .is_some_and(|owner| owner.is_shared())
    })
    .map(|obj| obj.object_id)
    .unwrap();

  get_identity(client, identity_id).await
}

#[derive(Debug, Clone)]
pub struct DidDocumentMetadata {
  pub document: Vec<u8>,
  pub created: u64,
  pub updated: u64,
  pub deleted: bool,
}

impl FromMoveViewCallResult for DidDocumentMetadata {
  fn from_move_view_call_result(result: &mut Value) -> anyhow::Result<Self> {
    let document = serde_json::from_value(result.get_mut("document").context("missing 'document' field")?.take())?;
    let created = result
      .get("created")
      .and_then(|v| v.as_str())
      .context("missing 'created' field")?
      .parse()?;
    let updated = result
      .get("updated")
      .and_then(|v| v.as_str())
      .context("missing 'updated' field")?
      .parse()?;
    let deleted = result
      .get("deleted")
      .and_then(|v| v.as_bool())
      .context("missing 'deleted' field")?;

    Ok(Self {
      document,
      created,
      updated,
      deleted,
    })
  }
}

#[derive(Debug, Clone)]
pub struct IdentityConfig {
  pub controllers: HashSet<Controller>,
  pub threshold: u64,
}

impl FromMoveViewCallResult for IdentityConfig {
  fn from_move_view_call_result(result: &mut Value) -> anyhow::Result<Self> {
    let controllers = result
      .get_mut("controllers")
      .context("missing 'controllers' field")?
      .as_array_mut()
      .context("'controllers' field is not an array")?
      .iter_mut()
      .map(|obj| obj.get_mut("fields").unwrap())
      .map(Controller::from_move_view_call_result)
      .collect::<anyhow::Result<HashSet<_>>>()?;

    let threshold = result
      .get("threshold")
      .and_then(|v| v.as_str())
      .context("missing 'threshold' field")?
      .parse()?;

    Ok(Self {
      controllers: controllers.into_iter().collect(),
      threshold,
    })
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Controller {
  pub address: Address,
  pub weight: u64,
  pub permissions: u64,
}

impl FromMoveViewCallResult for Controller {
  fn from_move_view_call_result(value: &mut Value) -> anyhow::Result<Self> {
    let address = value
      .get("addr")
      .and_then(|v| v.as_str())
      .context("missing 'addr' field")?
      .parse()?;
    let weight = value
      .get("weight")
      .and_then(|v| v.as_str())
      .context("missing 'weight' field")?
      .parse()?;
    let permissions = value
      .get("permissions")
      .and_then(|v| v.as_str())
      .context("missing 'permissions' field")?
      .parse()?;

    Ok(Self {
      address,
      weight,
      permissions,
    })
  }
}

#[derive(Debug)]
pub enum TransactionProposalResult<T> {
  Pending(Transaction),
  Executed(T),
}
