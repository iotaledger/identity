// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::ops::Deref;
use std::rc::Rc;

use anyhow::anyhow;
use identity_iota::iota::rebased::client::IdentityClient;
use identity_iota::iota::rebased::client::PublishDidDocument;
use product_common::core_client::CoreClient as _;
use product_common::core_client::CoreClientReadOnly as _;
use product_common::transaction::TransactionOutputInternal;

use iota_interaction_ts::bindings::WasmExecutionStatus;
use iota_interaction_ts::bindings::WasmIotaClient;
use iota_interaction_ts::bindings::WasmIotaTransactionBlockEffects;
use iota_interaction_ts::bindings::WasmOwnedObjectRef;
use iota_interaction_ts::WasmPublicKey;
use product_common::bindings::core_client::WasmManagedCoreClientReadOnly;
use product_common::bindings::transaction::WasmTransactionBuilder;
use product_common::transaction::transaction_builder::Transaction;

use identity_iota::iota::rebased::Error;
use iota_interaction_ts::bindings::WasmTransactionSigner;
use iota_interaction_ts::core_client::WasmCoreClientReadOnly;
use iota_interaction_ts::NativeTransactionBlockResponse;
use js_sys::Object;

use super::identity::WasmIdentityBuilder;
use super::IdentityContainer;
use super::WasmIdentityClientReadOnly;
use super::WasmIotaAddress;
use super::WasmObjectID;

use crate::error::Result;
use crate::error::WasmResult;
use crate::iota::IotaDocumentLock;
use crate::iota::WasmIotaDID;
use crate::iota::WasmIotaDocument;
use identity_iota::iota::IotaDocument;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(getter_with_clone, inspectable, js_name = IotaTransactionBlockResponseEssence)]
pub struct WasmIotaTransactionBlockResponseEssence {
  #[wasm_bindgen(js_name = effectsExist)]
  pub effects_exist: bool,
  pub effects: String,
  #[wasm_bindgen(js_name = effectsExecutionStatus)]
  pub effects_execution_status: Option<WasmExecutionStatus>,
  #[wasm_bindgen(js_name = effectsCreated)]
  pub effects_created: Option<Vec<WasmOwnedObjectRef>>,
}

/// A client to interact with identities on the IOTA chain.
///
/// Used for read and write operations. If you just want read capabilities,
/// you can also use {@link IdentityClientReadOnly}, which does not need an account and signing capabilities.
#[wasm_bindgen(js_name = IdentityClient)]
pub struct WasmIdentityClient(pub(crate) IdentityClient<WasmTransactionSigner>);

impl Deref for WasmIdentityClient {
  type Target = IdentityClient<WasmTransactionSigner>;
  fn deref(&self) -> &Self::Target {
    &self.0
  }
}

#[wasm_bindgen(js_class = IdentityClient)]
impl WasmIdentityClient {
  /// @deprecated Use `IdentityClient.create` instead.
  #[wasm_bindgen(constructor)]
  pub fn _new() -> Result<WasmIdentityClient> {
    Err(JsError::new("cannot build an instance of `IdentityClient` through its default sync constructor. Use `IdentityClient.create` instead.").into())
  }

  #[wasm_bindgen(js_name = create)]
  pub async fn new(client: WasmIdentityClientReadOnly, signer: WasmTransactionSigner) -> Result<WasmIdentityClient> {
    #[allow(deprecated)]
    let inner_client = IdentityClient::new(client.0, signer).await.wasm_result()?;
    Ok(WasmIdentityClient(inner_client))
  }

  #[wasm_bindgen(js_name = senderPublicKey)]
  pub fn sender_public_key(&self) -> Result<WasmPublicKey> {
    self.0.sender_public_key().try_into()
  }

  #[wasm_bindgen(js_name = senderAddress)]
  pub fn sender_address(&self) -> WasmIotaAddress {
    self.0.sender_address().to_string()
  }

  #[wasm_bindgen(js_name = network)]
  pub fn network(&self) -> String {
    self.0.network().to_string()
  }

  #[wasm_bindgen(js_name = createIdentity)]
  pub fn create_identity(&self, iota_document: &WasmIotaDocument) -> Result<WasmIdentityBuilder> {
    Ok(
      WasmIdentityBuilder::new(iota_document)
        .map_err(|err| JsError::new(&format!("failed to initialize new identity builder; {err:?}")))?,
    )
  }

  #[wasm_bindgen(js_name = getIdentity)]
  pub async fn get_identity(&self, object_id: WasmObjectID) -> Result<IdentityContainer> {
    let inner_value = self
      .0
      .get_identity(
        object_id
          .parse()
          .map_err(|e| anyhow!("failed to parse ObjectID out of string: {e}"))
          .wasm_result()?,
      )
      .await
      .unwrap();
    Ok(IdentityContainer(inner_value))
  }

  #[wasm_bindgen(js_name = packageId)]
  pub fn package_id(&self) -> String {
    self.0.package_id().to_string()
  }

  #[wasm_bindgen(js_name = packageHistory)]
  pub fn package_history(&self) -> Vec<String> {
    self
      .0
      .package_history()
      .into_iter()
      .map(|pkg_id| pkg_id.to_string())
      .collect()
  }

  #[wasm_bindgen(js_name = resolveDid)]
  pub async fn resolve_did(&self, did: &WasmIotaDID) -> Result<WasmIotaDocument> {
    let document = self.0.resolve_did(&did.0).await.map_err(JsError::from)?;
    Ok(WasmIotaDocument(Rc::new(IotaDocumentLock::new(document))))
  }

  /// Returns the list of DIDs the given address can access as a controller.
  /// # Errors
  /// @throws {QueryControlledDidsError} when the underlying RPC calls fail;
  /// @throws {Error} when the passed `address` string is not a valid IOTA address.
  #[wasm_bindgen(js_name = didsControlledBy)]
  pub async fn dids_controlled_by(&self, address: &str) -> std::result::Result<Vec<WasmIotaDID>, js_sys::Error> {
    self.read_only().dids_controlled_by(address).await
  }

  /// Returns the list of DIDs the address wrapped by this client can access as a controller.
  /// # Errors
  /// @throws {QueryControlledDidsError} when the underlying RPC calls fail;
  #[wasm_bindgen(js_name = controlledDids)]
  pub async fn controlled_dids(&self) -> std::result::Result<Vec<WasmIotaDID>, js_sys::Error> {
    self.dids_controlled_by(&self.address().to_string()).await
  }

  #[wasm_bindgen(
    js_name = publishDidDocument,
    unchecked_return_type = "TransactionBuilder<PublishDidDocument>"
  )]
  pub fn publish_did_document(
    &self,
    document: &WasmIotaDocument,
    controller: WasmIotaAddress,
  ) -> Result<WasmTransactionBuilder> {
    let js_value: JsValue = WasmPublishDidDocument::new(document, controller)?.into();
    Ok(WasmTransactionBuilder::new(js_value.unchecked_into()))
  }

  #[wasm_bindgen(js_name = publishDidDocumentUpdate)]
  pub async fn publish_did_document_update(
    &self,
    document: &WasmIotaDocument,
    gas_budget: u64,
  ) -> Result<WasmIotaDocument> {
    let doc: IotaDocument = document
      .0
      .try_read()
      .map_err(|err| JsError::new(&format!("failed to read DID document; {err:?}")))?
      .clone();
    let document = self
      .0
      .publish_did_document_update(doc, gas_budget)
      .await
      .map_err(<Error as std::convert::Into<JsError>>::into)?;

    Ok(WasmIotaDocument(Rc::new(IotaDocumentLock::new(document))))
  }

  #[wasm_bindgen(js_name = deactivateDidOutput)]
  pub async fn deactivate_did_output(&self, did: &WasmIotaDID, gas_budget: u64) -> Result<()> {
    self
      .0
      .deactivate_did_output(&did.0, gas_budget)
      .await
      .map_err(<Error as std::convert::Into<JsError>>::into)?;

    Ok(())
  }

  #[wasm_bindgen(js_name = iotaClient)]
  pub fn iota_client(&self) -> WasmIotaClient {
    (**self.0).clone().into_inner()
  }

  #[wasm_bindgen]
  pub fn signer(&self) -> WasmTransactionSigner {
    self.0.signer().clone()
  }

  #[wasm_bindgen(js_name = readOnly)]
  pub fn read_only(&self) -> WasmIdentityClientReadOnly {
    WasmIdentityClientReadOnly((*self.0).clone())
  }
}

#[wasm_bindgen(js_name = TransactionOutputInternalIotaDocument)]
pub struct WasmTransactionOutputPublishDid(pub(crate) TransactionOutputInternal<IotaDocument>);

#[wasm_bindgen(js_class = TransactionOutputInternalIotaDocument)]
impl WasmTransactionOutputPublishDid {
  #[wasm_bindgen(getter)]
  pub fn output(&self) -> WasmIotaDocument {
    self.0.output.clone().into()
  }

  #[wasm_bindgen(getter)]
  pub fn response(&self) -> NativeTransactionBlockResponse {
    self.0.response.clone_native_response()
  }
}

#[wasm_bindgen(js_name = PublishDidDocument)]
pub struct WasmPublishDidDocument(pub(crate) PublishDidDocument);

#[wasm_bindgen(js_class = PublishDidDocument)]
impl WasmPublishDidDocument {
  #[wasm_bindgen(constructor)]
  pub fn new(did_document: &WasmIotaDocument, controller: WasmIotaAddress) -> Result<Self> {
    let did_document = did_document
      .0
      .try_read()
      .map_err(|_| anyhow!("failed to access IotaDocument"))
      .wasm_result()?
      .clone();
    let controller = controller.parse().wasm_result()?;

    Ok(Self(PublishDidDocument::new(did_document, controller)))
  }

  #[wasm_bindgen(js_name = buildProgrammableTransaction)]
  pub async fn build_programmable_transaction(&self, client: &WasmCoreClientReadOnly) -> Result<Vec<u8>> {
    let managed_client = WasmManagedCoreClientReadOnly::from_wasm(client)?;
    let pt = self
      .0
      .build_programmable_transaction(&managed_client)
      .await
      .wasm_result()?;
    bcs::to_bytes(&pt).wasm_result()
  }

  #[wasm_bindgen]
  pub async fn apply(
    self,
    wasm_effects: &WasmIotaTransactionBlockEffects,
    client: &WasmCoreClientReadOnly,
  ) -> Result<WasmIotaDocument> {
    let managed_client = WasmManagedCoreClientReadOnly::from_wasm(client)?;
    let mut effects = wasm_effects.clone().into();
    let apply_result = self.0.apply(&mut effects, &managed_client).await;
    let wasm_remaining_effects = WasmIotaTransactionBlockEffects::from(&effects);
    Object::assign(wasm_effects.as_ref(), &wasm_remaining_effects);

    apply_result.wasm_result().map(WasmIotaDocument::from)
  }
}
