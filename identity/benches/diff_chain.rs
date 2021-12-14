// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity::core::Timestamp;
use identity::crypto::KeyPair;
use identity::did::CoreDIDUrl;
use identity::did::MethodBuilder;
use identity::did::MethodData;
use identity::did::MethodRef;
use identity::did::MethodType;
use identity::did::DID;
use identity::iota::DiffMessage;
use identity::iota::DocumentChain;
use identity::iota::IotaDocument;
use identity::iota::MessageId;
use identity::iota::TangleRef;
use identity_core::crypto::SignatureOptions;
use identity_iota::document::ResolvedIotaDocument;

pub fn setup_diff_chain_bench() -> (ResolvedIotaDocument, KeyPair) {
  let keypair: KeyPair = KeyPair::new_ed25519().unwrap();
  let mut document: IotaDocument = IotaDocument::new(&keypair).unwrap();

  document
    .sign_self(keypair.private(), &document.default_signing_method().unwrap().id())
    .unwrap();

  let mut resolved: ResolvedIotaDocument = ResolvedIotaDocument::from(document);
  resolved.set_message_id(MessageId::new([8; 32]));

  (resolved, keypair)
}

/// Creates a diff chain and updates it `n` times
pub fn update_diff_chain(n: usize, chain: &mut DocumentChain, keypair: &KeyPair) {
  let current_n = chain.diff().len();

  for i in current_n..(n + current_n) {
    let new: IotaDocument = {
      let mut this: IotaDocument = chain.current().clone().document;
      this.properties_mut().insert(i.to_string(), 123.into());
      this.metadata.updated = Timestamp::now_utc();
      this
    };

    let message_id = *chain.diff_message_id();
    let mut diff: DiffMessage = chain
      .current()
      .document
      .diff(
        &new,
        message_id,
        keypair.private(),
        chain.current().document.default_signing_method().unwrap().id(),
      )
      .unwrap();

    diff.set_message_id(message_id);
    assert!(chain.try_push_diff(diff).is_ok());
  }
}

/// Creates an integration chain and updates it `n` times
pub fn update_integration_chain(n: usize, chain: &mut DocumentChain, keypair: &KeyPair) {
  let current_n = chain.diff().len();

  for i in current_n..(n + current_n) {
    let mut new: ResolvedIotaDocument = chain.current().clone();

    let authentication: MethodRef = MethodBuilder::default()
      .id(CoreDIDUrl::from(
        chain.id().to_url().join(&format!("#key-{}", i)).unwrap(),
      ))
      .controller(chain.id().clone().into())
      .key_type(MethodType::Ed25519VerificationKey2018)
      .key_data(MethodData::new_multibase(keypair.public()))
      .build()
      .map(Into::into)
      .unwrap();

    unsafe {
      new.document.core_document_mut().authentication_mut().clear();
      new
        .document
        .core_document_mut()
        .authentication_mut()
        .append(authentication);
    }

    new.document.metadata.updated = Timestamp::now_utc();
    new.document.metadata.previous_message_id = *chain.integration_message_id();

    chain
      .current()
      .document
      .sign_data(
        &mut new.document,
        keypair.private(),
        chain.current().document.default_signing_method().unwrap().id(),
        SignatureOptions::default(),
      )
      .unwrap();
    chain.try_push_integration(new).unwrap();
  }
}
