// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use async_trait::async_trait;
use identity_did::verification::MethodData;

use crate::Ed25519KeyType;
use crate::KeyAlias;
use crate::KeyStorage;
use crate::MethodContent;
use crate::MethodType1;

pub struct MethodSuite<K: KeyStorage> {
  key_storage: K,
  method_handlers: HashMap<MethodType1, Box<dyn MethodHandler<K>>>,
}

impl<K: KeyStorage> MethodSuite<K> {
  pub fn new(key_storage: K) -> Self {
    Self {
      key_storage,
      method_handlers: HashMap::new(),
    }
  }

  pub fn register<MET>(&mut self, handler: MET)
  where
    MET: MethodHandler<K> + 'static,
  {
    self.method_handlers.insert(handler.method_type(), Box::new(handler));
  }

  pub async fn create(&self, method_type: &MethodType1, method_content: MethodContent) -> (KeyAlias, MethodData) {
    match self.method_handlers.get(method_type) {
      Some(handler) => handler.create(method_content, &self.key_storage).await,
      None => todo!("return missing handler error"),
    }
  }

  #[cfg(target_family = "wasm")]
  pub fn register_unchecked(&mut self, method_type: MethodType1, handler: Box<dyn MethodHandler<K>>) {
    self.method_handlers.insert(method_type, handler);
  }
}

#[cfg(feature = "send-sync-storage")]
#[async_trait::async_trait]
pub trait MethodHandler<K: KeyStorage>: Send + Sync {
  fn method_type(&self) -> MethodType1;
  async fn create(&self, method_content: MethodContent, key_storage: &K) -> (KeyAlias, MethodData);
}

#[cfg(not(feature = "send-sync-storage"))]
#[async_trait::async_trait(?Send)]
pub trait MethodHandler<K: KeyStorage> {
  fn method_type(&self) -> MethodType1;
  async fn create(&self, method_content: MethodContent, key_storage: &K) -> (KeyAlias, MethodData);
}

pub struct Ed25519VerificationKey2018;

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl<K> MethodHandler<K> for Ed25519VerificationKey2018
where
  K: KeyStorage,
  K::KeyType: From<Ed25519KeyType> + Send,
{
  fn method_type(&self) -> MethodType1 {
    MethodType1::ED25519_VERIFICATION_KEY_2018
  }

  async fn create(&self, method_content: MethodContent, key_storage: &K) -> (KeyAlias, MethodData) {
    if let MethodContent::Generate = method_content {
      let key_type: K::KeyType = K::KeyType::from(Ed25519KeyType);
      let key_alias: KeyAlias = key_storage.generate(key_type).await.expect("TODO");

      let pubkey = key_storage.public(&key_alias).await.expect("TODO");

      let method_data: MethodData = MethodData::new_base58(pubkey.as_ref());

      (key_alias, method_data)
    } else {
      unimplemented!("{method_content:?}")
    }
  }
}
