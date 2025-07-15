// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::WasmMethodDigest;
use crate::common::PromiseString;
use crate::error::JsValueResult;
use identity_iota::storage::key_id_storage::KeyIdStorage;
use identity_iota::storage::key_id_storage::KeyIdStorageResult;
use identity_iota::storage::key_id_storage::MethodDigest;
use identity_iota::storage::key_storage::KeyId;
use js_sys::Promise;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(typescript_type = "KeyIdStorage")]
  pub type WasmKeyIdStorage;

  #[wasm_bindgen(method, js_name = insertKeyId)]
  pub fn insert_key_id(this: &WasmKeyIdStorage, method_digest: WasmMethodDigest, key_id: String) -> Promise;

  #[wasm_bindgen(method, js_name = getKeyId)]
  pub fn get_key_id(this: &WasmKeyIdStorage, method_digest: WasmMethodDigest) -> PromiseString;

  #[wasm_bindgen(method, js_name = deleteKeyId)]
  pub fn delete_key_id(this: &WasmKeyIdStorage, method_digest: WasmMethodDigest) -> Promise;
}

#[async_trait::async_trait(?Send)]
impl KeyIdStorage for WasmKeyIdStorage {
  async fn insert_key_id(&self, method_digest: MethodDigest, key_id: KeyId) -> KeyIdStorageResult<()> {
    let promise: Promise = Promise::resolve(&WasmKeyIdStorage::insert_key_id(
      self,
      WasmMethodDigest(method_digest),
      key_id.clone().into(),
    ));
    let result: JsValueResult = JsFuture::from(promise).await.into();
    result.into()
  }

  async fn get_key_id(&self, method_digest: &MethodDigest) -> KeyIdStorageResult<KeyId> {
    let promise: Promise = Promise::resolve(&WasmKeyIdStorage::get_key_id(
      self,
      WasmMethodDigest(method_digest.clone()),
    ));
    let result: JsValueResult = JsFuture::from(promise).await.into();
    result.into()
  }

  async fn delete_key_id(&self, method_digest: &MethodDigest) -> KeyIdStorageResult<()> {
    let promise: Promise = Promise::resolve(&WasmKeyIdStorage::delete_key_id(
      self,
      WasmMethodDigest(method_digest.clone()),
    ));
    let result: JsValueResult = JsFuture::from(promise).await.into();
    result.into()
  }
}

#[wasm_bindgen(typescript_custom_section)]
const JWK_STORAGE: &'static str = r#"
/**
 * Key value Storage for key ids under {@link MethodDigest}.
 */
interface KeyIdStorage {
  /**
   * Insert a key id into the `KeyIdStorage` under the given {@link MethodDigest}.
   * 
   * If an entry for `key` already exists in the storage an error must be returned
   * immediately without altering the state of the storage.
   */
  insertKeyId: (methodDigest: MethodDigest, keyId: string) => Promise<void>;

  /**
   * Obtain the key id associated with the given {@link MethodDigest}.
   */
  getKeyId: (methodDigest: MethodDigest) => Promise<string>;

  /**
   * Delete the `KeyId` associated with the given {@link MethodDigest} from the {@link KeyIdStorage}.
   * 
   * If `key` is not found in storage, an Error must be returned.
   */
  deleteKeyId: (methodDigest: MethodDigest) => Promise<void>;
}"#;
