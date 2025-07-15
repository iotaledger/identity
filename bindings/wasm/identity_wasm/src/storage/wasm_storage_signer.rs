// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::traits::EncodeDecodeBase64;
use identity_iota::storage::KeyId;
use identity_iota::storage::StorageSigner;
use iota_interaction_ts::WasmPublicKey;
use secret_storage::Signer;
use wasm_bindgen::prelude::*;

use crate::error::Result;
use crate::error::WasmResult;
use crate::jose::WasmJwk;
use crate::storage::WasmJwkStorage;
use crate::storage::WasmKeyIdStorage;
use crate::storage::WasmStorage;

#[wasm_bindgen(js_name = StorageSigner)]
pub struct WasmStorageSigner {
  storage: WasmStorage,
  key_id: KeyId,
  public_key: WasmJwk,
}

impl WasmStorageSigner {
  fn signer(&self) -> StorageSigner<'_, WasmJwkStorage, WasmKeyIdStorage> {
    StorageSigner::new(&self.storage.0, self.key_id.clone(), self.public_key.0.clone())
  }
}

#[wasm_bindgen(js_class = StorageSigner)]
impl WasmStorageSigner {
  #[wasm_bindgen(constructor)]
  pub fn new(storage: &WasmStorage, key_id: String, public_key: WasmJwk) -> Self {
    Self {
      storage: storage.clone(),
      key_id: KeyId::new(key_id),
      public_key,
    }
  }

  #[wasm_bindgen(js_name = keyId)]
  pub fn key_id(&self) -> String {
    self.key_id.to_string()
  }

  #[wasm_bindgen(js_name = sign)]
  pub async fn sign(&self, data: &[u8]) -> Result<String> {
    let tx_data = bcs::from_bytes(data).wasm_result()?;
    let sig = self.signer().sign(&tx_data).await.wasm_result()?;
    Ok(sig.encode_base64())
  }

  #[wasm_bindgen(js_name = publicKey)]
  pub async fn public_key(&self) -> Result<WasmPublicKey> {
    Signer::public_key(&self.signer())
      .await
      .wasm_result()
      .and_then(|pk| WasmPublicKey::try_from(&pk))
      .inspect(|wasm_pk| console_log!("WasmStorageSigner's PK: {:?}", &wasm_pk.to_raw_bytes()))
  }

  #[wasm_bindgen(js_name = iotaPublicKeyBytes)]
  pub async fn iota_public_key_bytes(&self) -> Result<Vec<u8>> {
    Signer::public_key(&self.signer()).await.wasm_result().map(|pk| {
      let mut bytes: Vec<u8> = Vec::new();
      bytes.extend_from_slice(&[pk.flag()]);
      bytes.extend_from_slice(pk.as_ref());
      bytes
    })
  }
}
