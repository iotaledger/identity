// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::traits::EncodeDecodeBase64;
use identity_iota::storage::KeyId;
use identity_iota::storage::StorageSigner;
use iota_interaction_ts::WasmPublicKey;
use secret_storage::Signer;
use wasm_bindgen::prelude::*;

use crate::common::ImportedDocumentLock;
use crate::did::IToCoreDocument;
use crate::error::Result;
use crate::error::WasmResult;
use crate::jose::WasmJwk;
use crate::storage::WasmJwkStorage;
use crate::storage::WasmKeyIdStorage;
use crate::storage::WasmStorage;

#[wasm_bindgen(js_name = StorageSigner)]
#[derive(Clone)]
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

  /// Creates a new {@link StorageSigner} from a given DID Document and a verification method fragment.
  /// ## Notes
  /// At this time, this function only supports "JsonWebKey2020"-based verification methods.
  #[wasm_bindgen(js_name = fromVmFragment)]
  pub async fn from_vm_fragment(
    storage: &WasmStorage,
    document: &IToCoreDocument,
    fragment: &str,
  ) -> std::result::Result<Self, JsError> {
    let document_lock = ImportedDocumentLock::from(document);
    let document_lock = document_lock.read().await;

    let signer = StorageSigner::new_from_vm_fragment(&storage.0, document_lock.as_ref(), fragment).await?;
    let public_key = signer.public_key_jwk().clone();
    let key_id = signer.key_id().clone();

    Ok(Self {
      storage: storage.clone(),
      key_id,
      public_key: WasmJwk(public_key),
    })
  }

  #[wasm_bindgen(js_name = keyId)]
  pub fn key_id(&self) -> String {
    self.key_id.to_string()
  }

  #[wasm_bindgen(getter, js_name = publicJwk)]
  pub fn get_pk(&self) -> WasmJwk {
    self.public_key.clone()
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

  #[wasm_bindgen(
    js_name = asJwsSigner,
    unchecked_return_type = JwsSigner,
  )]
  pub fn as_jws_signer(&self) -> WasmStorageJwsSigner {
    WasmStorageJwsSigner(self.clone())
  }
}

#[wasm_bindgen(js_name = StorageJwsSigner, skip_typescript)]
pub struct WasmStorageJwsSigner(WasmStorageSigner);

#[wasm_bindgen(js_class = StorageJwsSigner)]
impl WasmStorageJwsSigner {
  pub async fn sign(&self, headers: js_sys::Object, payload: js_sys::Object) -> std::result::Result<Vec<u8>, JsError> {
    use identity_iota::sd_jwt_payload::JwsSigner;

    let headers = serde_wasm_bindgen::from_value(headers.into())?;
    let payload = serde_wasm_bindgen::from_value(payload.into())?;
    Ok(JwsSigner::sign(&self.0.signer(), &headers, &payload).await?)
  }
}
