// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::rc::Rc;

use identity_iota::document::CoreDocument;
use identity_iota::prelude::IotaDocument;
use js_sys::Array;

use crate::did::ArrayIToCoreDocument;
use crate::did::CoreDocumentLock;
use crate::did::IToCoreDocument;
use crate::did::WasmCoreDocument;
use crate::error::Result;
use crate::iota::IotaDocumentLock;
use crate::iota::WasmIotaDocument;

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

/// A shallow copy of a document imported from JS.
/// Instances of this type are expected to be short lived (for the duration of a function call)
/// in order to avoid unintentional memory leaks.
pub(crate) enum ImportedDocumentLock {
  Core(Rc<CoreDocumentLock>),
  Iota(Rc<IotaDocumentLock>),
}

impl ImportedDocumentLock {
  /// Obtain a read guard which implements `AsRef<CoreDocument>`.
  pub(crate) fn try_read(&self) -> Result<ImportedDocumentReadGuard<'_>> {
    match self {
      Self::Iota(lock) => Ok(ImportedDocumentReadGuard(tokio::sync::RwLockReadGuard::map(
        lock.try_read()?,
        IotaDocument::core_document,
      ))),
      Self::Core(lock) => Ok(ImportedDocumentReadGuard(lock.try_read()?)),
    }
  }
  /// Must only be called on values implementing `IToCoreDocument`.
  pub(crate) fn from_js_value_unchecked(value: &JsValue) -> Self {
    if let Some(doc) = maybe_get_iota_document(value) {
      Self::Iota(doc.0)
    } else {
      Self::Core(getCoreDocument(value).0)
    }
  }

  // Currently unused, but might be needed in the future.
  #[allow(dead_code)]
  pub(crate) async fn read(&self) -> ImportedDocumentReadGuard<'_> {
    match self {
      Self::Iota(lock) => ImportedDocumentReadGuard(tokio::sync::RwLockReadGuard::map(
        lock.read().await,
        IotaDocument::core_document,
      )),
      Self::Core(loc) => ImportedDocumentReadGuard(loc.read().await),
    }
  }
}

impl From<&IToCoreDocument> for ImportedDocumentLock {
  fn from(value: &IToCoreDocument) -> Self {
    Self::from_js_value_unchecked(value.as_ref())
  }
}

impl From<&ArrayIToCoreDocument> for Vec<ImportedDocumentLock> {
  fn from(value: &ArrayIToCoreDocument) -> Self {
    let value_array = value
      .dyn_ref::<Array>()
      .expect("the provided argument should be of type `Array`");
    value_array
      .iter()
      .map(|value| ImportedDocumentLock::from_js_value_unchecked(&value))
      .collect()
  }
}

pub(crate) struct ImportedDocumentReadGuard<'a>(tokio::sync::RwLockReadGuard<'a, CoreDocument>);

impl AsRef<CoreDocument> for ImportedDocumentReadGuard<'_> {
  fn as_ref(&self) -> &CoreDocument {
    self.0.as_ref()
  }
}

// Specially crafted functions that 1) Provide strongly typed values without expensive cloning and 2) use our
// custom JS shims to make sure that pointers are not nulled after passing them to Rust.
#[wasm_bindgen]
extern "C" {
  /// Called internally by `ImportedDocumentLock`, if used elsewhere panics or memory leaks may occur.  
  #[wasm_bindgen(js_name = _getCoreDocumentInternal)]
  pub fn getCoreDocument(input: &JsValue) -> WasmCoreDocument;

  /// Called internally by `ImportedDocumentLock`, if used elsewhere panics or memory leaks may occur.
  #[wasm_bindgen(js_name = _maybeGetIotaDocumentInternal)]
  pub fn maybe_get_iota_document(input: &JsValue) -> Option<WasmIotaDocument>;
}
