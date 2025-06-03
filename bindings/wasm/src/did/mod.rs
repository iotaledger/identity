// Copyright 2020-2025 IOTA Stiftung, Fondazione LINKS
// SPDX-License-Identifier: Apache-2.0

mod did_jwk;
mod did_compositejwk;
mod jws_verification_options;
mod service;
mod wasm_core_did;
mod wasm_core_document;
mod wasm_did_url;
mod wasm_did_jwk_document_ext;

pub use self::service::IService;
pub use self::service::UServiceEndpoint;
pub use self::service::WasmService;
pub use self::wasm_core_did::IToCoreDID;
pub use self::wasm_core_did::WasmCoreDID;
pub use self::wasm_core_document::ArrayIToCoreDocument;
pub(crate) use self::wasm_core_document::CoreDocumentLock;
pub use self::wasm_core_document::IToCoreDocument;
pub use self::wasm_core_document::PromiseJws;
pub use self::wasm_core_document::PromiseJwt;
pub use self::wasm_core_document::WasmCoreDocument;
pub use self::wasm_did_url::WasmDIDUrl;
pub use did_jwk::*;
pub use did_compositejwk::*;
pub use self::jws_verification_options::*;
