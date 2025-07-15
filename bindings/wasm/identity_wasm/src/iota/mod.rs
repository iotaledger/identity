// Copyright 2020-2025 IOTA Stiftung, Fondazione LINKS
// SPDX-License-Identifier: Apache-2.0

pub use iota_did::WasmIotaDID;
pub(crate) use iota_document::IotaDocumentLock;
pub use iota_document::PromiseIotaDocument;
pub use iota_document::WasmIotaDocument;
pub use iota_document_metadata::WasmIotaDocumentMetadata;
pub use iota_metadata_encoding::WasmStateMetadataEncoding;

mod iota_did;
mod iota_document;
mod iota_document_ext;
mod iota_document_metadata;
mod iota_metadata_encoding;
