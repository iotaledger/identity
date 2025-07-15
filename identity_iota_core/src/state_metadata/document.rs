// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_core::convert::FromJson;
use identity_core::convert::ToJson;
use identity_did::CoreDID;
use identity_document::document::CoreDocument;
use once_cell::sync::Lazy;
use serde::Deserialize;
use serde::Serialize;

use crate::error::Result;
use crate::Error;
use crate::IotaDID;
use crate::IotaDocument;
use crate::IotaDocumentMetadata;

use super::StateMetadataEncoding;
use super::StateMetadataVersion;

pub(crate) static PLACEHOLDER_DID: Lazy<CoreDID> = Lazy::new(|| CoreDID::parse("did:0:0").unwrap());

/// Magic bytes used to mark DID documents.
const DID_MARKER: &[u8] = b"DID";

/// Intermediate representation of the DID document as it is contained in the identity.
///
/// DID instances in the document are replaced by the `PLACEHOLDER_DID`.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct StateMetadataDocument {
  #[serde(rename = "doc")]
  pub(crate) document: CoreDocument,
  #[serde(rename = "meta")]
  pub(crate) metadata: IotaDocumentMetadata,
}

impl StateMetadataDocument {
  /// Transforms the document into a [`IotaDocument`] by replacing all placeholders with `original_did`.
  pub fn into_iota_document(self, original_did: &IotaDID) -> Result<IotaDocument> {
    let Self { document, metadata } = self;

    // Transform identifiers: Replace placeholder identifiers, and ensure that `id` and `controller` adhere to the
    // specification.
    let replace_placeholder_with_method_check = |did: CoreDID| -> Result<CoreDID> {
      if did == PLACEHOLDER_DID.as_ref() {
        Ok(CoreDID::from(original_did.clone()))
      } else {
        IotaDID::check_validity(&did).map_err(Error::DIDSyntaxError)?;
        Ok(did)
      }
    };
    let [id_update, controller_update] = [replace_placeholder_with_method_check; 2];

    // Methods and services are not required to be IOTA UTXO DIDs, but we still want to replace placeholders
    let replace_placeholder = |did: CoreDID| -> Result<CoreDID> {
      if did == PLACEHOLDER_DID.as_ref() {
        Ok(CoreDID::from(original_did.clone()))
      } else {
        Ok(did)
      }
    };
    let [methods_update, service_update] = [replace_placeholder; 2];

    let document = document.try_map(
      id_update,
      controller_update,
      methods_update,
      service_update,
      crate::error::Error::InvalidDoc,
    )?;

    Ok(IotaDocument { document, metadata })
  }

  /// Returns the corresponding [`IotaDocument`] with DID replaced by DID placeholder `did:0:0`.
  pub fn into_iota_document_with_placeholders(self) -> IotaDocument {
    IotaDocument {
      document: self.document,
      metadata: self.metadata,
    }
  }

  /// Pack a [`StateMetadataDocument`] into bytes, suitable for storing in an identity,
  /// according to the given `encoding`.
  pub fn pack(self, encoding: StateMetadataEncoding) -> Result<Vec<u8>> {
    let encoded_message_data: Vec<u8> = match encoding {
      StateMetadataEncoding::Json => self
        .to_json_vec()
        .map_err(|err| Error::SerializationError("failed to serialize document to JSON", Some(err)))?,
    };

    // Prepend flags and length.
    let encoded_message_data_with_flags =
      add_flags_to_message(encoded_message_data, StateMetadataVersion::CURRENT, encoding)?;
    Ok(encoded_message_data_with_flags)
  }

  /// Unpack bytes into a [`StateMetadataDocument`].
  pub fn unpack(data: &[u8]) -> Result<Self> {
    // Check marker.
    let marker: &[u8] = data
      .get(0..=2)
      .ok_or(identity_document::Error::InvalidDocument(
        "state metadata decoding: expected DID marker at offset [0..=2]",
        None,
      ))
      .map_err(Error::InvalidDoc)?;
    if marker != DID_MARKER {
      return Err(Error::InvalidStateMetadata("missing `DID` marker"));
    }

    // Check version.
    let version: StateMetadataVersion = StateMetadataVersion::try_from(
      *data
        .get(3)
        .ok_or(identity_document::Error::InvalidDocument(
          "state metadata decoding: expected version at offset 3",
          None,
        ))
        .map_err(Error::InvalidDoc)?,
    )?;
    if version != StateMetadataVersion::V1 {
      return Err(Error::InvalidStateMetadata("unsupported version"));
    }

    // Decode data.
    let encoding: StateMetadataEncoding = StateMetadataEncoding::try_from(
      *data
        .get(4)
        .ok_or(identity_document::Error::InvalidDocument(
          "state metadata decoding: expected encoding at offset 4",
          None,
        ))
        .map_err(Error::InvalidDoc)?,
    )?;

    let data_len_packed: [u8; 2] = data
      .get(5..=6)
      .ok_or(identity_document::Error::InvalidDocument(
        "state metadata decoding: expected data length at offset [5..=6]",
        None,
      ))
      .map_err(Error::InvalidDoc)?
      .try_into()
      .map_err(|_| {
        identity_document::Error::InvalidDocument("state metadata decoding: data length conversion error", None)
      })
      .map_err(Error::InvalidDoc)?;
    let data_len: u16 = u16::from_le_bytes(data_len_packed);

    let data: &[u8] = data
      .get(7..(7 + data_len as usize))
      .ok_or(identity_document::Error::InvalidDocument(
        "state metadata decoding: encoded document shorter than length prefix",
        None,
      ))
      .map_err(Error::InvalidDoc)?;

    match encoding {
      StateMetadataEncoding::Json => StateMetadataDocument::from_json_slice(data).map_err(|err| {
        Error::SerializationError(
          "state metadata decoding: failed to deserialize JSON document",
          Some(err),
        )
      }),
    }
  }
}

/// Prepends the message flags and marker magic bytes to the data in the following order:
/// `[marker, version, encoding, data length, data]`.
fn add_flags_to_message(
  mut data: Vec<u8>,
  version: StateMetadataVersion,
  encoding: StateMetadataEncoding,
) -> Result<Vec<u8>> {
  let data_len: u16 =
    u16::try_from(data.len()).map_err(|_| Error::SerializationError("failed to convert usize to u16", None))?;
  let data_len_packed: [u8; 2] = data_len.to_le_bytes();
  let mut buffer: Vec<u8> = Vec::with_capacity(DID_MARKER.len() + 1 + 1 + data_len_packed.len() + data_len as usize);
  buffer.extend_from_slice(DID_MARKER);
  buffer.push(version as u8);
  buffer.push(encoding as u8);
  buffer.extend_from_slice(&data_len_packed);
  buffer.append(&mut data);
  Ok(buffer)
}

impl From<IotaDocument> for StateMetadataDocument {
  /// Transforms a [`IotaDocument`] into its state metadata representation by replacing all
  /// occurrences of its did with a placeholder.
  fn from(document: IotaDocument) -> Self {
    let id: IotaDID = document.id().clone();
    let IotaDocument { document, metadata } = document;

    // Replace self-referential identifiers with a placeholder, but not others.
    let replace_id_with_placeholder = |did: CoreDID| -> CoreDID {
      if &did == id.as_ref() {
        PLACEHOLDER_DID.clone()
      } else {
        did
      }
    };

    let [id_update, controller_update, methods_update, service_update] = [replace_id_with_placeholder; 4];

    StateMetadataDocument {
      document: document.map_unchecked(id_update, controller_update, methods_update, service_update),
      metadata,
    }
  }
}

#[cfg(test)]
mod tests {
  use identity_core::common::Object;
  use identity_core::common::OneOrSet;
  use identity_core::common::Url;
  use identity_did::CoreDID;
  use identity_did::DID;
  use identity_verification::MethodScope;

  use crate::state_metadata::document::DID_MARKER;
  use crate::state_metadata::PLACEHOLDER_DID;
  use crate::test_utils::generate_method;
  use crate::IotaDID;
  use crate::IotaDocument;
  use crate::StateMetadataDocument;
  use crate::StateMetadataEncoding;
  use crate::StateMetadataVersion;
  use identity_document::service::Service;

  struct TestSetup {
    document: IotaDocument,
    did_self: IotaDID,
    did_foreign: IotaDID,
  }

  fn test_document() -> TestSetup {
    let did_self =
      IotaDID::parse("did:iota:0x8036235b6b5939435a45d68bcea7890eef399209a669c8c263fac7f5089b2ec6").unwrap();
    let did_foreign =
      IotaDID::parse("did:iota:0x71b709dff439f1ac9dd2b9c2e28db0807156b378e13bfa3605ce665aa0d0fdca").unwrap();

    let mut document: IotaDocument = IotaDocument::new_with_id(did_self.clone());
    document
      .insert_method(generate_method(&did_self, "did-self"), MethodScope::VerificationMethod)
      .unwrap();

    document
      .insert_method(
        generate_method(&did_foreign, "did-foreign"),
        MethodScope::authentication(),
      )
      .unwrap();

    assert!(document
      .insert_service(
        Service::builder(Object::new())
          .id(document.id().to_url().join("#my-service").unwrap())
          .type_("RevocationList2022")
          .service_endpoint(Url::parse("https://example.com/xyzabc").unwrap())
          .build()
          .unwrap()
      )
      .is_ok());

    assert!(document
      .insert_service(
        Service::builder(Object::new())
          .id(did_foreign.to_url().join("#my-foreign-service").unwrap())
          .type_("RevocationList2022")
          .service_endpoint(Url::parse("https://example.com/0xf4c42e9da").unwrap())
          .build()
          .unwrap()
      )
      .is_ok());

    document
      .also_known_as_mut()
      .append(Url::parse("did:example:abc").unwrap());
    document
      .also_known_as_mut()
      .append(Url::parse("did:example:xyz").unwrap());

    let controllers = OneOrSet::try_from(vec![did_foreign.clone().into(), did_self.clone().into()]).unwrap();
    *document.core_document_mut().controller_mut() = Some(controllers);

    TestSetup {
      document,
      did_self,
      did_foreign,
    }
  }

  #[test]
  fn test_transformation_roundtrip() {
    let TestSetup {
      document,
      did_self,
      did_foreign,
    } = test_document();

    let state_metadata_doc: StateMetadataDocument = StateMetadataDocument::from(document.clone());

    assert_eq!(
      state_metadata_doc
        .document
        .resolve_method("#did-self", None)
        .unwrap()
        .id()
        .did(),
      <CoreDID as AsRef<CoreDID>>::as_ref(PLACEHOLDER_DID.as_ref())
    );

    assert_eq!(
      state_metadata_doc
        .document
        .resolve_method("#did-foreign", None)
        .unwrap()
        .id()
        .did(),
      did_foreign.as_ref()
    );

    assert_eq!(
      state_metadata_doc
        .document
        .service()
        .iter()
        .find(|service| service.id().fragment().unwrap() == "my-foreign-service")
        .unwrap()
        .id()
        .did(),
      did_foreign.as_ref()
    );

    assert_eq!(
      state_metadata_doc
        .document
        .service()
        .iter()
        .find(|service| service.id().fragment().unwrap() == "my-service")
        .unwrap()
        .id()
        .did(),
      <CoreDID as AsRef<CoreDID>>::as_ref(PLACEHOLDER_DID.as_ref())
    );

    let controllers = state_metadata_doc.document.controller().unwrap();
    assert_eq!(controllers.get(0).unwrap(), did_foreign.as_ref());
    assert_eq!(
      controllers.get(1).unwrap(),
      <CoreDID as AsRef<CoreDID>>::as_ref(PLACEHOLDER_DID.as_ref())
    );

    let iota_document = state_metadata_doc.into_iota_document(&did_self).unwrap();
    assert_eq!(iota_document, document);
  }

  #[test]
  fn test_packing_roundtrip() {
    let TestSetup { document, .. } = test_document();

    let state_metadata_doc: StateMetadataDocument = StateMetadataDocument::from(document);
    let packed_bytes: Vec<u8> = state_metadata_doc.clone().pack(StateMetadataEncoding::Json).unwrap();

    let unpacked_doc = StateMetadataDocument::unpack(&packed_bytes).unwrap();
    assert_eq!(state_metadata_doc.metadata.created, unpacked_doc.metadata.created);
    assert_eq!(state_metadata_doc.metadata.updated, unpacked_doc.metadata.updated);
    assert_eq!(
      state_metadata_doc.metadata.deactivated,
      unpacked_doc.metadata.deactivated
    );

    assert_eq!(state_metadata_doc.document.id(), unpacked_doc.document.id());
    assert_eq!(
      state_metadata_doc.document.also_known_as(),
      unpacked_doc.document.also_known_as()
    );
    assert_eq!(
      state_metadata_doc.document.verification_method(),
      unpacked_doc.document.verification_method()
    );
    assert_eq!(
      state_metadata_doc.document.authentication(),
      unpacked_doc.document.authentication()
    );
    assert_eq!(
      state_metadata_doc.document.assertion_method(),
      unpacked_doc.document.assertion_method()
    );
    assert_eq!(
      state_metadata_doc.document.key_agreement(),
      unpacked_doc.document.key_agreement()
    );
    assert_eq!(
      state_metadata_doc.document.capability_delegation(),
      unpacked_doc.document.capability_delegation()
    );
    assert_eq!(state_metadata_doc.document.service(), unpacked_doc.document.service());
    assert_eq!(
      state_metadata_doc.document.properties(),
      unpacked_doc.document.properties()
    );
  }

  #[test]
  fn test_pack_format() {
    // Changing the serialization is a breaking change!
    let TestSetup { document, .. } = test_document();
    let state_metadata_doc: StateMetadataDocument = StateMetadataDocument::from(document);
    let packed: Vec<u8> = state_metadata_doc.clone().pack(StateMetadataEncoding::Json).unwrap();
    let expected_payload: String = format!(
      "{{\"doc\":{},\"meta\":{}}}",
      state_metadata_doc.document, state_metadata_doc.metadata
    );

    // DID marker.
    assert_eq!(&packed[0..3], DID_MARKER);
    // Version.
    assert_eq!(packed[3], StateMetadataVersion::V1 as u8);
    // Encoding.
    assert_eq!(packed[4], StateMetadataEncoding::Json as u8);
    // JSON length.
    assert_eq!(&packed[5..=6], (expected_payload.len() as u16).to_le_bytes().as_ref());
    // JSON payload.
    assert_eq!(&packed[7..], expected_payload.as_bytes());
  }

  #[test]
  fn test_no_controller() {
    let TestSetup {
      mut document, did_self, ..
    } = test_document();
    *document.core_document_mut().controller_mut() = None;
    let state_metadata_doc: StateMetadataDocument = StateMetadataDocument::from(document);
    let packed: Vec<u8> = state_metadata_doc.clone().pack(StateMetadataEncoding::Json).unwrap();
    let expected_payload: String = format!(
      "{{\"doc\":{},\"meta\":{}}}",
      state_metadata_doc.document, state_metadata_doc.metadata
    );
    assert_eq!(&packed[7..], expected_payload.as_bytes());
    let unpacked = StateMetadataDocument::unpack(&packed).unwrap();
    assert_eq!(
      unpacked
        .into_iota_document(&did_self)
        .unwrap()
        .controller()
        .collect::<Vec<_>>()
        .len(),
      0
    );
  }

  #[test]
  fn test_unpack_length_prefix() {
    // Changing the serialization is a breaking change!
    let TestSetup { document, .. } = test_document();
    let state_metadata_doc: StateMetadataDocument = StateMetadataDocument::from(document);
    let mut packed: Vec<u8> = state_metadata_doc.clone().pack(StateMetadataEncoding::Json).unwrap();
    let original_length = u16::from_le_bytes(packed[5..=6].try_into().unwrap());

    // INVALID: length is too long.
    let longer = (original_length + 1_u16).to_le_bytes();
    packed[5] = longer[0];
    packed[6] = longer[1];
    assert!(StateMetadataDocument::unpack(&packed).is_err());

    // INVALID: length is too long.
    let max: [u8; 2] = u16::MAX.to_le_bytes();
    packed[5] = max[0];
    packed[6] = max[1];
    assert!(StateMetadataDocument::unpack(&packed).is_err());

    // INVALID: length is too short (JSON deserialization fails).
    let shorter = (original_length - 1_u16).to_le_bytes();
    packed[5] = shorter[0];
    packed[6] = shorter[1];
    assert!(StateMetadataDocument::unpack(&packed).is_err());

    // INVALID: length is too short (JSON deserialization fails).
    let min = 0_u16.to_le_bytes();
    packed[5] = min[0];
    packed[6] = min[1];
    assert!(StateMetadataDocument::unpack(&packed).is_err());

    // VALID: length is just right.
    let original = original_length.to_le_bytes();
    packed[5] = original[0];
    packed[6] = original[1];

    let unpacked_doc = StateMetadataDocument::unpack(&packed).unwrap();
    // Controller and State Controller are set to None when packing
    assert_eq!(state_metadata_doc.metadata.created, unpacked_doc.metadata.created);
    assert_eq!(state_metadata_doc.metadata.updated, unpacked_doc.metadata.updated);
    assert_eq!(
      state_metadata_doc.metadata.deactivated,
      unpacked_doc.metadata.deactivated
    );

    assert_eq!(state_metadata_doc.document.id(), unpacked_doc.document.id());
    assert_eq!(
      state_metadata_doc.document.also_known_as(),
      unpacked_doc.document.also_known_as()
    );
    assert_eq!(
      state_metadata_doc.document.verification_method(),
      unpacked_doc.document.verification_method()
    );
    assert_eq!(
      state_metadata_doc.document.authentication(),
      unpacked_doc.document.authentication()
    );
    assert_eq!(
      state_metadata_doc.document.assertion_method(),
      unpacked_doc.document.assertion_method()
    );
    assert_eq!(
      state_metadata_doc.document.key_agreement(),
      unpacked_doc.document.key_agreement()
    );
    assert_eq!(
      state_metadata_doc.document.capability_delegation(),
      unpacked_doc.document.capability_delegation()
    );
    assert_eq!(state_metadata_doc.document.service(), unpacked_doc.document.service());
    assert_eq!(
      state_metadata_doc.document.properties(),
      unpacked_doc.document.properties()
    );
  }
}
