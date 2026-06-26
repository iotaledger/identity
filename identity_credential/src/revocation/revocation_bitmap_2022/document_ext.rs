// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::RevocationBitmap;
use identity_document::document::CoreDocument;
use identity_document::service::Service;
use identity_document::utils::DIDUrlQuery;
use identity_document::utils::Queryable;

use crate::revocation::RevocationError;
use crate::revocation::RevocationResult;

/// Extension trait providing convenience methods to update a `RevocationBitmap2022` service
/// in a [`CoreDocument`](::identity_document::document::CoreDocument).   
pub trait RevocationDocumentExt: private::Sealed {
  /// If the document has a [`RevocationBitmap`] service identified by `service_query`,
  /// revoke all specified `indices`.
  fn revoke_credentials<'query, 'me, Q>(&'me mut self, service_query: Q, indices: &[u32]) -> RevocationResult<()>
  where
    Q: Into<DIDUrlQuery<'query>>;

  /// If the document has a [`RevocationBitmap`] service identified by `service_query`,
  /// unrevoke all specified `indices`.
  fn unrevoke_credentials<'query, 'me, Q>(&'me mut self, service_query: Q, indices: &[u32]) -> RevocationResult<()>
  where
    Q: Into<DIDUrlQuery<'query>>;

  /// Extracts the `RevocationBitmap` from the referenced service in the DID Document.
  ///
  /// # Errors
  ///
  /// Fails if the referenced service is not found, or is not a
  /// valid `RevocationBitmap2022` service.
  fn resolve_revocation_bitmap(&self, query: DIDUrlQuery<'_>) -> RevocationResult<RevocationBitmap>;
}

mod private {
  use super::CoreDocument;

  pub trait Sealed {}
  impl Sealed for CoreDocument {}
}

impl RevocationDocumentExt for CoreDocument {
  fn revoke_credentials<'query, 'me, Q>(&'me mut self, service_query: Q, indices: &[u32]) -> RevocationResult<()>
  where
    Q: Into<DIDUrlQuery<'query>>,
  {
    update_revocation_bitmap(self, service_query, |revocation_bitmap| {
      for credential in indices {
        revocation_bitmap.revoke(*credential);
      }
    })
  }

  fn unrevoke_credentials<'query, 'me, Q>(&mut self, service_query: Q, indices: &[u32]) -> RevocationResult<()>
  where
    Q: Into<DIDUrlQuery<'query>>,
  {
    update_revocation_bitmap(self, service_query, |revocation_bitmap| {
      for credential in indices {
        revocation_bitmap.unrevoke(*credential);
      }
    })
  }

  fn resolve_revocation_bitmap(&self, query: DIDUrlQuery<'_>) -> RevocationResult<RevocationBitmap> {
    self
      .resolve_service(query)
      .ok_or(RevocationError::InvalidService("revocation bitmap service not found"))
      .and_then(RevocationBitmap::try_from)
  }
}

fn update_revocation_bitmap<'query, 'me, F, Q>(
  document: &'me mut CoreDocument,
  service_query: Q,
  f: F,
) -> RevocationResult<()>
where
  F: FnOnce(&mut RevocationBitmap),
  Q: Into<DIDUrlQuery<'query>>,
{
  let service: &mut Service = document
    .service_mut_unchecked()
    .query_mut(service_query)
    .ok_or(RevocationError::InvalidService("invalid id - service not found"))?;

  let mut revocation_bitmap: RevocationBitmap = RevocationBitmap::try_from(&*service)?;
  f(&mut revocation_bitmap);

  *service.service_endpoint_mut() = revocation_bitmap.to_endpoint()?;

  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use identity_core::convert::FromJson;
  use identity_did::DID;

  const START_DOCUMENT_JSON: &str = r#"{
        "id": "did:example:1234",
        "verificationMethod": [
          {
            "id": "did:example:1234#key-1",
            "controller": "did:example:1234",
            "type": "Ed25519VerificationKey2018",
            "publicKeyMultibase": "zJdzr2UvC"
          },
          {
            "id": "did:example:1234#key-2",
            "controller": "did:example:1234",
            "type": "Ed25519VerificationKey2018",
            "publicKeyMultibase": "zJdzr2UvD"
          },
          {
            "id": "did:example:1234#key-3",
            "controller": "did:example:1234",
            "type": "Ed25519VerificationKey2018",
            "publicKeyMultibase": "zJdzr2UvE"
          }
        ],
        "authentication": [
          {
            "id": "did:example:1234#auth-key",
            "controller": "did:example:1234",
            "type": "Ed25519VerificationKey2018",
            "publicKeyMultibase": "zT7yhPEwJZL4G"
          },
          "did:example:1234#key-3"
        ],
        "keyAgreement": [
          "did:example:1234#key-4"
        ]
      }
      "#;

  #[test]
  fn test_revocation() {
    let mut document: CoreDocument = CoreDocument::from_json(&START_DOCUMENT_JSON).unwrap();

    let indices_1 = [3, 9, 254, 65536];
    let indices_2 = [2, 15, 1337, 1000];

    let service_id = document.id().to_url().join("#revocation-service").unwrap();

    // The methods error if the service doesn't exist.
    assert!(document.revoke_credentials(&service_id, &indices_2).is_err());
    assert!(document.unrevoke_credentials(&service_id, &indices_2).is_err());

    // Add service with indices_1 already revoked.
    let mut bitmap: crate::revocation::RevocationBitmap = crate::revocation::RevocationBitmap::new();
    for index in indices_1.iter() {
      bitmap.revoke(*index);
    }

    assert!(document
      .insert_service(bitmap.to_service(service_id.clone()).unwrap())
      .is_ok());

    // Revoke indices_2.
    document.revoke_credentials(&service_id, &indices_2).unwrap();
    let service: &Service = document.resolve_service(&service_id).unwrap();
    let decoded_bitmap: crate::revocation::RevocationBitmap = service.try_into().unwrap();

    // We expect all indices to be revoked now.
    for index in indices_1.iter().chain(indices_2.iter()) {
      assert!(decoded_bitmap.is_revoked(*index));
    }

    // Unrevoke indices_1.
    document.unrevoke_credentials(&service_id, &indices_1).unwrap();

    let service: &Service = document.resolve_service(&service_id).unwrap();
    let decoded_bitmap: crate::revocation::RevocationBitmap = service.try_into().unwrap();

    // Expect indices_2 to be revoked, but not indices_1.
    for index in indices_2 {
      assert!(decoded_bitmap.is_revoked(index));
    }
    for index in indices_1 {
      assert!(!decoded_bitmap.is_revoked(index));
    }
  }
}
