// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_core::common::Object;
use identity_core::common::Url;
use identity_core::convert::FromJson;
use identity_credential::credential::Credential;
use identity_credential::credential::Jws;
use identity_credential::validator::JwtCredentialValidationOptions;
use identity_did::DIDUrl;
use identity_did::DID;
use identity_document::document::CoreDocument;
use identity_document::verifiable::JwsVerificationOptions;
use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_verification::jose::jws::JwsAlgorithm;
use identity_verification::jwk::Jwk;
use identity_verification::jws::DecodedJws;
use identity_verification::jwu::encode_b64;
use identity_verification::MethodRelationship;
use identity_verification::MethodScope;

use crate::key_id_storage::KeyIdMemstore;
use crate::key_storage::JwkMemStore;
use crate::storage::JwsSignatureOptions;

use crate::storage::JwkDocumentExt;
use crate::Storage;

type MemStorage = Storage<JwkMemStore, KeyIdMemstore>;

const MOCK_DOCUMENT_JSON: &str = r#"
{
    "id": "did:bar:Hyx62wPQGyvXCoihZq1BrbUjBRh2LuNxWiiqMkfAuSZr",
    "verificationMethod": [
      {
        "id": "did:bar:Hyx62wPQGyvXCoihZq1BrbUjBRh2LuNxWiiqMkfAuSZr#root",
        "controller": "did:bar:Hyx62wPQGyvXCoihZq1BrbUjBRh2LuNxWiiqMkfAuSZr",
        "type": "Ed25519VerificationKey2018",
        "publicKeyMultibase": "zHyx62wPQGyvXCoihZq1BrbUjBRh2LuNxWiiqMkfAuSZr"
      }
    ]
}"#;

fn setup() -> (CoreDocument, MemStorage) {
  let mock_document = CoreDocument::from_json(MOCK_DOCUMENT_JSON).unwrap();
  let storage = Storage::new(JwkMemStore::new(), KeyIdMemstore::new());
  (mock_document, storage)
}

async fn setup_with_method() -> (CoreDocument, MemStorage, String) {
  let mut mock_document = CoreDocument::from_json(MOCK_DOCUMENT_JSON).unwrap();
  let storage = Storage::new(JwkMemStore::new(), KeyIdMemstore::new());

  let method_fragment: String = mock_document
    .generate_method(
      &storage,
      JwkMemStore::ED25519_KEY_TYPE,
      JwsAlgorithm::EdDSA,
      None,
      MethodScope::VerificationMethod,
    )
    .await
    .unwrap();

  (mock_document, storage, method_fragment)
}

#[tokio::test]
async fn generation() {
  let (mut document, storage) = setup();
  // Insert a method whose key material is backed by storage and check that it resolves.
  let fragment = "#key-1";
  let _kid = document
    .generate_method(
      &storage,
      JwkMemStore::ED25519_KEY_TYPE,
      JwsAlgorithm::EdDSA,
      Some(fragment),
      MethodScope::VerificationMethod,
    )
    .await
    .unwrap();
  assert!(document.resolve_method(fragment, None).is_some());

  // Insert a method backed by storage without passing a fragment
  let method_fragment: String = document
    .generate_method(
      &storage,
      JwkMemStore::ED25519_KEY_TYPE,
      JwsAlgorithm::EdDSA,
      None,
      MethodScope::VerificationRelationship(MethodRelationship::AssertionMethod),
    )
    .await
    .unwrap();

  // Check that the method can be resolved by passing the `kid` as a fragment
  assert!(document
    .resolve_method(
      &method_fragment,
      Some(MethodScope::VerificationRelationship(
        MethodRelationship::AssertionMethod
      ))
    )
    .is_some());
}

#[tokio::test]
async fn create_jws() {
  let (document, storage, fragment) = setup_with_method().await;

  let payload: &[u8] = b"test";
  let signature_options: JwsSignatureOptions = JwsSignatureOptions::new();
  let verification_options: JwsVerificationOptions = JwsVerificationOptions::new();

  let jws: Jws = document
    .create_jws(&storage, &fragment, payload, &signature_options)
    .await
    .unwrap();

  assert!(document
    .verify_jws(jws.as_str(), None, &EdDSAJwsVerifier::default(), &verification_options)
    .is_ok());
}

#[tokio::test]
async fn create_jws_typ() {
  // Default `typ` is "JWT".
  let (document, storage, fragment) = setup_with_method().await;
  let payload: &[u8] = b"test";
  let signature_options: JwsSignatureOptions = JwsSignatureOptions::new();
  let verification_options: JwsVerificationOptions = JwsVerificationOptions::new();

  let jws: Jws = document
    .create_jws(&storage, &fragment, payload, &signature_options)
    .await
    .unwrap();

  let decoded_jws = document.verify_jws(jws.as_str(), None, &EdDSAJwsVerifier::default(), &verification_options);
  assert_eq!(decoded_jws.unwrap().protected.typ().unwrap(), "JWT");

  // Custom `typ`.
  let signature_options: JwsSignatureOptions = JwsSignatureOptions::new().typ("test-typ");

  let jws: Jws = document
    .create_jws(&storage, &fragment, payload, &signature_options)
    .await
    .unwrap();

  let decoded_jws = document.verify_jws(jws.as_str(), None, &EdDSAJwsVerifier::default(), &verification_options);
  assert_eq!(decoded_jws.unwrap().protected.typ().unwrap(), "test-typ");
}

#[tokio::test]
async fn create_jws_with_nonce() {
  let (document, storage, fragment) = setup_with_method().await;

  let payload: &[u8] = b"test";
  let nonce: &str = "nonce";
  let signature_options: JwsSignatureOptions = JwsSignatureOptions::new().nonce(nonce);
  let verification_options: JwsVerificationOptions = JwsVerificationOptions::new().nonce(nonce);

  let jws: Jws = document
    .create_jws(&storage, &fragment, payload, &signature_options)
    .await
    .unwrap();

  assert!(document
    .verify_jws(jws.as_str(), None, &EdDSAJwsVerifier::default(), &verification_options)
    .is_ok());

  assert!(document
    .verify_jws(
      jws.as_str(),
      None,
      &EdDSAJwsVerifier::default(),
      &JwsVerificationOptions::new()
    )
    .is_err());

  assert!(document
    .verify_jws(
      jws.as_str(),
      None,
      &EdDSAJwsVerifier::default(),
      &JwsVerificationOptions::new().nonce("other")
    )
    .is_err());
}

#[tokio::test]
async fn create_jws_with_header_copy_options() {
  let (document, storage, fragment) = setup_with_method().await;

  let payload: &[u8] = b"test";
  let url: Url = Url::parse("https://example.com/").unwrap();
  let typ: &str = "typ";
  let cty: &str = "content_type";

  let signature_options: JwsSignatureOptions = JwsSignatureOptions::new()
    .url(url.clone())
    .typ(typ)
    .cty(cty)
    .attach_jwk_to_header(true);

  let verification_options: JwsVerificationOptions = JwsVerificationOptions::new();

  let jws: Jws = document
    .create_jws(&storage, &fragment, payload, &signature_options)
    .await
    .unwrap();

  let decoded_jws: DecodedJws<'_> = document
    .verify_jws(jws.as_str(), None, &EdDSAJwsVerifier::default(), &verification_options)
    .unwrap();

  let jwk: &Jwk = document
    .resolve_method(&fragment, None)
    .unwrap()
    .data()
    .try_public_key_jwk()
    .unwrap();

  assert_eq!(decoded_jws.protected.typ().unwrap(), typ);
  assert_eq!(decoded_jws.protected.cty().unwrap(), cty);
  assert_eq!(decoded_jws.protected.url().unwrap(), &url);
  assert_eq!(decoded_jws.protected.jwk().unwrap(), jwk);
}

#[tokio::test]
async fn create_jws_detached() {
  let (document, storage, fragment) = setup_with_method().await;

  // =====================
  // Without B64 Encoding
  // =====================

  let payload: &[u8] = b"test";
  let signature_options: JwsSignatureOptions = JwsSignatureOptions::new().b64(false).detached_payload(true);
  let verification_options: JwsVerificationOptions = JwsVerificationOptions::new();

  let jws: Jws = document
    .create_jws(&storage, fragment.as_ref(), payload, &signature_options)
    .await
    .unwrap();

  assert!(document
    .verify_jws(
      jws.as_str(),
      Some(payload),
      &EdDSAJwsVerifier::default(),
      &verification_options,
    )
    .is_ok());

  // ==================
  // With B64 Encoding
  // ==================

  let signature_options: JwsSignatureOptions = JwsSignatureOptions::new().b64(true).detached_payload(true);

  let jws: Jws = document
    .create_jws(&storage, fragment.as_ref(), payload, &signature_options)
    .await
    .unwrap();
  let payload_b64: String = encode_b64(payload);

  assert!(document
    .verify_jws(
      jws.as_str(),
      Some(payload_b64.as_ref()),
      &EdDSAJwsVerifier::default(),
      &verification_options,
    )
    .is_ok());
}

#[tokio::test]
async fn create_jws_with_custom_kid() {
  let (document, storage, fragment) = setup_with_method().await;

  let payload: &[u8] = b"test";
  let key_id: &str = "my-key-id";
  let signature_options: JwsSignatureOptions = JwsSignatureOptions::new().kid(key_id);
  let verification_options: JwsVerificationOptions =
    JwsVerificationOptions::new().method_id(document.id().clone().join(format!("#{fragment}")).unwrap());

  let jws: Jws = document
    .create_jws(&storage, &fragment, payload, &signature_options)
    .await
    .unwrap();

  let decoded = document
    .verify_jws(jws.as_str(), None, &EdDSAJwsVerifier::default(), &verification_options)
    .unwrap();

  assert_eq!(decoded.protected.kid().unwrap(), key_id);
}

#[tokio::test]
async fn signing_credential() {
  let (mut document, storage) = setup();

  // Generate a method with the kid as fragment
  let method_fragment: String = document
    .generate_method(
      &storage,
      JwkMemStore::ED25519_KEY_TYPE,
      JwsAlgorithm::EdDSA,
      None,
      MethodScope::VerificationMethod,
    )
    .await
    .unwrap();

  let credential_json: &str = r#"
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "id": "http://example.edu/credentials/3732",
      "type": ["VerifiableCredential", "UniversityDegreeCredential"],
      "issuer": "did:bar:Hyx62wPQGyvXCoihZq1BrbUjBRh2LuNxWiiqMkfAuSZr",
      "issuanceDate": "2010-01-01T19:23:24Z",
      "credentialSubject": {
        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "degree": {
          "type": "BachelorDegree",
          "name": "Bachelor of Science in Mechanical Engineering"
        }
      }
    }"#;

  let credential: Credential = Credential::from_json(credential_json).unwrap();
  let jws = document
    .create_credential_jwt(
      &credential,
      &storage,
      &method_fragment,
      &JwsSignatureOptions::default(),
      None,
    )
    .await
    .unwrap();
  // Verify the credential
  let validator =
    identity_credential::validator::JwtCredentialValidator::with_signature_verifier(EdDSAJwsVerifier::default());
  assert!(validator
    .validate::<_, Object>(
      &jws,
      &document,
      &JwtCredentialValidationOptions::default(),
      identity_credential::validator::FailFast::FirstError
    )
    .is_ok());
}

#[tokio::test]
async fn purging() {
  let (mut document, storage) = setup();
  let method_fragment: String = document
    .generate_method(
      &storage,
      JwkMemStore::ED25519_KEY_TYPE,
      JwsAlgorithm::EdDSA,
      None,
      MethodScope::VerificationMethod,
    )
    .await
    .unwrap();

  let method_id: DIDUrl = document.resolve_method(&method_fragment, None).unwrap().id().to_owned();

  assert!(document.purge_method(&storage, &method_id).await.is_ok());
  // Check that the method is no longer contained in the document
  assert!(document.resolve_method(&method_fragment, None).is_none());
  // there should now be no items left in the storage
  assert_eq!(storage.key_id_storage().count().await, 0);
  assert_eq!(storage.key_storage().count().await, 0);
}

#[cfg(feature = "iota-document")]
mod iota_document_tests {
  // Write a single test for the IotaDocument case just to check that it works
  use super::*;
  use identity_did::DIDUrl;
  use identity_did::DID;
  use identity_document::verifiable::JwsVerificationOptions;
  use identity_iota_core::IotaDocument;
  #[tokio::test]
  async fn iota_document_document_jwk_storage_extension() {
    // Construct IotaDocument from json
    const DOC_JSON: &str = r#"
    {
      "doc": {
        "id": "did:iota:rms:0x7591a0bc872e3a4ab66228d65773961a7a95d2299ec8464331c80fcd86b35f38",
        "controller": "did:iota:rms:0xfbaaa919b51112d51a8f18b1500d98f0b2e91d793bc5b27fd5ab04cb1b806343"
      },
      "meta": {
        "created": "2023-01-25T15:48:09Z",
        "updated": "2023-01-25T15:48:09Z"
      }
    }
    "#;
    let mut iota_document: IotaDocument = IotaDocument::from_json(DOC_JSON).unwrap();
    // Initialize storage
    let storage = MemStorage::new(JwkMemStore::new(), KeyIdMemstore::new());
    let fragment = "#key-1";
    // Generate method
    let _kid = iota_document
      .generate_method(
        &storage,
        JwkMemStore::ED25519_KEY_TYPE,
        JwsAlgorithm::EdDSA,
        Some(fragment),
        MethodScope::VerificationMethod,
      )
      .await
      .unwrap();

    // Sign the test string
    let jws = iota_document
      .create_jws(&storage, fragment, b"test", &JwsSignatureOptions::new())
      .await
      .unwrap();

    // Verify the JWS
    let result = iota_document.verify_jws(
      &jws,
      None,
      &EdDSAJwsVerifier::default(),
      &JwsVerificationOptions::default(),
    );
    assert!(result.is_ok());

    // Check that the claims contain the expected string
    assert!(std::str::from_utf8(&result.unwrap().claims).unwrap().contains("test"));

    // Remove the method from the document
    let method_id: DIDUrl = iota_document.id().to_url().join(fragment).unwrap();
    assert!(iota_document.purge_method(&storage, &method_id).await.is_ok());
    assert!(iota_document.resolve_method(method_id, None).is_none());
    // The storage should now be empty
    assert_eq!(storage.key_id_storage().count().await, 0);
    assert_eq!(storage.key_storage().count().await, 0);
  }
}
