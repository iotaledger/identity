// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crypto::signatures::ed25519::PublicKey;
use crypto::signatures::ed25519::SecretKey;
use identity_core::common::Timestamp;
use identity_core::common::Url;
use identity_core::convert::FromJson;
use identity_credential::credential::Credential;
use identity_credential::credential::CredentialBuilder;
use identity_credential::credential::Subject;
use identity_did::CoreDID;
use identity_did::DID;
use identity_document::document::CoreDocument;
use identity_iota_core::IotaDocument;
use identity_verification::jwk::EdCurve;
use identity_verification::jwk::Jwk;
use identity_verification::jwk::JwkParamsOkp;
use identity_verification::jws::JwsAlgorithm;
use identity_verification::jwu;
use identity_verification::MethodScope;
use identity_verification::VerificationMethod;
use serde_json::json;

use crate::key_id_storage::KeyIdMemstore;
use crate::key_storage::JwkMemStore;
use crate::JwkDocumentExt;
use crate::Storage;

type MemStorage = Storage<JwkMemStore, KeyIdMemstore>;

const ISSUER_DOCUMENT_JSON: &str = r#"
{
    "id": "did:bar:Hyx62wPQGyvXCoihZq1BrbUjBRh2LuNxWiiqMkfAuSZr"
}"#;

const SUBJECT_DOCUMENT_JSON: &str = r#"
{
    "id": "did:foo:0xabcdef"
}"#;

const SUBJECT_IOTA_DOCUMENT_JSON: &str = r#"
{
  "doc": {
    "id": "did:iota:tst2:0xdfda8bcfb959c3e6ef261343c3e1a8310e9c8294eeafee326a4e96d65dbeaca0"
  },
  "meta": {
    "created": "2023-05-12T15:09:50Z",
    "updated": "2023-05-12T15:09:50Z"
  }
}"#;

const ISSUER_IOTA_DOCUMENT_JSON: &str = r#"
{
  "doc": {
    "id": "did:iota:tst:0xdfda8bcfb959c3e6ef261343c3e1a8310e9c8294eeafee326a4e96d65dbeaca0"
  },
  "meta": {
    "created": "2023-05-12T15:09:50Z",
    "updated": "2023-05-12T15:09:50Z"
  }
}"#;

pub(super) struct Setup<T: JwkDocumentExt, U: JwkDocumentExt> {
  pub(crate) issuer_doc: T,
  pub(crate) subject_doc: U,
  pub(crate) issuer_storage: MemStorage,
  pub(crate) issuer_method_fragment: String,
  pub(crate) subject_storage: MemStorage,
  pub(crate) subject_method_fragment: String,
}

pub(super) async fn setup_iotadocument(
  issuer_fragment: Option<&'static str>,
  subject_fragment: Option<&'static str>,
) -> Setup<IotaDocument, IotaDocument> {
  let mut issuer_doc = IotaDocument::from_json(ISSUER_IOTA_DOCUMENT_JSON).unwrap();
  let mut subject_doc = IotaDocument::from_json(SUBJECT_IOTA_DOCUMENT_JSON).unwrap();
  let issuer_storage = Storage::new(JwkMemStore::new(), KeyIdMemstore::new());
  let subject_storage = Storage::new(JwkMemStore::new(), KeyIdMemstore::new());

  let issuer_method_fragment: String = generate_method(&issuer_storage, &mut issuer_doc, issuer_fragment).await;
  let subject_method_fragment: String = generate_method(&subject_storage, &mut subject_doc, subject_fragment).await;

  Setup {
    issuer_doc,
    subject_doc,
    issuer_storage,
    subject_storage,
    issuer_method_fragment,
    subject_method_fragment,
  }
}

pub(super) async fn setup_coredocument(
  issuer_fragment: Option<&'static str>,
  subject_fragment: Option<&'static str>,
) -> Setup<CoreDocument, CoreDocument> {
  let mut issuer_doc = CoreDocument::from_json(ISSUER_DOCUMENT_JSON).unwrap();
  let mut subject_doc = CoreDocument::from_json(SUBJECT_DOCUMENT_JSON).unwrap();
  let issuer_storage = Storage::new(JwkMemStore::new(), KeyIdMemstore::new());
  let subject_storage = Storage::new(JwkMemStore::new(), KeyIdMemstore::new());

  let issuer_method_fragment: String = generate_method(&issuer_storage, &mut issuer_doc, issuer_fragment).await;
  let subject_method_fragment: String = generate_method(&subject_storage, &mut subject_doc, subject_fragment).await;

  Setup {
    issuer_doc,
    subject_doc,
    issuer_storage,
    subject_storage,
    issuer_method_fragment,
    subject_method_fragment,
  }
}

async fn generate_method<T>(storage: &MemStorage, document: &mut T, fragment: Option<&'static str>) -> String
where
  T: JwkDocumentExt,
{
  document
    .generate_method(
      storage,
      JwkMemStore::ED25519_KEY_TYPE,
      JwsAlgorithm::EdDSA,
      fragment,
      MethodScope::assertion_method(),
    )
    .await
    .unwrap()
}

pub(super) struct CredentialSetup {
  pub(crate) credential: Credential,
  pub(crate) issuance_date: Timestamp,
  pub(crate) expiration_date: Timestamp,
}

pub(super) fn generate_credential<T: AsRef<CoreDocument>, U: AsRef<CoreDocument>>(
  issuer: T,
  subjects: &[&U],
  issuance_date: Option<Timestamp>,
  expiration_date: Option<Timestamp>,
) -> CredentialSetup {
  let issuance_date = issuance_date.unwrap_or_else(|| Timestamp::parse("2020-01-01T00:00:00Z").unwrap());
  let expiration_date = expiration_date.unwrap_or_else(|| Timestamp::parse("2024-01-01T00:00:00Z").unwrap());

  let credential_subjects: Vec<Subject> = subjects
    .iter()
    .map(|subject| {
      Subject::from_json_value(json!({
        "id": subject.as_ref().id().as_str(),
        "name": "Alice",
        "degree": {
          "type": "BachelorDegree",
          "name": "Bachelor of Science and Arts",
        },
        "GPA": "4.0",
      }))
      .unwrap()
    })
    .collect();

  // Build credential using subject above and issuer.
  let credential: Credential = CredentialBuilder::default()
    .id(Url::parse("https://example.edu/credentials/3732").unwrap())
    .issuer(Url::parse(issuer.as_ref().id().as_str()).unwrap())
    .type_("UniversityDegreeCredential")
    .subjects(credential_subjects)
    .issuance_date(issuance_date)
    .expiration_date(expiration_date)
    .build()
    .unwrap();

  CredentialSetup {
    credential,
    issuance_date,
    expiration_date,
  }
}

pub(crate) fn create_verification_method() -> VerificationMethod {
  let secret: SecretKey = SecretKey::generate().unwrap();
  let public: PublicKey = secret.public_key();
  let jwk: Jwk = encode_public_ed25519_jwk(&public);
  let did: CoreDID = CoreDID::parse(format!("did:example:{}", jwk.thumbprint_sha256_b64())).unwrap();
  VerificationMethod::new_from_jwk(did, jwk, Some("#frag")).unwrap()
}

pub(crate) fn encode_public_ed25519_jwk(public_key: &PublicKey) -> Jwk {
  let x = jwu::encode_b64(public_key.as_ref());
  let mut params = JwkParamsOkp::new();
  params.x = x;
  params.d = None;
  params.crv = EdCurve::Ed25519.name().to_string();
  let mut jwk = Jwk::from_params(params);
  jwk.set_alg(JwsAlgorithm::EdDSA.name());
  jwk
}
