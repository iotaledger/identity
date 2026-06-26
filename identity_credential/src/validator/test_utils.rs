// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crypto::signatures::ed25519::PublicKey;
use crypto::signatures::ed25519::SecretKey;
use identity_core::common::Object;
use identity_core::convert::BaseEncoding;
use identity_did::CoreDID;
use identity_document::document::CoreDocument;
use identity_verification::jwk::EdCurve;
use identity_verification::jwk::Jwk;
use identity_verification::jwk::JwkParamsOkp;
use identity_verification::jws::JwsAlgorithm;
use identity_verification::jwu;
use identity_verification::VerificationMethod;

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

pub(crate) fn generate_jwk_document_with_keys() -> (CoreDocument, SecretKey, String) {
  let secret: SecretKey = SecretKey::generate().unwrap();
  let public: PublicKey = secret.public_key();
  let jwk: Jwk = encode_public_ed25519_jwk(&public);

  let did: CoreDID = CoreDID::parse(format!("did:example:{}", BaseEncoding::encode_base58(&public))).unwrap();
  let fragment: String = "#jwk".to_owned();
  let document: CoreDocument = CoreDocument::builder(Object::new())
    .id(did.clone())
    .verification_method(VerificationMethod::new_from_jwk(did, jwk, Some(&fragment)).unwrap())
    .build()
    .unwrap();
  (document, secret, fragment)
}
