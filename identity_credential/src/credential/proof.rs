// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_core::common::Object;
use serde::Deserialize;
use serde::Serialize;

/// Represents a cryptographic proof that can be used to validate verifiable credentials and
/// presentations.
///
/// This representation does not inherently implement any standard; instead, it
/// can be utilized to implement standards or user-defined proofs. The presence of the
/// `type` field is necessary to accommodate different types of cryptographic proofs.
///
/// Note that this proof is not related to JWT and can be used in combination or as an alternative
/// to it.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Proof {
  /// Type of proof.
  #[serde(rename = "type")]
  pub type_: String,

  /// Properties of the proof, entries depend on the proof type.
  #[serde(flatten)]
  pub properties: Object,
}

impl Proof {
  /// Creates a new `Proof`.
  pub fn new(type_: String, properties: Object) -> Proof {
    Self { type_, properties }
  }
}

#[cfg(test)]
mod tests {
  use super::Proof;
  use crate::credential::Credential;
  use identity_core::common::Object;
  use identity_core::convert::FromJson;

  #[test]
  fn test_proof_from_json() {
    let proof = r#"
    {
      "type": "test-proof",
      "signature": "abc123"
    }
    "#;
    let proof: Proof = Proof::from_json(proof).expect("proof deserialization failed");

    assert_eq!(proof.type_, "test-proof");
    let value = proof
      .properties
      .get("signature")
      .expect("property in proof doesn't exist");
    assert_eq!(value, "abc123");
  }

  #[test]
  fn test_credential_with_proof_from_json() {
    let credential_json = r#"
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "id": "http://example.edu/credentials/58473",
      "type": ["VerifiableCredential", "AlumniCredential"],
      "issuer": "https://example.edu/issuers/14",
      "issuanceDate": "2010-01-01T19:23:24Z",
      "credentialSubject": {
        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "alumniOf": "Example University"
      },
      "proof": {
        "type": "RsaSignature2018",
        "created": "2017-06-18T21:19:10Z",
        "proofPurpose": "assertionMethod",
        "verificationMethod": "https://example.com/jdoe/keys/1",
        "jws": "eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..TCYt5XsITJX1CxPCT8yAV-TVkIEq_PbChOMqsLfRoPsnsgw5WEuts01mq-pQy7UJiN5mgRxD-WUcX16dUEMGlv50aqzpqh4Qktb3rk-BuQy72IFLOqV0G_zS245-kronKb78cPN25DGlcTwLtjPAYuNzVBAh4vGHSrQyHUdBBPM"
      }
    }
    "#;

    let proof: Proof = Credential::<Object>::from_json(credential_json).unwrap().proof.unwrap();

    assert_eq!(proof.type_, "RsaSignature2018");
    let value = proof
      .properties
      .get("proofPurpose")
      .expect("property in proof doesn't exist");
    assert_eq!(value, "assertionMethod");
    assert_eq!(proof.properties.len(), 4);
  }
}
