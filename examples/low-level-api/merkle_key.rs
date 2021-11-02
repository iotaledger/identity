// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! An example that revokes a key and shows how verification fails as a consequence.
//!
//! cargo run --example merkle_key

use rand::rngs::OsRng;
use rand::Rng;

use identity::core::ToJson;
use identity::credential::Credential;
use identity::crypto::merkle_key::Sha256;
use identity::crypto::merkle_tree::Proof;
use identity::crypto::KeyCollection;
use identity::crypto::PrivateKey;
use identity::crypto::PublicKey;
use identity::did::MethodScope;
use identity::iota::ClientMap;
use identity::iota::CredentialValidation;
use identity::iota::CredentialValidator;
use identity::iota::IotaDID;
use identity::iota::IotaVerificationMethod;
use identity::iota::Receipt;
use identity::prelude::*;

mod common;
mod create_did;

#[tokio::main]
async fn main() -> Result<()> {
  // Create a client instance to send messages to the Tangle.
  let client: ClientMap = ClientMap::new();

  // Create a signed DID Document/KeyPair for the credential issuer (see create_did.rs).
  let (mut issuer_doc, issuer_key, issuer_receipt): (IotaDocument, KeyPair, Receipt) = create_did::run().await?;

  // Create a signed DID Document/KeyPair for the credential subject (see create_did.rs).
  let (subject_doc, _, _): (IotaDocument, KeyPair, Receipt) = create_did::run().await?;

  // Generate a Merkle Key Collection Verification Method with 8 keys (Must be a power of 2)
  let keys: KeyCollection = KeyCollection::new_ed25519(8)?;
  let method_did: IotaDID = issuer_doc.id().clone();
  let method = IotaVerificationMethod::create_merkle_key::<Sha256>(method_did, &keys, "merkle-key")?;

  // Add to the DID Document as a general-purpose verification method
  issuer_doc.insert_method(method, MethodScope::VerificationMethod);
  issuer_doc.set_previous_message_id(*issuer_receipt.message_id());
  issuer_doc.sign_self(issuer_key.private(), &issuer_doc.default_signing_method()?.id())?;

  // Publish the Identity to the IOTA Network and log the results.
  // This may take a few seconds to complete proof-of-work.
  let receipt: Receipt = client.publish_document(&issuer_doc).await?;
  println!("Publish Receipt > {:#?}", receipt);

  // Create an unsigned Credential with claims about `subject` specified by `issuer`.
  let mut credential: Credential = common::issue_degree(&issuer_doc, &subject_doc)?;

  // Select a random key from the collection
  let index: usize = OsRng.gen_range(0..keys.len());

  let public: &PublicKey = keys.public(index).unwrap();
  let private: &PrivateKey = keys.private(index).unwrap();

  // Generate an inclusion proof for the selected key
  let proof: Proof<Sha256> = keys.merkle_proof(index).unwrap();

  // Sign the Credential with the issuers private key
  issuer_doc
    .signer(private)
    .method("merkle-key")
    .merkle_key((public, &proof))
    .sign(&mut credential)?;

  println!("Credential JSON > {:#}", credential);

  let credential_json: String = credential.to_json()?;

  // Check the verifiable credential is valid
  let validator: CredentialValidator<ClientMap> = CredentialValidator::new(&client);
  let validation: CredentialValidation = validator.check(&credential_json).await?;
  assert!(validation.verified);

  println!("Credential Validation > {:#?}", validation);

  // The Issuer would like to revoke the credential (and therefore revokes key at `index`)
  issuer_doc
    .try_resolve_method_mut("merkle-key")
    .and_then(IotaVerificationMethod::try_from_mut)?
    .revoke_merkle_key(index)?;
  issuer_doc.set_previous_message_id(*receipt.message_id());
  issuer_doc.sign_self(issuer_key.private(), &issuer_doc.default_signing_method()?.id())?;

  let receipt: Receipt = client.publish_document(&issuer_doc).await?;

  println!("Publish Receipt > {:#?}", receipt);

  // Check the verifiable credential is revoked
  let validation: CredentialValidation = validator.check(&credential_json).await?;
  assert!(!validation.verified);

  println!("Credential Validation > {:#?}", validation);

  Ok(())
}
