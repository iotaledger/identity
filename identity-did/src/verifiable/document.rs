// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::any::Any;
use identity_core::common::BitSet;
use identity_core::crypto::merkle_key::Blake2b256;
use identity_core::crypto::merkle_key::MerkleDigest;
use identity_core::crypto::merkle_key::MerkleKey;
use identity_core::crypto::merkle_key::MerkleSignature;
use identity_core::crypto::merkle_key::MerkleSigner;
use identity_core::crypto::merkle_key::MerkleTag;
use identity_core::crypto::merkle_key::MerkleVerifier;
use identity_core::crypto::merkle_key::Sha256;
use identity_core::crypto::merkle_key::SigningKey;
use identity_core::crypto::merkle_key::VerificationKey;
use identity_core::crypto::merkle_tree::Proof;
use identity_core::crypto::Ed25519;
use identity_core::crypto::JcsEd25519;
use identity_core::crypto::PublicKey;
use identity_core::crypto::SecretKey;
use identity_core::crypto::SetSignature;
use identity_core::crypto::Sign;
use identity_core::crypto::Signature;
use identity_core::crypto::Signer;
use identity_core::crypto::TrySignature;
use identity_core::crypto::TrySignatureMut;
use identity_core::crypto::Verifier;
use identity_core::crypto::Verify;
use identity_core::error::Error as CoreError;
use serde::Serialize;

use crate::document::Document;
use crate::error::Error;
use crate::error::Result;
use crate::verifiable::Properties;
use crate::verifiable::Revocation;
use crate::verification::Method;
use crate::verification::MethodQuery;
use crate::verification::MethodType;

// =============================================================================
// Generic Crypto Extensions
// =============================================================================

impl<T, U, V> Document<T, U, V> {
  pub fn into_verifiable(self) -> Document<Properties<T>, U, V> {
    self.map(Properties::new)
  }

  pub fn into_verifiable_with_proof(self, proof: Signature) -> Document<Properties<T>, U, V> {
    self.map(|old| Properties::with_proof(old, proof))
  }
}

impl<T, U, V> Document<Properties<T>, U, V> {
  pub fn proof(&self) -> Option<&Signature> {
    self.properties().proof()
  }

  pub fn proof_mut(&mut self) -> Option<&mut Signature> {
    self.properties_mut().proof_mut()
  }

  pub fn set_proof(&mut self, signature: Signature) {
    self.properties_mut().set_proof(signature);
  }
}

impl<T, U, V> TrySignature for Document<Properties<T>, U, V> {
  fn signature(&self) -> Option<&Signature> {
    self.proof()
  }
}

impl<T, U, V> TrySignatureMut for Document<Properties<T>, U, V> {
  fn signature_mut(&mut self) -> Option<&mut Signature> {
    self.proof_mut()
  }
}

impl<T, U, V> SetSignature for Document<Properties<T>, U, V> {
  fn set_signature(&mut self, signature: Signature) {
    self.set_proof(signature)
  }
}

// =============================================================================
// Signature Extensions
// =============================================================================

impl<T, U, V> Document<Properties<T>, U, V>
where
  T: Serialize,
  U: Serialize,
  V: Serialize,
{
  pub fn sign_this<'query, Q>(&mut self, query: Q, secret: &SecretKey) -> Result<()>
  where
    Q: Into<MethodQuery<'query>>,
  {
    let method: &Method<U> = self.try_resolve(query)?;
    let fragment: String = method.try_into_fragment()?;

    match method.key_type() {
      MethodType::Ed25519VerificationKey2018 => {
        JcsEd25519::<Ed25519>::create_signature(self, &fragment, secret.as_ref())?;
      }
      MethodType::MerkleKeyCollection2021 => {
        // Documents can't be signed with Merkle Key Collections
        return Err(Error::InvalidMethodType);
      }
    }

    Ok(())
  }

  pub fn verify_this(&self) -> Result<()> {
    let signature: &Signature = self.try_signature()?;
    let method: &Method<U> = self.try_resolve(signature)?;
    let public: PublicKey = method.key_data().try_decode()?.into();

    match method.key_type() {
      MethodType::Ed25519VerificationKey2018 => {
        JcsEd25519::<Ed25519>::verify_signature(self, public.as_ref())?;
      }
      MethodType::MerkleKeyCollection2021 => {
        // Documents can't be signed with Merkle Key Collections
        return Err(Error::InvalidMethodType);
      }
    }

    Ok(())
  }
}

impl<T, U, V> Document<T, U, V> {
  /// Creates a new [`DocumentSigner`] that can be used to create digital
  /// signatures from verification methods in this DID Document.
  pub fn signer<'base>(&'base self, secret: &'base SecretKey) -> DocumentSigner<'base, '_, '_, T, U, V> {
    DocumentSigner::new(self, secret)
  }

  /// Creates a new [`DocumentVerifier`] that can be used to verify signatures
  /// created with this DID Document.
  pub fn verifier(&self) -> DocumentVerifier<'_, T, U, V> {
    DocumentVerifier::new(self)
  }
}

// =============================================================================
// Document Signer - Simplifying Digital Signature Creation Since 2021
// =============================================================================

pub struct DocumentSigner<'base, 'query, 'proof, T, U, V> {
  document: &'base Document<T, U, V>,
  secret: &'base SecretKey,
  method: Option<MethodQuery<'query>>,
  merkle_key: Option<(&'proof PublicKey, &'proof dyn Any)>,
}

impl<'base, T, U, V> DocumentSigner<'base, '_, '_, T, U, V> {
  pub fn new(document: &'base Document<T, U, V>, secret: &'base SecretKey) -> Self {
    Self {
      document,
      secret,
      method: None,
      merkle_key: None,
    }
  }
}

impl<'base, 'query, T, U, V> DocumentSigner<'base, 'query, '_, T, U, V> {
  pub fn method<Q>(mut self, value: Q) -> Self
  where
    Q: Into<MethodQuery<'query>>,
  {
    self.method = Some(value.into());
    self
  }
}

impl<'proof, T, U, V> DocumentSigner<'_, '_, 'proof, T, U, V> {
  pub fn merkle_key<D>(mut self, proof: (&'proof PublicKey, &'proof Proof<D>)) -> Self
  where
    D: MerkleDigest,
  {
    self.merkle_key = Some((proof.0, proof.1));
    self
  }
}

impl<T, U, V> DocumentSigner<'_, '_, '_, T, U, V> {
  /// Signs the provided data with the configured verification method.
  ///
  /// # Errors
  ///
  /// Fails if an unsupported verification method is used, document
  /// serialization fails, or the signature operation fails.
  pub fn sign<X>(&self, that: &mut X) -> Result<()>
  where
    X: Serialize + SetSignature,
  {
    let query: MethodQuery<'_> = self.method.ok_or(Error::QueryMethodNotFound)?;
    let method: &Method<U> = self.document.try_resolve(query)?;
    let fragment: String = method.try_into_fragment()?;

    match method.key_type() {
      MethodType::Ed25519VerificationKey2018 => {
        JcsEd25519::<Ed25519>::create_signature(that, &fragment, self.secret.as_ref())?;
      }
      MethodType::MerkleKeyCollection2021 => {
        let data: Vec<u8> = method.key_data().try_decode()?;

        match MerkleKey::extract_tags(&data)? {
          (MerkleTag::ED25519, MerkleTag::SHA256) => {
            self.merkle_key_sign::<X, Sha256, Ed25519>(that, fragment)?;
          }
          (MerkleTag::ED25519, MerkleTag::BLAKE2B_256) => {
            self.merkle_key_sign::<X, Blake2b256, Ed25519>(that, fragment)?;
          }
          (_, _) => {
            return Err(Error::InvalidMethodType);
          }
        }
      }
    }

    Ok(())
  }

  fn merkle_key_sign<X, D, S>(&self, that: &mut X, fragment: String) -> Result<()>
  where
    X: Serialize + SetSignature,
    D: MerkleDigest,
    S: MerkleSignature + Sign<Secret = [u8]>,
    S::Output: AsRef<[u8]>,
  {
    match self.merkle_key {
      Some((public, proof)) => {
        let proof: &Proof<D> = proof
          .downcast_ref()
          .ok_or(Error::CoreError(CoreError::InvalidKeyFormat))?;

        let skey: SigningKey<'_, D> = SigningKey::from_borrowed(public, self.secret, proof);

        MerkleSigner::<D, S>::create_signature(that, &fragment, &skey)?;

        Ok(())
      }
      None => Err(Error::CoreError(CoreError::InvalidKeyFormat)),
    }
  }
}

// =============================================================================
// Document Verifier - Simplifying Digital Signature Verification Since 2021
// =============================================================================

pub struct DocumentVerifier<'base, T, U, V> {
  document: &'base Document<T, U, V>,
}

impl<'base, T, U, V> DocumentVerifier<'base, T, U, V> {
  pub fn new(document: &'base Document<T, U, V>) -> Self {
    Self { document }
  }
}

impl<T, U, V> DocumentVerifier<'_, T, U, V>
where
  U: Revocation,
{
  /// Verifies the signature of the provided data.
  ///
  /// # Errors
  ///
  /// Fails if an unsupported verification method is used, document
  /// serialization fails, or the verification operation fails.
  pub fn verify<X>(&self, that: &X) -> Result<()>
  where
    X: Serialize + TrySignature,
  {
    let signature: &Signature = that.try_signature()?;
    let method: &Method<U> = self.document.try_resolve(signature)?;
    let data: Vec<u8> = method.key_data().try_decode()?;

    match method.key_type() {
      MethodType::Ed25519VerificationKey2018 => {
        JcsEd25519::<Ed25519>::verify_signature(that, &data)?;
      }
      MethodType::MerkleKeyCollection2021 => match MerkleKey::extract_tags(&data)? {
        (MerkleTag::ED25519, MerkleTag::SHA256) => {
          self.merkle_key_verify::<X, Sha256, Ed25519>(that, method, &data)?;
        }
        (MerkleTag::ED25519, MerkleTag::BLAKE2B_256) => {
          self.merkle_key_verify::<X, Blake2b256, Ed25519>(that, method, &data)?;
        }
        (_, _) => {
          return Err(Error::InvalidMethodType);
        }
      },
    }

    Ok(())
  }

  fn merkle_key_verify<X, D, S>(&self, that: &X, method: &Method<U>, data: &[u8]) -> Result<()>
  where
    X: Serialize + TrySignature,
    D: MerkleDigest,
    S: MerkleSignature + Verify<Public = [u8]>,
  {
    let revocation: Option<BitSet> = method.revocation()?;
    let mut vkey: VerificationKey<'_> = VerificationKey::from_borrowed(data);

    if let Some(revocation) = revocation.as_ref() {
      vkey.set_revocation(revocation);
    }

    MerkleVerifier::<D, S>::verify_signature(that, &vkey)?;

    Ok(())
  }
}
