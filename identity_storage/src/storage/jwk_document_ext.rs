// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;

use super::JwkStorageDocumentError as Error;
use super::JwsSignatureOptions;
use super::Storage;

use crate::key_id_storage::KeyIdStorage;
use crate::key_id_storage::KeyIdStorageResult;
use crate::key_id_storage::MethodDigest;
use crate::key_storage::JwkGenOutput;
use crate::key_storage::JwkStorage;
use crate::key_storage::KeyId;
use crate::key_storage::KeyStorageResult;
use crate::key_storage::KeyType;

use async_trait::async_trait;
use identity_core::common::Object;
use identity_credential::credential::Credential;
use identity_credential::credential::CredentialV2;
use identity_credential::credential::Jws;
use identity_credential::credential::Jwt;
use identity_credential::credential::JwtVcV2;
use identity_credential::presentation::JwtPresentationOptions;
use identity_credential::presentation::Presentation;
use identity_did::DIDUrl;
use identity_document::document::CoreDocument;
use identity_verification::jose::jws::CompactJwsEncoder;
use identity_verification::jose::jws::CompactJwsEncodingOptions;
use identity_verification::jose::jws::JwsAlgorithm;
use identity_verification::jose::jws::JwsHeader;
use identity_verification::jws::CharSet;
use identity_verification::MethodData;
use identity_verification::MethodScope;
use identity_verification::VerificationMethod;
use serde::de::DeserializeOwned;
use serde::Serialize;

/// Alias for a `Result` with the error type [`Error`].
pub type StorageResult<T> = Result<T, Error>;

/// Extension trait for JWK-based operations on DID documents.
///
/// This trait is deliberately sealed and cannot be implemented by external crates.
/// The trait only exists as an extension of existing DID documents implemented in
/// dependent crates. Because those crates cannot also depend on this crate,
/// the extension trait is necessary. External crates however should simply wrap the methods
/// on the trait if they wish to reexport them on their DID document type.
/// This also allows them to use their own error type on those methods.
#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
pub trait JwkDocumentExt: private::Sealed {
  /// Generate new key material in the given `storage` and insert a new verification method with the corresponding
  /// public key material into the DID document.
  ///
  /// - If no fragment is given the `kid` of the generated JWK is used, if it is set, otherwise an error is returned.
  /// - The `key_type` must be compatible with the given `storage`. [`Storage`]s are expected to export key type
  ///   constants for that use case.
  ///
  /// The fragment of the generated method is returned.
  async fn generate_method<K, I>(
    &mut self,
    storage: &Storage<K, I>,
    key_type: KeyType,
    alg: JwsAlgorithm,
    fragment: Option<&str>,
    scope: MethodScope,
  ) -> StorageResult<String>
  where
    K: JwkStorage,
    I: KeyIdStorage;

  /// Remove the method identified by the given `id` from the document and delete the corresponding key material in
  /// the given `storage`.
  ///
  /// ## Warning
  ///
  /// This will delete the key material permanently and irrecoverably.
  async fn purge_method<K, I>(&mut self, storage: &Storage<K, I>, id: &DIDUrl) -> StorageResult<()>
  where
    K: JwkStorage,
    I: KeyIdStorage;

  /// Sign the arbitrary `payload` according to `options` with the storage backed private key corresponding to the
  /// public key material in the verification method identified by the given `fragment.
  ///
  /// Upon success a string representing a JWS encoded according to the Compact JWS Serialization format is returned.
  /// See [RFC7515 section 3.1](https://www.rfc-editor.org/rfc/rfc7515#section-3.1).
  async fn create_jws<K, I>(
    &self,
    storage: &Storage<K, I>,
    fragment: &str,
    payload: &[u8],
    options: &JwsSignatureOptions,
  ) -> StorageResult<Jws>
  where
    K: JwkStorage,
    I: KeyIdStorage;

  /// Produces a JWT where the payload is produced from the given `credential`
  /// in accordance with either [VC Data Model v1.1](https://www.w3.org/TR/vc-data-model/#json-web-token)
  /// or [VC Data Model v2.0](https://www.w3.org/TR/vc-data-model-2.0/).
  ///
  /// Unless the `kid` is explicitly set in the options, the `kid` in the protected header is the `id`
  /// of the method identified by `fragment` and the JWS signature will be produced by the corresponding
  /// private key backed by the `storage` in accordance with the passed `options`.
  ///
  /// The `custom_claims` can be used to set additional claims on the resulting JWT.
  async fn create_credential_jwt<K, I, T>(
    &self,
    credential: &Credential<T>,
    storage: &Storage<K, I>,
    fragment: &str,
    options: &JwsSignatureOptions,
    custom_claims: Option<Object>,
  ) -> StorageResult<Jwt>
  where
    K: JwkStorage,
    I: KeyIdStorage,
    T: ToOwned<Owned = T> + Serialize + DeserializeOwned + Sync;

  /// Returns a JWT containing the given VC Data Model 2.0 `credential` in accordance with the mediatype
  /// `application/vc+jwt` defined in [Securing Verifiable Credentials using JOSE and COSE](https://www.w3.org/TR/vc-jose-cose/#securing-with-jose).
  ///
  /// Unless the `kid` is explicitly set in the options, the `kid` in the protected header is the `id`
  /// of the method identified by `fragment` and the JWS signature will be produced by the corresponding
  /// private key backed by the `storage` in accordance with the passed `options`.
  async fn create_credential_v2_jwt<K, I, T>(
    &self,
    credential: &CredentialV2<T>,
    storage: &Storage<K, I>,
    fragment: &str,
    options: &JwsSignatureOptions,
  ) -> StorageResult<JwtVcV2>
  where
    K: JwkStorage,
    I: KeyIdStorage,
    T: Clone + Serialize + Sync;

  /// Produces a JWT where the payload is produced from the given `presentation`
  /// in accordance with [VC Data Model v1.1](https://www.w3.org/TR/vc-data-model/#json-web-token)
  /// or with [VC Data Model v2.0](https://www.w3.org/TR/vc-jose-cose/#securing-vps-with-jose) depending
  /// on the presentation's context.
  ///
  /// Unless the `kid` is explicitly set in the options, the `kid` in the protected header is the `id`
  /// of the method identified by `fragment` and the JWS signature will be produced by the corresponding
  /// private key backed by the `storage` in accordance with the passed `options`.
  async fn create_presentation_jwt<K, I, CRED, T>(
    &self,
    presentation: &Presentation<CRED, T>,
    storage: &Storage<K, I>,
    fragment: &str,
    signature_options: &JwsSignatureOptions,
    presentation_options: &JwtPresentationOptions,
  ) -> StorageResult<Jwt>
  where
    K: JwkStorage,
    I: KeyIdStorage,
    T: Clone + Serialize + DeserializeOwned + Sync,
    CRED: ToOwned<Owned = CRED> + Serialize + DeserializeOwned + Clone + Sync;
}

mod private {
  pub trait Sealed {}
  impl Sealed for identity_document::document::CoreDocument {}
  #[cfg(feature = "iota-document")]
  impl Sealed for identity_iota_core::IotaDocument {}
}

// ====================================================================================================================
// Implementation
// ====================================================================================================================

// We want to implement this trait both for CoreDocument and IotaDocument, but the methods that take `&mut self` cannot
// be implemented in terms of &mut CoreDocument for IotaDocument. To work around this limitation we use macros to avoid
// copious amounts of repetition.
// NOTE: If such use of macros becomes very common it is probably better to use the duplicate crate: https://docs.rs/duplicate/latest/duplicate/
macro_rules! generate_method_for_document_type {
  ($t:ty, $a:ty, $k:path, $f:path, $name:ident) => {
    async fn $name<K, I>(
      document: &mut $t,
      storage: &Storage<K, I>,
      key_type: KeyType,
      alg: $a,
      fragment: Option<&str>,
      scope: MethodScope,
    ) -> StorageResult<String>
    where
      K: $k,
      I: KeyIdStorage,
    {
      let JwkGenOutput { key_id, jwk } = $f(storage.key_storage(), key_type, alg)
        .await
        .map_err(Error::KeyStorageError)?;

      // Produce a new verification method containing the generated JWK. If this operation fails we handle the error
      // by attempting to revert key generation before returning an error.
      let method: VerificationMethod = {
        match VerificationMethod::new_from_jwk(document.id().clone(), jwk, fragment)
          .map_err(Error::VerificationMethodConstructionError)
        {
          Ok(method) => method,
          Err(source) => {
            return Err(try_undo_key_generation(storage, &key_id, source).await);
          }
        }
      };

      // Extract data from method before inserting it into the DID document.
      let method_digest: MethodDigest = MethodDigest::new(&method).map_err(Error::MethodDigestConstructionError)?;
      let method_id: DIDUrl = method.id().clone();

      // The fragment is always set on a method, so this error will never occur.
      let fragment: String = method_id
        .fragment()
        .ok_or(identity_verification::Error::MissingIdFragment)
        .map_err(Error::VerificationMethodConstructionError)?
        .to_owned();

      // Insert method into document and handle error upon failure.
      if let Err(error) = document
        .insert_method(method, scope)
        .map_err(|_| Error::FragmentAlreadyExists)
      {
        return Err(try_undo_key_generation(storage, &key_id, error).await);
      };

      // Insert the generated `KeyId` into storage under the computed method digest and handle the error if the
      // operation fails.
      if let Err(error) = <I as KeyIdStorage>::insert_key_id(&storage.key_id_storage(), method_digest, key_id.clone())
        .await
        .map_err(Error::KeyIdStorageError)
      {
        // Remove the method from the document as it can no longer be used.
        let _ = document.remove_method(&method_id);
        return Err(try_undo_key_generation(storage, &key_id, error).await);
      }

      Ok(fragment)
    }
  };
}

macro_rules! purge_method_for_document_type {
  ($t:ty, $name:ident) => {
    async fn $name<K, I>(document: &mut $t, storage: &Storage<K, I>, id: &DIDUrl) -> StorageResult<()>
    where
      K: JwkStorage,
      I: KeyIdStorage,
    {
      let (method, scope) = document.remove_method_and_scope(id).ok_or(Error::MethodNotFound)?;

      // Obtain method digest and handle error if this operation fails.
      let method_digest: MethodDigest = match MethodDigest::new(&method).map_err(Error::MethodDigestConstructionError) {
        Ok(digest) => digest,
        Err(error) => {
          // Revert state by reinserting the method before returning the error.
          let _ = document.insert_method(method, scope);
          return Err(error);
        }
      };

      // Obtain key id and handle error upon failure.
      let key_id: KeyId = match <I as KeyIdStorage>::get_key_id(&storage.key_id_storage(), &method_digest)
        .await
        .map_err(Error::KeyIdStorageError)
      {
        Ok(key_id) => key_id,
        Err(error) => {
          // Reinsert method before returning.
          let _ = document.insert_method(method, scope);
          return Err(error);
        }
      };

      // Delete key and key id concurrently.
      let key_deletion_fut = <K as JwkStorage>::delete(&storage.key_storage(), &key_id);
      let key_id_deletion_fut = <I as KeyIdStorage>::delete_key_id(&storage.key_id_storage(), &method_digest);
      let (key_deletion_result, key_id_deletion_result): (KeyStorageResult<()>, KeyIdStorageResult<()>) =
        futures::join!(key_deletion_fut, key_id_deletion_fut);

      // Check for any errors that may have occurred. Unfortunately this is somewhat involved.
      match (key_deletion_result, key_id_deletion_result) {
        (Ok(_), Ok(_)) => Ok(()),
        (Ok(_), Err(key_id_deletion_error)) => {
          // Cannot attempt to revert this operation as the JwkStorage may not return the same KeyId when
          // JwkStorage::insert is called.
          Err(Error::UndoOperationFailed {
            message: format!(
              "cannot undo key deletion: this results in a stray key id stored under packed method digest: {:?}",
              &method_digest.pack()
            ),
            source: Box::new(Error::KeyIdStorageError(key_id_deletion_error)),
            undo_error: None,
          })
        }
        (Err(key_deletion_error), Ok(_)) => {
          // Attempt to revert: Reinsert key id and method if possible.
          if let Err(key_id_insertion_error) =
            <I as KeyIdStorage>::insert_key_id(&storage.key_id_storage(), (&method_digest).clone(), key_id.clone())
              .await
              .map_err(Error::KeyIdStorageError)
          {
            Err(Error::UndoOperationFailed {
              message: format!("cannot revert key id deletion: this results in stray key with key id: {key_id}"),
              source: Box::new(Error::KeyStorageError(key_deletion_error)),
              undo_error: Some(Box::new(key_id_insertion_error)),
            })
          } else {
            // KeyId reinsertion succeeded. Now reinsert method.
            let _ = document.insert_method(method, scope);
            Err(Error::KeyStorageError(key_deletion_error))
          }
        }
        (Err(_key_deletion_error), Err(key_id_deletion_error)) => {
          // We assume this means nothing got deleted. Reinsert the method and return one of the errors (perhaps
          // key_id_deletion_error as we really expect the key id storage to work as expected at this point).
          let _ = document.insert_method(method, scope);
          Err(Error::KeyIdStorageError(key_id_deletion_error))
        }
      }
    }
  };
}

// ====================================================================================================================
// CoreDocument
// ====================================================================================================================

generate_method_for_document_type!(
  CoreDocument,
  JwsAlgorithm,
  JwkStorage,
  JwkStorage::generate,
  generate_method_core_document
);
purge_method_for_document_type!(CoreDocument, purge_method_core_document);

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl JwkDocumentExt for CoreDocument {
  async fn generate_method<K, I>(
    &mut self,
    storage: &Storage<K, I>,
    key_type: KeyType,
    alg: JwsAlgorithm,
    fragment: Option<&str>,
    scope: MethodScope,
  ) -> StorageResult<String>
  where
    K: JwkStorage,
    I: KeyIdStorage,
  {
    generate_method_core_document(self, storage, key_type, alg, fragment, scope).await
  }

  async fn purge_method<K, I>(&mut self, storage: &Storage<K, I>, id: &DIDUrl) -> StorageResult<()>
  where
    K: JwkStorage,
    I: KeyIdStorage,
  {
    purge_method_core_document(self, storage, id).await
  }

  async fn create_jws<K, I>(
    &self,
    storage: &Storage<K, I>,
    fragment: &str,
    payload: &[u8],
    options: &JwsSignatureOptions,
  ) -> StorageResult<Jws>
  where
    K: JwkStorage,
    I: KeyIdStorage,
  {
    // Obtain the method corresponding to the given fragment.
    let method: &VerificationMethod = self.resolve_method(fragment, None).ok_or(Error::MethodNotFound)?;
    let MethodData::PublicKeyJwk(ref jwk) = method.data() else {
      return Err(Error::NotPublicKeyJwk);
    };

    // Extract JwsAlgorithm.
    let alg: JwsAlgorithm = jwk
      .alg()
      .unwrap_or("")
      .parse()
      .map_err(|_| Error::InvalidJwsAlgorithm)?;

    // Create JWS header in accordance with options.
    let header: JwsHeader = {
      let mut header = JwsHeader::new();

      header.set_alg(alg);
      if let Some(custom) = &options.custom_header_parameters {
        header.set_custom(custom.clone())
      }

      if let Some(ref kid) = options.kid {
        header.set_kid(kid.clone());
      } else {
        header.set_kid(method.id().to_string());
      }

      if options.attach_jwk {
        header.set_jwk(jwk.clone())
      };

      if let Some(b64) = options.b64 {
        // Follow recommendation in https://datatracker.ietf.org/doc/html/rfc7797#section-7.
        if !b64 {
          header.set_b64(b64);
          header.set_crit(["b64"]);
        }
      };

      if let Some(typ) = &options.typ {
        header.set_typ(typ.clone())
      } else {
        // https://www.w3.org/TR/vc-data-model/#jwt-encoding
        header.set_typ("JWT")
      }

      if let Some(cty) = &options.cty {
        header.set_cty(cty.clone())
      };

      if let Some(url) = &options.url {
        header.set_url(url.clone())
      };

      if let Some(nonce) = &options.nonce {
        header.set_nonce(nonce.clone())
      };

      header
    };

    // Get the key identifier corresponding to the given method from the KeyId storage.
    let method_digest: MethodDigest = MethodDigest::new(method).map_err(Error::MethodDigestConstructionError)?;
    let key_id = <I as KeyIdStorage>::get_key_id(storage.key_id_storage(), &method_digest)
      .await
      .map_err(Error::KeyIdStorageError)?;

    // Extract Compact JWS encoding options.
    let encoding_options: CompactJwsEncodingOptions = if !options.detached_payload {
      // We use this as a default and don't provide the extra UrlSafe check for now.
      // Applications that require such checks can easily do so after JWS creation.
      CompactJwsEncodingOptions::NonDetached {
        charset_requirements: CharSet::Default,
      }
    } else {
      CompactJwsEncodingOptions::Detached
    };

    let jws_encoder: CompactJwsEncoder<'_> = CompactJwsEncoder::new_with_options(payload, &header, encoding_options)
      .map_err(|err| Error::EncodingError(err.into()))?;
    let signature = <K as JwkStorage>::sign(storage.key_storage(), &key_id, jws_encoder.signing_input(), jwk)
      .await
      .map_err(Error::KeyStorageError)?;
    Ok(Jws::new(jws_encoder.into_jws(&signature)))
  }

  async fn create_credential_jwt<K, I, T>(
    &self,
    credential: &Credential<T>,
    storage: &Storage<K, I>,
    fragment: &str,
    options: &JwsSignatureOptions,
    custom_claims: Option<Object>,
  ) -> StorageResult<Jwt>
  where
    K: JwkStorage,
    I: KeyIdStorage,
    T: ToOwned<Owned = T> + Serialize + DeserializeOwned + Sync,
  {
    if options.detached_payload {
      return Err(Error::EncodingError(Box::<dyn std::error::Error + Send + Sync>::from(
        "cannot use detached payload for credential signing",
      )));
    }

    if !options.b64.unwrap_or(true) {
      // JWTs should not have `b64` set per https://datatracker.ietf.org/doc/html/rfc7797#section-7.
      return Err(Error::EncodingError(Box::<dyn std::error::Error + Send + Sync>::from(
        "cannot use `b64 = false` with JWTs",
      )));
    }

    let payload = credential
      .serialize_jwt(custom_claims)
      .map_err(Error::ClaimsSerializationError)?;
    self
      .create_jws(storage, fragment, payload.as_bytes(), options)
      .await
      .map(|jws| Jwt::new(jws.into()))
  }

  async fn create_credential_v2_jwt<K, I, T>(
    &self,
    credential: &CredentialV2<T>,
    storage: &Storage<K, I>,
    fragment: &str,
    options: &JwsSignatureOptions,
  ) -> StorageResult<JwtVcV2>
  where
    K: JwkStorage,
    I: KeyIdStorage,
    T: Clone + Serialize + Sync,
  {
    if options.detached_payload {
      return Err(Error::EncodingError(
        "cannot use detached payload for credential signing".into(),
      ));
    }

    if !options.b64.unwrap_or(true) {
      // JWTs should not have `b64` set per https://datatracker.ietf.org/doc/html/rfc7797#section-7.
      return Err(Error::EncodingError("cannot use `b64 = false` with JWTs".into()));
    }

    let payload = credential
      .serialize_jwt(None)
      .map_err(Error::ClaimsSerializationError)?;

    // Ensure the correct `typ` header for VC Data Model 2.0 JWTs.
    let mut options = Cow::Borrowed(options);
    if options.typ.as_deref() != Some("vc+jwt") {
      options.to_mut().typ = Some("vc+jwt".to_owned());
    }

    self
      .create_jws(storage, fragment, payload.as_bytes(), &options)
      .await
      .map(|jws| JwtVcV2::parse(jws.as_str()).expect("valid JWT string containing a VC v2.0"))
  }

  async fn create_presentation_jwt<K, I, CRED, T>(
    &self,
    presentation: &Presentation<CRED, T>,
    storage: &Storage<K, I>,
    fragment: &str,
    jws_options: &JwsSignatureOptions,
    jwt_options: &JwtPresentationOptions,
  ) -> StorageResult<Jwt>
  where
    K: JwkStorage,
    I: KeyIdStorage,
    T: Clone + Serialize + DeserializeOwned + Sync,
    CRED: ToOwned<Owned = CRED> + Serialize + DeserializeOwned + Clone + Sync,
  {
    if jws_options.detached_payload {
      return Err(Error::EncodingError(
        "cannot use detached payload for presentation signing".into(),
      ));
    }

    if !jws_options.b64.unwrap_or(true) {
      // JWTs should not have `b64` set per https://datatracker.ietf.org/doc/html/rfc7797#section-7.
      return Err(Error::EncodingError("cannot use `b64 = false` with JWTs".into()));
    }
    let payload = presentation
      .serialize_jwt(jwt_options)
      .map_err(Error::ClaimsSerializationError)?;

    let mut jws_options = Cow::Borrowed(jws_options);
    // Set JWS headers in accordance with the JOSE specification for VPs that use VC Data Model 2.0.
    // See https://www.w3.org/TR/vc-jose-cose/#securing-vps-with-jose.
    if presentation.is_v2() {
      jws_options.to_mut().typ = Some("vp+jwt".to_owned());
    }

    self
      .create_jws(storage, fragment, payload.as_bytes(), &jws_options)
      .await
      .map(|jws| Jwt::new(jws.into()))
  }
}

/// Attempt to revert key generation. If this succeeds the original `source_error` is returned,
/// otherwise [`JwkStorageDocumentError::UndoOperationFailed`] is returned with the `source_error` attached as
/// `source`.
pub(crate) async fn try_undo_key_generation<K, I>(storage: &Storage<K, I>, key_id: &KeyId, source_error: Error) -> Error
where
  K: JwkStorage,
  I: KeyIdStorage,
{
  // Undo key generation
  if let Err(err) = <K as JwkStorage>::delete(storage.key_storage(), key_id).await {
    Error::UndoOperationFailed {
      message: format!("unable to delete stray key with id: {}", &key_id),
      source: Box::new(source_error),
      undo_error: Some(Box::new(Error::KeyStorageError(err))),
    }
  } else {
    source_error
  }
}

// ====================================================================================================================
// IotaDocument
// ====================================================================================================================
#[cfg(feature = "iota-document")]
mod iota_document {
  use super::*;
  use identity_credential::credential::{Credential, Jwt};
  use identity_iota_core::IotaDocument;

  generate_method_for_document_type!(
    IotaDocument,
    JwsAlgorithm,
    JwkStorage,
    JwkStorage::generate,
    generate_method_iota_document
  );
  purge_method_for_document_type!(IotaDocument, purge_method_iota_document);

  #[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
  #[cfg_attr(feature = "send-sync-storage", async_trait)]
  impl JwkDocumentExt for IotaDocument {
    async fn generate_method<K, I>(
      &mut self,
      storage: &Storage<K, I>,
      key_type: KeyType,
      alg: JwsAlgorithm,
      fragment: Option<&str>,
      scope: MethodScope,
    ) -> StorageResult<String>
    where
      K: JwkStorage,
      I: KeyIdStorage,
    {
      generate_method_iota_document(self, storage, key_type, alg, fragment, scope).await
    }

    async fn purge_method<K, I>(&mut self, storage: &Storage<K, I>, id: &DIDUrl) -> StorageResult<()>
    where
      K: JwkStorage,
      I: KeyIdStorage,
    {
      purge_method_iota_document(self, storage, id).await
    }

    async fn create_jws<K, I>(
      &self,
      storage: &Storage<K, I>,
      fragment: &str,
      payload: &[u8],
      options: &JwsSignatureOptions,
    ) -> StorageResult<Jws>
    where
      K: JwkStorage,
      I: KeyIdStorage,
    {
      self
        .core_document()
        .create_jws(storage, fragment, payload, options)
        .await
    }

    async fn create_credential_jwt<K, I, T>(
      &self,
      credential: &Credential<T>,
      storage: &Storage<K, I>,
      fragment: &str,
      options: &JwsSignatureOptions,
      custom_claims: Option<Object>,
    ) -> StorageResult<Jwt>
    where
      K: JwkStorage,
      I: KeyIdStorage,
      T: ToOwned<Owned = T> + Serialize + DeserializeOwned + Sync,
    {
      self
        .core_document()
        .create_credential_jwt(credential, storage, fragment, options, custom_claims)
        .await
    }
    async fn create_presentation_jwt<K, I, CRED, T>(
      &self,
      presentation: &Presentation<CRED, T>,
      storage: &Storage<K, I>,
      fragment: &str,
      options: &JwsSignatureOptions,
      jwt_options: &JwtPresentationOptions,
    ) -> StorageResult<Jwt>
    where
      K: JwkStorage,
      I: KeyIdStorage,
      T: Clone + Serialize + DeserializeOwned + Sync,
      CRED: ToOwned<Owned = CRED> + Serialize + DeserializeOwned + Clone + Sync,
    {
      self
        .core_document()
        .create_presentation_jwt(presentation, storage, fragment, options, jwt_options)
        .await
    }

    async fn create_credential_v2_jwt<K, I, T>(
      &self,
      credential: &CredentialV2<T>,
      storage: &Storage<K, I>,
      fragment: &str,
      options: &JwsSignatureOptions,
    ) -> StorageResult<JwtVcV2>
    where
      K: JwkStorage,
      I: KeyIdStorage,
      T: Clone + Serialize + Sync,
    {
      self
        .core_document()
        .create_credential_v2_jwt(credential, storage, fragment, options)
        .await
    }
  }
}
