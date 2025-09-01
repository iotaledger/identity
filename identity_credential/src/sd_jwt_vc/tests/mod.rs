// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use async_trait::async_trait;
use identity_core::convert::Base;
use identity_core::convert::BaseEncoding;
use identity_verification::jwk::Jwk;
use identity_verification::jwk::JwkParamsOct;
use identity_verification::jws::JwsVerifier;
use josekit::jws::JwsHeader;
use josekit::jws::HS256;
use josekit::jwt::JwtPayload;
use josekit::jwt::{self};
use sd_jwt_payload_rework::JsonObject;
use sd_jwt_payload_rework::JwsSigner;
use serde::Serialize;
use serde_json::Value;

use super::resolver;
use super::Resolver;

mod presentation;
mod validation;

pub(crate) const ISSUER_SECRET: &[u8] = b"0123456789ABCDEF0123456789ABCDEF";

/// A JWS signer that uses HS256 with a static secret string.
pub(crate) struct TestSigner;

pub(crate) fn signer_secret_jwk() -> Jwk {
  let mut params = JwkParamsOct::new();
  params.k = BaseEncoding::encode(ISSUER_SECRET, Base::Base64Url);
  let mut jwk = Jwk::from_params(params);
  jwk.set_kid("key1");

  jwk
}

#[async_trait]
impl JwsSigner for TestSigner {
  type Error = josekit::JoseError;
  async fn sign(&self, header: &JsonObject, payload: &JsonObject) -> std::result::Result<Vec<u8>, Self::Error> {
    let signer = HS256.signer_from_bytes(ISSUER_SECRET)?;
    let header = JwsHeader::from_map(header.clone())?;
    let payload = JwtPayload::from_map(payload.clone())?;
    let jws = jwt::encode_with_signer(&payload, &header, &signer)?;

    Ok(jws.into_bytes())
  }
}

#[derive(Default, Debug, Clone)]
pub(crate) struct TestResolver(HashMap<String, Vec<u8>>);

impl TestResolver {
  pub(crate) fn new() -> Self {
    Self::default()
  }

  pub(crate) fn insert_resource<K, V>(&mut self, id: K, value: V)
  where
    K: ToString,
    V: Serialize,
  {
    let value = serde_json::to_vec(&value).unwrap();
    self.0.insert(id.to_string(), value);
  }
}

#[async_trait]
impl<I> Resolver<I, Vec<u8>> for TestResolver
where
  I: ToString + Sync,
{
  async fn resolve(&self, id: &I) -> Result<Vec<u8>, resolver::Error> {
    let id = id.to_string();
    self.0.get(&id).cloned().ok_or_else(|| resolver::Error::NotFound(id))
  }
}

#[async_trait]
impl<I> Resolver<I, Value> for TestResolver
where
  I: ToString + Sync,
{
  async fn resolve(&self, id: &I) -> Result<Value, resolver::Error> {
    let id = id.to_string();
    self
      .0
      .get(&id)
      .ok_or_else(|| resolver::Error::NotFound(id))
      .and_then(|bytes| serde_json::from_slice(bytes).map_err(|e| resolver::Error::ParsingFailure(e.into())))
  }
}

pub(crate) struct TestJwsVerifier;

impl JwsVerifier for TestJwsVerifier {
  fn verify(
    &self,
    input: identity_verification::jws::VerificationInput,
    public_key: &Jwk,
  ) -> Result<(), identity_verification::jws::SignatureVerificationError> {
    let key = serde_json::to_value(public_key.clone())
      .and_then(serde_json::from_value)
      .unwrap();
    let verifier = HS256.verifier_from_jwk(&key).unwrap();
    verifier.verify(&input.signing_input, &input.decoded_signature).unwrap();

    Ok(())
  }
}
