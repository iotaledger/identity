// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::ops::Deref;

use anyhow::Context as _;
use identity_credential::credential::Credential;
use identity_credential::credential::Jwt;
use identity_credential::credential::JwtCredential;
use identity_jose::jwt::JwtHeader;
use identity_jose::jwu;
use iota_interaction::types::base_types::ObjectID;
use iota_interaction::IotaKeySignature;
use iota_interaction::IotaVerifiableCredential;
use iota_interaction::OptionalSync;
use itertools::Itertools;
use product_common::core_client::CoreClientReadOnly;
use secret_storage::Signer;

use crate::rebased::client::IdentityClient;
use crate::rebased::client::IdentityClientReadOnly;

use super::AuthenticatedAsset;
use super::AuthenticatedAssetBuilder;

/// A publicly available verifiable credential.
#[derive(Debug, Clone)]
pub struct PublicAvailableVC {
  asset: AuthenticatedAsset<IotaVerifiableCredential>,
  credential: Credential,
}

impl Deref for PublicAvailableVC {
  type Target = Credential;
  fn deref(&self) -> &Self::Target {
    &self.credential
  }
}

impl PublicAvailableVC {
  /// Get the ID of the asset.
  pub fn object_id(&self) -> ObjectID {
    self.asset.id()
  }

  /// Get the JWT of the credential.
  pub fn jwt(&self) -> Jwt {
    String::from_utf8(self.asset.content().data().clone())
      .map(Jwt::new)
      .expect("JWT is valid UTF8")
  }

  /// Create a new publicly available VC.
  ///
  /// # Returns
  /// A new `PublicAvailableVC`.
  pub async fn new<S>(jwt: Jwt, gas_budget: Option<u64>, client: &IdentityClient<S>) -> Result<Self, anyhow::Error>
  where
    S: Signer<IotaKeySignature> + OptionalSync,
  {
    let jwt_bytes = String::from(jwt).into_bytes();
    let credential = parse_jwt_credential(&jwt_bytes)?;
    let tx_builder = AuthenticatedAssetBuilder::new(IotaVerifiableCredential::new(jwt_bytes))
      .transferable(false)
      .mutable(true)
      .deletable(true)
      .finish(client);

    let tx_builder = if let Some(gas_budget) = gas_budget {
      tx_builder.with_gas_budget(gas_budget)
    } else {
      tx_builder
    };

    let asset = tx_builder.build_and_execute(client).await?.output;

    Ok(Self { credential, asset })
  }

  /// Get a publicly available VC by its ID.
  pub async fn get_by_id(id: ObjectID, client: &IdentityClientReadOnly) -> Result<Self, crate::rebased::Error> {
    let asset = client
      .get_object_by_id::<AuthenticatedAsset<IotaVerifiableCredential>>(id)
      .await?;

    Self::try_from_asset(asset).map_err(|e| {
      crate::rebased::Error::ObjectLookup(format!(
        "object at address {id} is not a valid publicly available VC: {e}"
      ))
    })
  }

  fn try_from_asset(asset: AuthenticatedAsset<IotaVerifiableCredential>) -> Result<Self, anyhow::Error> {
    let credential = parse_jwt_credential(asset.content().data())?;
    Ok(Self { asset, credential })
  }
}

fn parse_jwt_credential(bytes: &[u8]) -> Result<Credential, anyhow::Error> {
  let [header, payload, _signature]: [Vec<u8>; 3] = bytes
    .split(|c| *c == b'.')
    .map(jwu::decode_b64)
    .try_collect::<_, Vec<_>, _>()?
    .try_into()
    .map_err(|_| anyhow::anyhow!("invalid JWT"))?;
  let _header = serde_json::from_slice::<JwtHeader>(&header)?;
  let credential_claims = serde_json::from_slice::<JwtCredential>(&payload)?;
  credential_claims.try_into().context("invalid jwt credential claims")
}
