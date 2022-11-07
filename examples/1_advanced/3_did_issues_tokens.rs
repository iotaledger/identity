// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::ops::Deref;

use examples::create_did;
use examples::random_stronghold_path;
use examples::API_ENDPOINT;
use identity_iota::core::Duration;
use identity_iota::core::Timestamp;
use identity_iota::crypto::KeyPair;
use identity_iota::iota::block::output::unlock_condition::AddressUnlockCondition;
use identity_iota::iota::block::output::unlock_condition::ExpirationUnlockCondition;
use identity_iota::iota::block::output::BasicOutput;
use identity_iota::iota::block::output::BasicOutputBuilder;
use identity_iota::iota::block::output::Output;
use identity_iota::iota::block::output::OutputId;
use identity_iota::iota::IotaDID;
use identity_iota::iota::IotaDocument;
use identity_iota::iota::IotaIdentityClientExt;
use identity_iota::iota::NetworkName;
use iota_client::api_types::response::OutputResponse;
use iota_client::block::address::Address;
use iota_client::block::address::AliasAddress;
use iota_client::block::output::unlock_condition::ImmutableAliasAddressUnlockCondition;
use iota_client::block::output::AliasId;
use iota_client::block::output::AliasOutput;
use iota_client::block::output::AliasOutputBuilder;
use iota_client::block::output::FoundryId;
use iota_client::block::output::FoundryOutput;
use iota_client::block::output::FoundryOutputBuilder;
use iota_client::block::output::NativeToken;
use iota_client::block::output::RentStructure;
use iota_client::block::output::SimpleTokenScheme;
use iota_client::block::output::TokenId;
use iota_client::block::output::TokenScheme;
use iota_client::block::output::UnlockCondition;
use iota_client::block::Block;
use iota_client::secret::stronghold::StrongholdSecretManager;
use iota_client::secret::SecretManager;
use iota_client::Client;
use primitive_types::U256;

/// Demonstrates how an identity can issue and control
/// a Token Foundry and its tokens.
///
/// For this example, we consider the case where an authority issues
/// carbon credits that can be used to pay for carbon emissions or traded on a marketplace.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
  // ===========================================
  // Create the authority's DID and the foundry.
  // ===========================================

  // Create a new client to interact with the IOTA ledger.
  let client: Client = Client::builder().with_primary_node(API_ENDPOINT, None)?.finish()?;

  // Create a new secret manager backed by a Stronghold.
  let mut secret_manager: SecretManager = SecretManager::Stronghold(
    StrongholdSecretManager::builder()
      .password("secure_password")
      .build(random_stronghold_path())?,
  );

  // Create a new DID for the authority.
  let (_, authority_document, _): (Address, IotaDocument, KeyPair) = create_did(&client, &mut secret_manager).await?;
  let authority_did = authority_document.id().clone();

  let rent_structure: RentStructure = client.get_rent_structure()?;

  // We want to update the foundry counter of the authority's Alias Output, so we create an
  // updated version of the output. We pass in the previous document,
  // because we don't want to modify it in this update.
  let authority_document: IotaDocument = client.resolve_did(&authority_did).await?;
  let authority_alias_output: AliasOutput = client.update_did_output(authority_document).await?;

  // We will add one foundry to this Alias Output.
  let authority_alias_output = AliasOutputBuilder::from(&authority_alias_output)
    .with_foundry_counter(1)
    .finish(client.get_token_supply()?)?;

  // Create a token foundry that represents carbon credits.
  let token_scheme = TokenScheme::Simple(SimpleTokenScheme::new(
    U256::from(500_000u32),
    U256::from(0u8),
    U256::from(1_000_000u32),
  )?);

  // Create the identifier of the foundry, which is partially derived from the Alias Address.
  let foundry_id = FoundryId::build(
    &AliasAddress::new(AliasId::from(&authority_did)),
    1,
    token_scheme.kind(),
  );

  // Create the Foundry Output.
  let carbon_credits_foundry: FoundryOutput =
    FoundryOutputBuilder::new_with_minimum_storage_deposit(rent_structure.clone(), 1, token_scheme)?
      // Initially, all carbon credits are owned by the foundry.
      .add_native_token(NativeToken::new(TokenId::from(foundry_id), U256::from(500_000u32))?)
      // The authority is set as the immutable owner.
      .add_unlock_condition(UnlockCondition::ImmutableAliasAddress(
        ImmutableAliasAddressUnlockCondition::new(AliasAddress::new(AliasId::from(&authority_did))),
      ))
      .finish(client.get_token_supply()?)?;

  let carbon_credits_foundry_id: FoundryId = carbon_credits_foundry.id();

  // Publish all outputs.
  let block: Block = client
    .block()
    .with_secret_manager(&secret_manager)
    .with_outputs(vec![authority_alias_output.into(), carbon_credits_foundry.into()])?
    .finish()
    .await?;
  let _ = client.retry_until_included(&block.id(), None, None).await?;

  // ===================================
  // Resolve Foundry and its issuer DID.
  // ===================================

  // Get the latest output that contains the foundry.
  let foundry_output_id: OutputId = client.foundry_output_id(carbon_credits_foundry_id).await?;
  let carbon_credits_foundry: OutputResponse = client.get_output(&foundry_output_id).await?;
  let carbon_credits_foundry: Output =
    Output::try_from_dto(&carbon_credits_foundry.output, client.get_token_supply()?)?;

  let carbon_credits_foundry: FoundryOutput = if let Output::Foundry(foundry_output) = carbon_credits_foundry {
    foundry_output
  } else {
    anyhow::bail!("expected foundry output")
  };

  // Get the Alias Id of the authority that issued the carbon credits foundry.
  let authority_alias_id: &AliasId = carbon_credits_foundry.alias_address().alias_id();

  // Reconstruct the DID of the authority.
  let network: NetworkName = client.network_name().await?;
  let authority_did: IotaDID = IotaDID::new(authority_alias_id.deref(), &network);

  // Resolve the authority's DID document.
  let authority_document: IotaDocument = client.resolve_did(&authority_did).await?;

  println!("The authority's DID is: {authority_document:#}");

  // =========================================================
  // Transfer 1000 carbon credits to the address of a company.
  // =========================================================

  // Create a new address that represents the company.
  let company_address: Address = client.get_addresses(&secret_manager).with_range(1..2).get_raw().await?[0];

  // Create the timestamp at which the basic output will expire.
  let tomorrow: u32 = Timestamp::now_utc()
    .checked_add(Duration::seconds(60 * 60 * 24))
    .ok_or_else(|| anyhow::anyhow!("timestamp overflow"))?
    .to_unix()
    .try_into()
    .map_err(|err| anyhow::anyhow!("cannot fit timestamp into u32: {err}"))?;

  // Create a basic output containing our carbon credits that we'll send to the company's address.
  let basic_output: BasicOutput = BasicOutputBuilder::new_with_minimum_storage_deposit(rent_structure)?
    .add_unlock_condition(UnlockCondition::Address(AddressUnlockCondition::new(company_address)))
    .add_native_token(NativeToken::new(carbon_credits_foundry.token_id(), U256::from(1000))?)
    // Allow the company to claim the credits within 24 hours by using an expiration unlock condition.
    .add_unlock_condition(UnlockCondition::Expiration(ExpirationUnlockCondition::new(
      Address::Alias(AliasAddress::new(*authority_alias_id)),
      tomorrow,
    )?))
    .finish(client.get_token_supply()?)?;

  // Reduce the carbon credits in the foundry by the amount that is sent to the company.
  let carbon_credits_foundry = FoundryOutputBuilder::from(&carbon_credits_foundry)
    .with_native_tokens(vec![NativeToken::new(
      carbon_credits_foundry.token_id(),
      U256::from(499_000u32),
    )?])
    .finish(client.get_token_supply()?)?;

  // Publish the output, transferring the carbon credits.
  let block: Block = client
    .block()
    .with_secret_manager(&secret_manager)
    .with_outputs(vec![basic_output.into(), carbon_credits_foundry.into()])?
    .finish()
    .await?;
  let _ = client.retry_until_included(&block.id(), None, None).await?;

  println!("Sent carbon credits to {}", company_address.to_bech32(network.as_ref()));

  Ok(())
}
