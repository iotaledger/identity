// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_core::common::Timestamp;
use identity_core::common::Url;
use sd_jwt::Sha256Hasher;
use serde_json::json;

use crate::sd_jwt_vc::tests::TestSigner;
use crate::sd_jwt_vc::SdJwtVcBuilder;

#[tokio::test]
async fn test_sd_jwt_presentation_builder() -> anyhow::Result<()> {
  let credential = SdJwtVcBuilder::new(json!({
    "name": "John Doe",
    "address": {
      "street_address": "A random street",
      "number": "3a"
    },
    "degree": []
  }))?
  .header("kid", "key1")
  .vct("https://example.com/education_credential".parse::<Url>()?)
  .iat(Timestamp::now_utc())
  .iss("https://example.com".parse()?)
  .make_concealable("/address/street_address")?
  .make_concealable("/address")?
  .finish(&TestSigner, "HS256")
  .await?;

  let (concealed_address_credential, conceiled_disclosures) = credential
    .into_presentation(&Sha256Hasher)?
    .conceal("/address")?
    .finish();

  // Object "address" has been omitted from the credential.
  assert!(!concealed_address_credential.claims().contains_key("address"));
  // Concealable "address" and its sub-property "street_address" have both been concealed.
  assert_eq!(
    conceiled_disclosures
      .iter()
      .map(|disclosure| disclosure.claim_name.as_deref().unwrap())
      .collect::<Vec<_>>(),
    vec!["street_address", "address"]
  );

  Ok(())
}
