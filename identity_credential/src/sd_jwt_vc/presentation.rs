// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::Error;
use super::Result;
use super::SdJwtVc;
use super::SdJwtVcClaims;

use sd_jwt_payload_rework::Disclosure;
use sd_jwt_payload_rework::Hasher;
use sd_jwt_payload_rework::KeyBindingJwt;
use sd_jwt_payload_rework::SdJwtPresentationBuilder;

/// Builder structure to create an SD-JWT VC presentation.
/// It allows users to conceal claims and attach a key binding JWT.
#[derive(Debug, Clone)]
pub struct SdJwtVcPresentationBuilder {
  vc_claims: SdJwtVcClaims,
  builder: SdJwtPresentationBuilder,
}

impl SdJwtVcPresentationBuilder {
  /// Prepare a presentation for a given [`SdJwtVc`].
  pub fn new(token: SdJwtVc, hasher: &dyn Hasher) -> Result<Self> {
    let SdJwtVc {
      sd_jwt,
      parsed_claims: vc_claims,
    } = token;
    let builder = sd_jwt.into_presentation(hasher).map_err(Error::SdJwt)?;

    Ok(Self { vc_claims, builder })
  }
  /// Removes the disclosure for the property at `path`, conceiling it.
  ///
  /// ## Notes
  /// - When concealing a claim more than one disclosure may be removed: the disclosure for the claim itself and the
  ///   disclosures for any concealable sub-claim.
  pub fn conceal(mut self, path: &str) -> Result<Self> {
    self.builder = self.builder.conceal(path).map_err(Error::SdJwt)?;
    Ok(self)
  }

  /// Adds a [`KeyBindingJwt`] to this [`SdJwtVc`]'s presentation.
  pub fn attach_key_binding_jwt(mut self, kb_jwt: KeyBindingJwt) -> Self {
    self.builder = self.builder.attach_key_binding_jwt(kb_jwt);
    self
  }

  /// Returns the resulting [`SdJwtVc`] together with all removed disclosures.
  pub fn finish(self) -> Result<(SdJwtVc, Vec<Disclosure>)> {
    let (sd_jwt, disclosures) = self.builder.finish()?;
    Ok((SdJwtVc::new(sd_jwt, self.vc_claims), disclosures))
  }
}
