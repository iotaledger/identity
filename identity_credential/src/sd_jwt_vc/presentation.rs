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
      mut sd_jwt,
      parsed_claims: mut vc_claims,
    } = token;
    // Make sure to set the parsed claims back into the SD-JWT Token.
    // The reason we do this is to make sure that the underlying SdJwtPresetationBuilder
    // that operates on the wrapped SdJwt token can handle the claims.
    std::mem::swap(sd_jwt.claims_mut(), &mut vc_claims.sd_jwt_claims);
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

  /// Removes all disclosures from this SD-JWT, resulting in a token that,
  /// when presented, will have *all* selectively-disclosable properties
  /// omitted.
  pub fn conceal_all(mut self) -> Self {
    self.builder = self.builder.conceal_all();
    self
  }

  /// Discloses a value that was previously concealed.
  /// # Notes
  /// - This method may disclose multiple values, if the given path references a disclosable value stored within another
  ///   disclosable value. That is, [disclose](Self::disclose) will unconceal the selectively disclosable value at
  ///   `path` together with *all* its parents that are disclosable values themselves.
  /// - By default *all* disclosable claims are disclosed, therefore this method can only be used to *undo* any
  ///   concealment operations previously performed by either [Self::conceal] or [Self::conceal_all].
  pub fn disclose(mut self, path: &str) -> Result<Self> {
    self.builder = self.builder.disclose(path).map_err(Error::SdJwt)?;
    Ok(self)
  }

  /// Adds a [`KeyBindingJwt`] to this [`SdJwtVc`]'s presentation.
  pub fn attach_key_binding_jwt(mut self, kb_jwt: KeyBindingJwt) -> Self {
    self.builder = self.builder.attach_key_binding_jwt(kb_jwt);
    self
  }

  /// Returns the resulting [`SdJwtVc`] together with all removed disclosures.
  pub fn finish(mut self) -> Result<(SdJwtVc, Vec<Disclosure>)> {
    let (mut sd_jwt, disclosures) = self.builder.finish()?;
    // Move the token's claim back into parsed VC claims.
    std::mem::swap(sd_jwt.claims_mut(), &mut self.vc_claims.sd_jwt_claims);

    Ok((SdJwtVc::new(sd_jwt, self.vc_claims), disclosures))
  }
}
