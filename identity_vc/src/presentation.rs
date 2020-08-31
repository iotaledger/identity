use identity_core::common::{Object, Value};
use identity_crypto::{
  error::Result as CryptoResult,
  proof::{LinkedDataProof, ProofDocument},
  utils::convert,
};
use serde_json::{from_str, to_string};

use crate::{
  common::{Context, OneOrMany, RefreshService, TermsOfUse, URI},
  credential::Credential,
  error::{Error, Result},
  utils::validate_presentation_structure,
  verifiable::{VerifiableCredential, VerifiablePresentation},
};

/// A `Presentation` represents a bundle of one or more `VerifiableCredential`s.
///
/// `Presentation`s can be combined with `Proof`s to create `VerifiablePresentation`s.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Presentation {
  /// A set of URIs or `Object`s describing the applicable JSON-LD contexts.
  ///
  /// NOTE: The first URI MUST be `https://www.w3.org/2018/credentials/v1`
  #[serde(rename = "@context")]
  pub context: OneOrMany<Context>,
  /// A unique `URI` referencing the subject of the presentation.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub id: Option<URI>,
  /// One or more URIs defining the type of presentation.
  ///
  /// NOTE: The VC spec defines this as a set of URIs BUT they are commonly
  /// passed as non-`URI` strings and expected to be processed with JSON-LD.
  /// We're using a `String` here since we don't currently use JSON-LD and
  /// don't have any immediate plans to do so.
  #[serde(rename = "type")]
  pub types: OneOrMany<String>,
  /// TODO
  #[serde(rename = "verifiableCredential")]
  pub verifiable_credential: OneOrMany<VerifiableCredential>,
  /// The entity that generated the presentation.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub holder: Option<URI>,
  /// TODO
  #[serde(rename = "refreshService", skip_serializing_if = "Option::is_none")]
  pub refresh_service: Option<OneOrMany<RefreshService>>,
  /// The terms of use issued by the presentation holder
  #[serde(rename = "termsOfUse", skip_serializing_if = "Option::is_none")]
  pub terms_of_use: Option<OneOrMany<TermsOfUse>>,
  /// Miscellaneous properties.
  #[serde(flatten)]
  pub properties: Object,
}

impl Presentation {
  pub const BASE_TYPE: &'static str = "VerifiablePresentation";

  pub fn validate(&self) -> Result<()> {
    validate_presentation_structure(self)
  }

  pub fn from_json(json: &(impl AsRef<str> + ?Sized)) -> Result<Self> {
    from_str(json.as_ref()).map_err(Error::DecodeJSON)
  }

  pub fn to_json(&self) -> Result<String> {
    to_string(self).map_err(Error::EncodeJSON)
  }
}

impl ProofDocument for Presentation {
  fn to_object(&self) -> CryptoResult<Object> {
    convert(self)
  }
}

// =============================================================================
// Presentation Builder
// =============================================================================

/// A convenience for constructing a `Presentation` or `VerifiablePresentation`
/// from dynamic data.
///
/// NOTE: Base context and type are automatically included.
#[derive(Debug)]
pub struct PresentationBuilder {
  context: Vec<Context>,
  id: Option<URI>,
  types: Vec<String>,
  verifiable_credential: Vec<VerifiableCredential>,
  holder: Option<URI>,
  refresh_service: Vec<RefreshService>,
  terms_of_use: Vec<TermsOfUse>,
  properties: Object,
}

impl PresentationBuilder {
  pub fn new() -> Self {
    Self {
      context: vec![Credential::BASE_CONTEXT.into()],
      id: None,
      types: vec![Presentation::BASE_TYPE.into()],
      verifiable_credential: Vec::new(),
      holder: None,
      refresh_service: Vec::new(),
      terms_of_use: Vec::new(),
      properties: Default::default(),
    }
  }

  pub fn context(mut self, value: impl Into<Context>) -> Self {
    let value: Context = value.into();

    if !matches!(value, Context::URI(ref uri) if uri == Credential::BASE_CONTEXT) {
      self.context.push(value);
    }

    self
  }

  pub fn type_(mut self, value: impl Into<String>) -> Self {
    let value: String = value.into();

    if value != Presentation::BASE_TYPE {
      self.types.push(value);
    }

    self
  }

  pub fn property(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
    self.properties.insert(key.into(), value.into());
    self
  }

  impl_builder_setter!(id, id, Option<URI>);
  impl_builder_setter!(credential, verifiable_credential, Vec<VerifiableCredential>);
  impl_builder_setter!(holder, holder, Option<URI>);
  impl_builder_setter!(refresh, refresh_service, Vec<RefreshService>);
  impl_builder_setter!(terms_of_use, terms_of_use, Vec<TermsOfUse>);
  impl_builder_setter!(properties, properties, Object);

  impl_builder_try_setter!(try_refresh_service, refresh_service, Vec<RefreshService>);
  impl_builder_try_setter!(try_terms_of_use, terms_of_use, Vec<TermsOfUse>);

  /// Consumes the `PresentationBuilder`, returning a valid `Presentation`
  pub fn build(self) -> Result<Presentation> {
    let mut presentation: Presentation = Presentation {
      context: self.context.into(),
      id: self.id,
      types: self.types.into(),
      verifiable_credential: self.verifiable_credential.into(),
      holder: self.holder,
      refresh_service: None,
      terms_of_use: None,
      properties: self.properties,
    };

    if !self.refresh_service.is_empty() {
      presentation.refresh_service = Some(self.refresh_service.into());
    }

    if !self.terms_of_use.is_empty() {
      presentation.terms_of_use = Some(self.terms_of_use.into());
    }

    presentation.validate()?;

    Ok(presentation)
  }

  /// Consumes the `PresentationBuilder`, returning a valid `VerifiablePresentation`
  pub fn build_verifiable(self, proof: impl Into<OneOrMany<LinkedDataProof>>) -> Result<VerifiablePresentation> {
    self
      .build()
      .map(|credential| VerifiablePresentation::new(credential, proof))
  }
}

impl Default for PresentationBuilder {
  fn default() -> Self {
    Self::new()
  }
}
