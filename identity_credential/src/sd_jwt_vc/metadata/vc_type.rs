// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use futures::future::FutureExt;
use futures::future::LocalBoxFuture;
use identity_core::common::Url;
use itertools::Itertools as _;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

use crate::sd_jwt_vc::Error;
use crate::sd_jwt_vc::Resolver;
use crate::sd_jwt_vc::Result;

use super::ClaimMetadata;
use super::DisplayMetadata;
use super::IntegrityMetadata;

/// SD-JWT VC's credential type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeMetadata {
  /// A human-readable name for the type, intended for developers reading the JSON document.
  pub name: Option<String>,
  /// A human-readable description for the type, intended for developers reading the JSON document.
  pub description: Option<String>,
  /// A URI of another type that this type extends.
  pub extends: Option<Url>,
  /// Integrity metadata for the extended type.
  #[serde(rename = "extends#integrity")]
  pub extends_integrity: Option<IntegrityMetadata>,
  /// Either an embedded schema or a reference to one.
  #[serde(flatten)]
  pub schema: Option<TypeSchema>,
  /// A list containing display information for the type.
  #[serde(skip_serializing_if = "Vec::is_empty", default)]
  pub display: Vec<DisplayMetadata>,
  /// A list of [`ClaimMetadata`] containing information about particular claims.
  #[serde(skip_serializing_if = "Vec::is_empty", default)]
  pub claims: Vec<ClaimMetadata>,
}

impl TypeMetadata {
  /// Returns the name of this VC type, if any.
  pub fn name(&self) -> Option<&str> {
    self.name.as_deref()
  }
  /// Returns the description of this VC type, if any.
  pub fn description(&self) -> Option<&str> {
    self.description.as_deref()
  }
  /// Returns the URI or string of the type this VC type extends, if any.
  pub fn extends(&self) -> Option<&Url> {
    self.extends.as_ref()
  }
  /// Returns the integrity string of the extended type object, if any.
  pub fn extends_integrity(&self) -> Option<&str> {
    self.extends_integrity.as_ref().map(|meta| meta.as_ref())
  }
  /// Returns the [`ClaimMetadata`]s associated with this credential type.
  pub fn claim_metadata(&self) -> &[ClaimMetadata] {
    &self.claims
  }
  /// Returns the [`DisplayMetadata`]s associated with this credential type.
  pub fn display_metadata(&self) -> &[DisplayMetadata] {
    &self.display
  }
  /// Uses this [`TypeMetadata`] to validate JSON object `credential`. This method fails
  /// if the schema is referenced instead of embedded.
  /// Use [`TypeMetadata::validate_credential_with_resolver`] for such cases.
  /// ## Notes
  /// This method ignores type extensions.
  pub fn validate_credential(&self, credential: &Value) -> Result<()> {
    match &self.schema {
      Some(TypeSchema::Object { schema, .. }) => validate_credential_with_schema(schema, credential),
      Some(_) => Err(Error::Validation(anyhow::anyhow!(
        "this credential type references a schema; resolution is required"
      ))),
      None => Ok(()),
    }
  }

  /// Similar to [`TypeMetadata::validate_credential`], but accepts a [`Resolver`]
  /// [`Url`] -> [`Value`] that is used to resolve any reference to either
  /// another type or JSON schema.
  pub async fn validate_credential_with_resolver<R>(&self, credential: &Value, resolver: &R) -> Result<()>
  where
    R: Resolver<Url, Value>,
  {
    validate_credential_impl(self.clone(), credential, resolver, vec![]).await
  }
}

// Recursively validate a credential.
fn validate_credential_impl<'c, 'r, R>(
  current_type: TypeMetadata,
  credential: &'c Value,
  resolver: &'r R,
  mut passed_types: Vec<TypeMetadata>,
) -> LocalBoxFuture<'c, Result<()>>
where
  R: Resolver<Url, Value>,
  'r: 'c,
{
  async move {
    // Check if current type has already been checked.
    let is_type_already_checked = passed_types.contains(&current_type);
    if is_type_already_checked {
      // This is a dependency cycle!
      return Err(Error::Validation(anyhow::anyhow!("dependency cycle detected")));
    }

    // Check if `validate_credential` should have been called instead.
    let has_extend = current_type.extends.is_none();
    let is_immediate = current_type
      .schema
      .as_ref()
      .map(|schema| matches!(schema, &TypeSchema::Object { .. }))
      .unwrap_or(true);

    if is_immediate && !has_extend {
      return current_type.validate_credential(credential);
    }

    if !is_immediate {
      // Fetch schema and validate `current_type`.
      let TypeSchema::Uri { schema_uri, .. } = current_type.schema.as_ref().unwrap() else {
        unreachable!("schema is provided through `schema_uri` as checked by `validate_credential`");
      };
      let schema = resolver.resolve(schema_uri).await.map_err(|e| Error::Resolution {
        input: schema_uri.to_string(),
        source: e,
      })?;
      validate_credential_with_schema(&schema, credential)?;
    }

    // Check for extends.
    if let Some(extends_uri) = current_type.extends() {
      // Fetch the extended type metadata and parse it.
      let raw_type_metadata = resolver.resolve(extends_uri).await.map_err(|e| Error::Resolution {
        input: extends_uri.to_string(),
        source: e,
      })?;
      let type_metadata =
        serde_json::from_value(raw_type_metadata).map_err(|e| Error::InvalidTypeMetadata(e.into()))?;
      // Forward validation of new type.
      passed_types.push(current_type);
      validate_credential_impl(type_metadata, credential, resolver, passed_types).await
    } else {
      Ok(())
    }
  }
  .boxed_local()
}

fn validate_credential_with_schema(schema: &Value, credential: &Value) -> Result<()> {
  let schema = jsonschema::compile(schema).map_err(|e| Error::Validation(anyhow::anyhow!(e.to_string())))?;
  schema.validate(credential).map_err(|errors| {
    let error_msg = errors.map(|e| e.to_string()).join("; ");
    Error::Validation(anyhow::anyhow!(error_msg))
  })
}

/// Either a reference to or an embedded JSON Schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(untagged)]
pub enum TypeSchema {
  /// URI reference to a JSON schema.
  Uri {
    /// URI of the referenced JSON schema.
    schema_uri: Url,
    /// Integrity string for the referenced schema.
    #[serde(rename = "schema_uri#integrity")]
    schema_uri_integrity: Option<IntegrityMetadata>,
  },
  /// An embedded JSON schema.
  Object {
    /// The JSON schema.
    schema: Value,
    /// Integrity of the JSON schema.
    #[serde(rename = "schema#integrity")]
    schema_integrity: Option<IntegrityMetadata>,
  },
}

#[cfg(test)]
mod tests {
  use std::sync::LazyLock;

  use async_trait::async_trait;
  use serde_json::json;

  use crate::sd_jwt_vc::resolver;

  use super::*;

  static IMMEDIATE_TYPE_METADATA: LazyLock<TypeMetadata> = LazyLock::new(|| TypeMetadata {
    name: Some("immediate credential".to_string()),
    description: None,
    extends: None,
    extends_integrity: None,
    display: vec![],
    claims: vec![],
    schema: Some(TypeSchema::Object {
      schema: json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
          "name": {
            "type": "string"
          },
          "age": {
            "type": "number"
          }
        },
        "required": ["name", "age"]
      }),
      schema_integrity: None,
    }),
  });
  static REFERENCED_TYPE_METADATA: LazyLock<TypeMetadata> = LazyLock::new(|| TypeMetadata {
    name: Some("immediate credential".to_string()),
    description: None,
    extends: None,
    extends_integrity: None,
    display: vec![],
    claims: vec![],
    schema: Some(TypeSchema::Uri {
      schema_uri: Url::parse("https://example.com/vc_types/1").unwrap(),
      schema_uri_integrity: None,
    }),
  });

  struct SchemaResolver;
  #[async_trait]
  impl Resolver<Url, Value> for SchemaResolver {
    async fn resolve(&self, _input: &Url) -> resolver::Result<Value> {
      Ok(serde_json::to_value(IMMEDIATE_TYPE_METADATA.clone().schema).unwrap())
    }
  }

  #[test]
  fn validation_of_immediate_type_metadata_works() {
    IMMEDIATE_TYPE_METADATA
      .validate_credential(&json!({
        "name": "John Doe",
        "age": 42
      }))
      .unwrap();
  }

  #[tokio::test]
  async fn validation_of_referenced_type_metadata_works() {
    REFERENCED_TYPE_METADATA
      .validate_credential_with_resolver(
        &json!({
          "name": "Aristide Zantedeschi",
          "age": 90,
        }),
        &SchemaResolver,
      )
      .await
      .unwrap();
  }
}
