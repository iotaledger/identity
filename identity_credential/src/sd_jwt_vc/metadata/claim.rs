// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Display;
use std::ops::Deref;

use anyhow::anyhow;
use anyhow::Context;
use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;
use serde::Serializer;
use serde_json::Value;

use crate::sd_jwt_vc::Error;

/// Information about a particular claim for displaying and validation purposes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimMetadata {
  /// [`ClaimPath`] of the claim or claims that are being addressed.
  pub path: ClaimPath,
  /// Object containing display information for the claim.
  #[serde(skip_serializing_if = "Vec::is_empty", default)]
  pub display: Vec<ClaimDisplay>,
  /// A boolean indicating that the claim must be present in
  /// the issued credential.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub mandatory: Option<bool>,
  /// A string indicating whether the claim is selectively disclosable.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub sd: Option<ClaimDisclosability>,
  /// A string defining the ID of the claim for reference in the SVG template.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub svg_id: Option<String>,
}

impl ClaimMetadata {
  /// Checks whether `value` is compliant with the disclosability policy imposed by this [`ClaimMetadata`].
  pub fn check_value_disclosability(&self, value: &Value) -> Result<(), Error> {
    if self.sd.unwrap_or_default() == ClaimDisclosability::Allowed {
      return Ok(());
    }

    let interested_claims = self.path.reverse_index(value);
    if self.sd.unwrap_or_default() == ClaimDisclosability::Always && interested_claims.is_ok() {
      return Err(Error::Validation(anyhow!(
        "claim or claims with path {} must always be disclosable",
        &self.path
      )));
    }

    if self.sd.unwrap_or_default() == ClaimDisclosability::Never && interested_claims.is_err() {
      return Err(Error::Validation(anyhow!(
        "claim or claims with path {} must never be disclosable",
        &self.path
      )));
    }

    Ok(())
  }
}

/// A non-empty list of string, `null` values, or non-negative integers.
/// It is used to select a particular claim in the credential or a
/// set of claims. See [Claim Path](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-05.html#name-claim-path) for more information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<ClaimPathSegment>")]
pub struct ClaimPath(Vec<ClaimPathSegment>);

impl ClaimPath {
  fn reverse_index<'v>(&self, value: &'v Value) -> anyhow::Result<OneOrManyValue<'v>> {
    let mut segments = self.iter();
    let first_segment = segments.next().context("empty claim path")?;
    segments.try_fold(index_value(value, first_segment)?, |values, segment| {
      values.get(segment)
    })
  }
}

impl TryFrom<Vec<ClaimPathSegment>> for ClaimPath {
  type Error = anyhow::Error;
  fn try_from(value: Vec<ClaimPathSegment>) -> Result<Self, Self::Error> {
    if value.is_empty() {
      Err(anyhow::anyhow!("`ClaimPath` cannot be empty"))
    } else {
      Ok(Self(value))
    }
  }
}

impl Display for ClaimPath {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let segments = self.iter().join(", ");
    write!(f, "[{segments}]")
  }
}

impl Deref for ClaimPath {
  type Target = [ClaimPathSegment];
  fn deref(&self) -> &Self::Target {
    &self.0
  }
}

/// A single segment of a [`ClaimPath`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, try_from = "Value")]
pub enum ClaimPathSegment {
  /// JSON object property.
  Name(String),
  /// JSON array entry.
  Position(usize),
  /// All properties or entries.
  #[serde(serialize_with = "serialize_all_variant")]
  All,
}

impl Display for ClaimPathSegment {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::All => write!(f, "null"),
      Self::Name(name) => write!(f, "\"{name}\""),
      Self::Position(i) => write!(f, "{i}"),
    }
  }
}

impl TryFrom<Value> for ClaimPathSegment {
  type Error = anyhow::Error;
  fn try_from(value: Value) -> Result<Self, Self::Error> {
    match value {
      Value::Null => Ok(ClaimPathSegment::All),
      Value::String(s) => Ok(ClaimPathSegment::Name(s)),
      Value::Number(n) => n
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("expected number greater or equal to 0"))
        .map(|n| ClaimPathSegment::Position(n as usize)),
      _ => Err(anyhow::anyhow!("expected either a string, number, or null")),
    }
  }
}

fn serialize_all_variant<S>(serializer: S) -> Result<S::Ok, S::Error>
where
  S: Serializer,
{
  serializer.serialize_none()
}

/// Information about whether a given claim is selectively disclosable.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClaimDisclosability {
  /// The issuer **must** make the claim selectively disclosable.
  Always,
  /// The issuer **may** make the claim selectively disclosable.
  #[default]
  Allowed,
  /// The issuer **must not** make the claim selectively disclosable.
  Never,
}

/// Display information for a given claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimDisplay {
  /// A language tag as defined in [RFC5646](https://www.rfc-editor.org/rfc/rfc5646.txt).
  pub locale: String,
  /// A human-readable label for the claim.
  pub label: String,
  /// A human-readable description for the claim.
  pub description: Option<String>,
}

enum OneOrManyValue<'v> {
  One(&'v Value),
  Many(Box<dyn Iterator<Item = &'v Value> + 'v>),
}

impl<'v> OneOrManyValue<'v> {
  fn get(self, segment: &ClaimPathSegment) -> anyhow::Result<OneOrManyValue<'v>> {
    match self {
      Self::One(value) => index_value(value, segment),
      Self::Many(values) => {
        let new_values = values
          .map(|value| index_value(value, segment))
          .collect::<anyhow::Result<Vec<_>>>()?
          .into_iter()
          .flatten();

        Ok(OneOrManyValue::Many(Box::new(new_values)))
      }
    }
  }
}

struct OneOrManyValueIter<'v>(Option<OneOrManyValue<'v>>);

impl<'v> OneOrManyValueIter<'v> {
  fn new(value: OneOrManyValue<'v>) -> Self {
    Self(Some(value))
  }
}

impl<'v> IntoIterator for OneOrManyValue<'v> {
  type IntoIter = OneOrManyValueIter<'v>;
  type Item = &'v Value;
  fn into_iter(self) -> Self::IntoIter {
    OneOrManyValueIter::new(self)
  }
}

impl<'v> Iterator for OneOrManyValueIter<'v> {
  type Item = &'v Value;
  fn next(&mut self) -> Option<Self::Item> {
    match self.0.take()? {
      OneOrManyValue::One(v) => Some(v),
      OneOrManyValue::Many(mut values) => {
        let value = values.next();
        self.0 = Some(OneOrManyValue::Many(values));

        value
      }
    }
  }
}

fn index_value<'v>(value: &'v Value, segment: &ClaimPathSegment) -> anyhow::Result<OneOrManyValue<'v>> {
  match segment {
    ClaimPathSegment::Name(name) => value.get(name).map(OneOrManyValue::One),
    ClaimPathSegment::Position(i) => value.get(i).map(OneOrManyValue::One),
    ClaimPathSegment::All => value
      .as_array()
      .map(|values| OneOrManyValue::Many(Box::new(values.iter()))),
  }
  .ok_or_else(|| anyhow::anyhow!("value {value:#} has no element {segment}"))
}

#[cfg(test)]
mod tests {
  use serde_json::json;

  use super::*;

  fn sample_obj() -> Value {
    json!({
      "vct": "https://betelgeuse.example.com/education_credential",
      "name": "Arthur Dent",
      "address": {
        "street_address": "42 Market Street",
        "city": "Milliways",
        "postal_code": "12345"
      },
      "degrees": [
        {
          "type": "Bachelor of Science",
          "university": "University of Betelgeuse"
        },
        {
          "type": "Master of Science",
          "university": "University of Betelgeuse"
        }
      ],
      "nationalities": ["British", "Betelgeusian"]
    })
  }

  #[test]
  fn claim_path_works() {
    let name_path = serde_json::from_value::<ClaimPath>(json!(["name"])).unwrap();
    let city_path = serde_json::from_value::<ClaimPath>(json!(["address", "city"])).unwrap();
    let first_degree_path = serde_json::from_value::<ClaimPath>(json!(["degrees", 0])).unwrap();
    let degrees_types_path = serde_json::from_value::<ClaimPath>(json!(["degrees", null, "type"])).unwrap();

    assert!(matches!(
      name_path.reverse_index(&sample_obj()).unwrap(),
      OneOrManyValue::One(&Value::String(_))
    ));
    assert!(matches!(
      city_path.reverse_index(&sample_obj()).unwrap(),
      OneOrManyValue::One(&Value::String(_))
    ));
    assert!(matches!(
      first_degree_path.reverse_index(&sample_obj()).unwrap(),
      OneOrManyValue::One(&Value::Object(_))
    ));
    let obj = &sample_obj();
    let mut degree_types = degrees_types_path.reverse_index(obj).unwrap().into_iter();
    assert_eq!(degree_types.next().unwrap().as_str(), Some("Bachelor of Science"));
    assert_eq!(degree_types.next().unwrap().as_str(), Some("Master of Science"));
    assert_eq!(degree_types.next(), None);
  }
}
