use identity_common::{Object, OneOrMany};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

use crate::{
    common::{take_object_id, try_take_object_types},
    error::Error,
};

/// Information used to increase confidence in the claims of a `Credential`
///
/// Ref: https://www.w3.org/TR/vc-data-model/#evidence
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct Evidence {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "type")]
    pub types: OneOrMany<String>,
    #[serde(flatten)]
    pub properties: Object,
}

impl TryFrom<Object> for Evidence {
    type Error = Error;

    fn try_from(mut other: Object) -> Result<Self, Self::Error> {
        let mut this: Self = Default::default();

        this.id = take_object_id(&mut other);
        this.types = try_take_object_types("Evidence", &mut other)?;
        this.properties = other;

        Ok(this)
    }
}
