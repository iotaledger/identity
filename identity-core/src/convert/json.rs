use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

/// A convenience-trait for types that can be serialized as JSON.
pub trait ToJson: Serialize {
    /// Serialize `self` as a string of JSON.
    fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(Error::EncodeJSON)
    }

    /// Serialize `self` as a JSON byte vector.
    fn to_json_vec(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(Error::EncodeJSON)
    }

    /// Serialize `self` as a [`serde_json::Value`].
    fn to_json_value(&self) -> Result<serde_json::Value> {
        serde_json::to_value(self).map_err(Error::EncodeJSON)
    }

    /// Serialize `self` as a pretty-printed string of JSON.
    fn to_json_pretty(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(Error::EncodeJSON)
    }

    /// Serialize `self` as a JSON byte vector, normalized using JSON
    /// Canonicalization Scheme (JCS).
    fn to_jcs(&self) -> Result<Vec<u8>> {
        serde_jcs::to_vec(self).map_err(Error::EncodeJSON)
    }
}

impl<T> ToJson for T where T: Serialize {}

// =============================================================================
// =============================================================================

/// A convenience-trait for types that can be deserialized from JSON.
pub trait FromJson: for<'de> Deserialize<'de> + Sized {
    /// Deserialize `Self` from a string of JSON text.
    fn from_json(json: &(impl AsRef<str> + ?Sized)) -> Result<Self> {
        serde_json::from_str(json.as_ref()).map_err(Error::DecodeJSON)
    }

    /// Deserialize `Self` from bytes of JSON text.
    fn from_json_slice(json: &(impl AsRef<[u8]> + ?Sized)) -> Result<Self> {
        serde_json::from_slice(json.as_ref()).map_err(Error::DecodeJSON)
    }

    /// Deserialize `Self` from a [`serde_json::Value`].
    fn from_json_value(json: serde_json::Value) -> Result<Self> {
        serde_json::from_value(json).map_err(Error::DecodeJSON)
    }
}

impl<T> FromJson for T where T: for<'de> Deserialize<'de> + Sized {}

// =============================================================================
// =============================================================================

/// A convenience-trait for types that can be converted to and from JSON.
pub trait AsJson: FromJson + ToJson {
    /// Deserialize `Self` from a string of JSON text.
    fn from_json(json: &(impl AsRef<str> + ?Sized)) -> Result<Self> {
        <Self as FromJson>::from_json(json)
    }

    /// Deserialize `Self` from bytes of JSON text.
    fn from_json_slice(json: &(impl AsRef<[u8]> + ?Sized)) -> Result<Self> {
        <Self as FromJson>::from_json_slice(json)
    }

    /// Deserialize `Self` from a [`serde_json::Value`].
    fn from_json_value(json: serde_json::Value) -> Result<Self> {
        <Self as FromJson>::from_json_value(json)
    }

    /// Serialize `self` as a string of JSON.
    fn to_json(&self) -> Result<String> {
        <Self as ToJson>::to_json(self)
    }

    /// Serialize `self` as a JSON byte vector.
    fn to_json_vec(&self) -> Result<Vec<u8>> {
        <Self as ToJson>::to_json_vec(self)
    }

    /// Serialize `self` as a [`serde_json::Value`].
    fn to_json_value(&self) -> Result<serde_json::Value> {
        <Self as ToJson>::to_json_value(self)
    }

    /// Serialize `self` as a pretty-printed string of JSON.
    fn to_json_pretty(&self) -> Result<String> {
        <Self as ToJson>::to_json_pretty(self)
    }

    /// Serialize `self` as a JSON byte vector, normalized using JSON
    /// Canonicalization Scheme (JCS).
    fn to_jcs(&self) -> Result<Vec<u8>> {
        <Self as ToJson>::to_jcs(self)
    }
}

impl<T> AsJson for T where T: FromJson + ToJson {}
