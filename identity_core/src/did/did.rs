use core::str::FromStr;
use serde::{
    de::{self, Deserialize, Deserializer, Visitor},
    ser::{Serialize, Serializer},
    Deserialize as DDeserialize, Serialize as DSerialize,
};
use std::{
    fmt::{self, Display, Formatter},
    hash::Hash,
};

use crate::did::parser::parse;

const LEADING_TOKENS: &str = "did";

/// An aliased tuple the converts into a `Param` type.
type DIDTuple = (String, Option<String>);

/// a Decentralized identity structure.
#[derive(Debug, PartialEq, Default, Eq, Clone, Hash, Ord, PartialOrd)]
pub struct DID {
    pub method_name: String,
    pub id_segments: Vec<String>,
    pub path_segments: Option<Vec<String>>,
    pub query: Option<Vec<Param>>,
    pub fragment: Option<String>,
}

impl DID {
    pub const BASE_CONTEXT: &'static str = "https://www.w3.org/ns/did/v1";

    pub const SECURITY_CONTEXT: &'static str = "https://w3id.org/security/v1";

    /// Initializes the DID struct with the filled out fields. Also runs parse_from_str to validate the fields.
    pub fn init(self) -> crate::Result<DID> {
        let did = DID {
            method_name: self.method_name,
            id_segments: self.id_segments,
            fragment: self.fragment,
            path_segments: self.path_segments,
            query: self.query,
        };

        DID::parse(did)
    }

    // TODO: Fix this
    pub fn join_relative(base: &Self, relative: &Self) -> crate::Result<Self> {
        Ok(Self {
            method_name: base.method_name.clone(),
            id_segments: base.id_segments.clone(),
            fragment: relative.fragment.clone(),
            path_segments: relative.path_segments.clone(),
            query: relative.query.clone(),
        })
    }

    pub fn matches_base(&self, base: &Self) -> bool {
        self.method_name == base.method_name
            && self.id_segments == base.id_segments
            && self.path_segments == base.path_segments
    }

    pub fn parse<T>(input: T) -> crate::Result<Self>
    where
        T: ToString,
    {
        parse(input)
    }

    /// Method to add a vector of query params to the DID.  The `value` field of the `Param` type can be None.
    pub fn add_query(&mut self, query: Vec<Param>) {
        let qur = match &mut self.query {
            Some(v) => {
                v.extend(query);

                v
            }
            None => &query,
        };

        self.query = Some(qur.clone());
    }

    /// add path segments to the current DID.
    pub fn add_path_segments(&mut self, path_segment: Vec<String>) {
        let ps = match &mut self.path_segments {
            Some(p) => {
                p.extend(path_segment);

                p
            }
            None => &path_segment,
        };

        self.path_segments = Some(ps.clone());
    }

    /// Method to add a fragment to the DID.
    pub fn add_fragment(&mut self, fragment: String) {
        self.fragment = Some(fragment);
    }
}

/// Display trait for the DID struct.
impl Display for DID {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let frag = match &self.fragment {
            Some(f) => format!("#{}", f),
            None => String::new(),
        };

        let formatted_ids = format!(
            ":{}",
            self.id_segments
                .iter()
                .map(ToString::to_string)
                .fold(&mut String::new(), |acc, p| {
                    if !acc.is_empty() {
                        acc.push(':');
                    }
                    acc.push_str(&p);

                    acc
                })
        );

        let path_segs = match &self.path_segments {
            Some(segs) => format!(
                "/{}",
                segs.iter().map(ToString::to_string).fold(&mut String::new(), |acc, p| {
                    if !acc.is_empty() {
                        acc.push('/');
                    }
                    acc.push_str(&p);

                    acc
                })
            ),
            None => String::new(),
        };

        let query = match &self.query {
            Some(qur) => format!(
                "?{}",
                qur.iter().map(ToString::to_string).fold(&mut String::new(), |acc, p| {
                    if !acc.is_empty() {
                        acc.push('&');
                    }
                    acc.push_str(&p);

                    acc
                })
            ),
            None => String::new(),
        };

        write!(
            f,
            "{}:{}{}{}{}{}",
            LEADING_TOKENS, self.method_name, formatted_ids, path_segs, query, frag
        )
    }
}

impl FromStr for DID {
    type Err = crate::Error;

    fn from_str(string: &str) -> crate::Result<Self> {
        Self::parse(string)
    }
}

/// deserialize logic for the `DID` type.
impl<'de> Deserialize<'de> for DID {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DIDVisitor;

        impl<'de> Visitor<'de> for DIDVisitor {
            type Value = DID;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("DID String")
            }

            fn visit_str<V>(self, value: &str) -> Result<DID, V>
            where
                V: de::Error,
            {
                match DID::parse(value) {
                    Ok(d) => Ok(d),
                    Err(e) => Err(de::Error::custom(e.to_string())),
                }
            }
        }

        deserializer.deserialize_any(DIDVisitor)
    }
}

/// serialize logic for the `DID` type.
impl Serialize for DID {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = format!("{}", self);

        serializer.serialize_str(s.as_str())
    }
}

/// a DID Params struct.
#[derive(Debug, PartialEq, Eq, Clone, Default, Hash, PartialOrd, Ord, DDeserialize, DSerialize)]
pub struct Param {
    pub key: String,
    pub value: Option<String>,
}

impl Param {
    pub fn pair(&self) -> (&str, &str) {
        (self.key.as_str(), self.value.as_deref().unwrap_or_default())
    }
}

/// Display trait for the param struct.
impl Display for Param {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let val = match &self.value {
            Some(v) => format!("={}", v),
            None => String::new(),
        };

        write!(f, "{}{}", self.key, val)
    }
}

impl From<DIDTuple> for Param {
    fn from((key, value): DIDTuple) -> Param {
        Param { key, value }
    }
}
