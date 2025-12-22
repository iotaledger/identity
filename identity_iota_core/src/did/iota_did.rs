// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::convert::TryFrom;
use core::fmt::Debug;
use core::fmt::Display;
use core::fmt::Formatter;
use core::str::FromStr;

use identity_core::common::KeyComparable;
use identity_did::BaseDIDUrl;
use identity_did::CoreDID;
use identity_did::Error as DIDError;
use identity_did::DID;
use iota_sdk::types::base_types::ObjectID;
use product_common::network_name::NetworkName;
use ref_cast::ref_cast_custom;
use ref_cast::RefCastCustom;
use serde::Deserialize;
use serde::Serialize;

/// Alias for a `Result` with the error type [`DIDError`].
type Result<T> = std::result::Result<T, DIDError>;

/// A DID conforming to the IOTA DID method specification.
///
/// This is a thin wrapper around the [`DID`][`CoreDID`] type from the
/// [`identity_did`][`identity_did`] crate.
#[derive(Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, RefCastCustom)]
#[repr(transparent)]
#[serde(into = "CoreDID", try_from = "CoreDID")]
pub struct IotaDID(CoreDID);

impl IotaDID {
  /// The URL scheme for Decentralized Identifiers.
  pub const SCHEME: &'static str = CoreDID::SCHEME;

  /// The IOTA DID method name (`"iota"`).
  pub const METHOD: &'static str = "iota";

  /// The default network name (`"iota"`).
  // TODO: replace this with main net chain ID
  // as soon as IOTA rebased lands on mainnet.
  pub const DEFAULT_NETWORK: &'static str = "iota";

  /// The tag of the placeholder DID.
  pub const PLACEHOLDER_TAG: &'static str = "0x0000000000000000000000000000000000000000000000000000000000000000";

  /// The length of an identity's object id, which is a BLAKE2b-256 hash (32-bytes).
  pub(crate) const TAG_BYTES_LEN: usize = 32;

  /// Convert a `CoreDID` reference to an `IotaDID` reference without checking the referenced value.
  ///  
  /// # Warning
  /// This method should only be called on [`CoreDIDs`](CoreDID) that
  /// are known to satisfy the requirements of the IOTA UTXO specification.  
  ///
  /// # Memory safety
  ///
  /// The `ref-cast` crate ensures a memory safe implementation.  
  #[ref_cast_custom]
  pub(crate) const fn from_inner_ref_unchecked(did: &CoreDID) -> &Self;

  // ===========================================================================
  // Constructors
  // ===========================================================================

  /// Constructs a new [`IotaDID`] from a byte representation of the tag and the given
  /// network name.
  ///
  /// See also [`IotaDID::placeholder`].
  ///
  /// # Example
  ///
  /// ```
  /// # use identity_did::DID;
  /// # use product_common::network_name::NetworkName;
  /// # use identity_iota_core::IotaDID;
  /// #
  /// let did = IotaDID::new(&[1;32], &NetworkName::try_from("smr").unwrap());
  /// assert_eq!(did.as_str(), "did:iota:smr:0x0101010101010101010101010101010101010101010101010101010101010101");
  pub fn new(bytes: &[u8; Self::TAG_BYTES_LEN], network_name: &NetworkName) -> Self {
    Self::from_object_id(ObjectID::new(*bytes), network_name)
  }

  /// Constructs a new [`IotaDID`] from an identity's object id and the given `network_name`.
  pub fn from_object_id(object_id: ObjectID, network_name: &NetworkName) -> Self {
    Self::parse(format!("did:iota:{network_name}:{object_id}")).expect("valid IOTA DID")
  }

  /// Converts this [IotaDID] into an [ObjectID].
  pub fn to_object_id(&self) -> ObjectID {
    let object_id_hex = self.as_str().rsplit_once(':').expect("valid IOTA DID").1;
    ObjectID::from_hex_literal(object_id_hex).expect("valid object ID")
  }

  /// Creates a new placeholder [`IotaDID`] with the given network name.
  ///
  /// # Example
  ///
  /// ```
  /// # use identity_did::DID;
  /// # use product_common::network_name::NetworkName;
  /// # use identity_iota_core::IotaDID;
  /// #
  /// let placeholder = IotaDID::placeholder(&NetworkName::try_from("smr").unwrap());
  /// assert_eq!(placeholder.as_str(), "did:iota:smr:0x0000000000000000000000000000000000000000000000000000000000000000");
  /// assert!(placeholder.is_placeholder());
  pub fn placeholder(network_name: &NetworkName) -> Self {
    Self::new(&[0; 32], network_name)
  }

  /// Returns whether this is the placeholder DID.
  ///
  /// # Example
  ///
  /// ```
  /// # use identity_did::DID;
  /// # use product_common::network_name::NetworkName;
  /// # use identity_iota_core::IotaDID;
  /// #
  /// let placeholder = IotaDID::placeholder(&NetworkName::try_from("smr").unwrap());
  /// assert!(placeholder.is_placeholder());
  pub fn is_placeholder(&self) -> bool {
    self.tag_str() == Self::PLACEHOLDER_TAG
  }

  /// Parses an [`IotaDID`] from the given `input`.
  ///
  /// # Errors
  ///
  /// Returns `Err` if the input does not conform to the [`IotaDID`] specification.
  pub fn parse(input: impl AsRef<str>) -> Result<Self> {
    CoreDID::parse(input.as_ref().to_lowercase()).and_then(Self::try_from_core)
  }

  /// Converts a [`CoreDID`] to a [`IotaDID`].
  ///
  /// # Errors
  ///
  /// Returns `Err` if the input does not conform to the [`IotaDID`] specification.
  pub fn try_from_core(did: CoreDID) -> Result<Self> {
    Self::check_validity(&did)?;

    Ok(Self(Self::normalize(did)))
  }

  // ===========================================================================
  // Properties
  // ===========================================================================

  /// Returns the IOTA `network` name of the `DID`.
  pub fn network_str(&self) -> &str {
    Self::denormalized_components(self.method_id()).0
  }

  /// Returns the tag of the `DID`, which is an identity's object id.
  pub fn tag_str(&self) -> &str {
    Self::denormalized_components(self.method_id()).1
  }

  // ===========================================================================
  // Validation
  // ===========================================================================

  /// Checks if the given `DID` is syntactically valid according to the [`IotaDID`] method specification.
  ///
  /// # Errors
  ///
  /// Returns `Err` if the input is not a syntactically valid [`IotaDID`].
  pub fn check_validity<D: DID>(did: &D) -> Result<()> {
    Self::check_method(did)
      .and_then(|_| Self::check_tag(did))
      .and_then(|_| Self::check_network(did))
  }

  /// Returns a `bool` indicating if the given `DID` is valid according to the
  /// [`IotaDID`] method specification.
  ///
  /// Equivalent to `IotaDID::check_validity(did).is_ok()`.
  pub fn is_valid(did: &CoreDID) -> bool {
    Self::check_validity(did).is_ok()
  }

  // ===========================================================================
  // Helpers
  // ===========================================================================

  /// Checks if the given `DID` has a valid [`IotaDID`] `method` (i.e. `"iota"`).
  ///
  /// # Errors
  ///
  /// Returns `Err` if the input represents another method.
  fn check_method<D: DID>(did: &D) -> Result<()> {
    (did.method() == Self::METHOD)
      .then_some(())
      .ok_or(DIDError::InvalidMethodName)
  }

  /// Checks if the given `DID` has a valid [`IotaDID`] `method_id`.
  ///
  /// # Errors
  ///
  /// Returns `Err` if the input does not have a [`IotaDID`] compliant method id.
  fn check_tag<D: DID>(did: &D) -> Result<()> {
    let (_, tag) = Self::denormalized_components(did.method_id());

    // Implicitly catches if there are too many segments (:) in the DID too.
    prefix_hex::decode::<[u8; Self::TAG_BYTES_LEN]>(tag)
      .map_err(|_| DIDError::InvalidMethodId)
      .map(|_| ())
  }

  /// Checks if the given `DID` has a valid [`IotaDID`] network name.
  ///
  /// # Errors
  ///
  /// Returns `Err` if the input is not a valid network name according to the [`IotaDID`] method specification.
  fn check_network<D: DID>(did: &D) -> Result<()> {
    let (network_name, _) = Self::denormalized_components(did.method_id());
    NetworkName::validate_network_name(network_name).map_err(|_| DIDError::Other("invalid network name"))
  }

  /// Normalizes the DID `method_id` by removing the default network segment if present.
  ///
  /// E.g.
  /// - `"did:iota:main:123" -> "did:iota:123"` is normalized
  /// - `"did:iota:dev:123" -> "did:iota:dev:123"` is unchanged
  // TODO: Remove the lint once this bug in clippy has been fixed. Without to_owned a mutable reference will be aliased.
  #[allow(clippy::unnecessary_to_owned)]
  fn normalize(mut did: CoreDID) -> CoreDID {
    let method_id = did.method_id();
    let (network, tag) = Self::denormalized_components(method_id);
    if tag.len() == method_id.len() || network != Self::DEFAULT_NETWORK {
      did
    } else {
      did
        .set_method_id(tag.to_owned())
        .expect("normalizing a valid CoreDID should be Ok");
      did
    }
  }

  /// foo:bar -> (foo,bar)
  /// foo:bar:baz -> (foo, bar:baz)
  /// foo -> (IotaDID::DEFAULT_NETWORK.as_ref(), foo)
  #[inline(always)]
  fn denormalized_components(input: &str) -> (&str, &str) {
    input
      .find(':')
      .map(|idx| input.split_at(idx))
      .map(|(network, tail)| (network, &tail[1..]))
      // Self::DEFAULT_NETWORK is built from a static reference so unwrapping is fine
      .unwrap_or((Self::DEFAULT_NETWORK, input))
  }
}

impl FromStr for IotaDID {
  type Err = DIDError;

  fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
    Self::parse(s)
  }
}

impl TryFrom<&str> for IotaDID {
  type Error = DIDError;

  fn try_from(other: &str) -> std::result::Result<Self, Self::Error> {
    Self::parse(other)
  }
}

impl TryFrom<String> for IotaDID {
  type Error = DIDError;

  fn try_from(other: String) -> std::result::Result<Self, Self::Error> {
    Self::parse(other)
  }
}

impl Display for IotaDID {
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    write!(f, "{}", self.0)
  }
}

impl From<IotaDID> for CoreDID {
  fn from(id: IotaDID) -> Self {
    id.0
  }
}

impl From<IotaDID> for String {
  fn from(did: IotaDID) -> Self {
    did.into_string()
  }
}

impl TryFrom<CoreDID> for IotaDID {
  type Error = DIDError;

  fn try_from(value: CoreDID) -> std::result::Result<Self, Self::Error> {
    Self::try_from_core(value)
  }
}

impl TryFrom<BaseDIDUrl> for IotaDID {
  type Error = DIDError;

  fn try_from(other: BaseDIDUrl) -> Result<Self> {
    let core_did: CoreDID = CoreDID::try_from(other)?;
    Self::try_from(core_did)
  }
}

impl AsRef<CoreDID> for IotaDID {
  fn as_ref(&self) -> &CoreDID {
    &self.0
  }
}

impl KeyComparable for IotaDID {
  type Key = CoreDID;

  #[inline]
  fn key(&self) -> &Self::Key {
    self.as_ref()
  }
}

#[cfg(test)]
mod tests {
  use identity_did::DIDUrl;
  use once_cell::sync::Lazy;
  use proptest::strategy::Strategy;
  use proptest::*;

  use super::*;

  // ===========================================================================================================================
  // Reusable constants and statics
  // ===========================================================================================================================

  const VALID_OBJECT_ID_STR: &str = "0xf29dd16310c2100fd1bf568b345fb1cc14d71caa3bd9b5ad735d2bd6d455ca3b";

  const LEN_VALID_OBJECT_ID_STR: usize = VALID_OBJECT_ID_STR.len();

  static VALID_IOTA_DID_STRING: Lazy<String> = Lazy::new(|| format!("did:{}:{}", IotaDID::METHOD, VALID_OBJECT_ID_STR));

  // Rules are: at least one character, at most six characters and may only contain digits and/or lowercase ascii
  // characters.
  const VALID_NETWORK_NAMES: [&str; 13] = [
    IotaDID::DEFAULT_NETWORK,
    "main",
    "dev",
    "smr",
    "rms",
    "test",
    "foo",
    "foobar",
    "123456",
    "0",
    "foo42",
    "bar123",
    "42foo",
  ];

  static VALID_IOTA_DID_STRINGS: Lazy<Vec<String>> = Lazy::new(|| {
    let network_tag_to_did = |network, tag| format!("did:{}:{}:{}", IotaDID::METHOD, network, tag);

    let valid_strings: Vec<String> = VALID_NETWORK_NAMES
      .iter()
      .flat_map(|network| {
        [VALID_OBJECT_ID_STR, IotaDID::PLACEHOLDER_TAG]
          .iter()
          .map(move |tag| network_tag_to_did(network, tag))
      })
      .collect();

    // in principle the previous binding is not necessary (we could have just returned the value),
    // but let's just ensure that it contains the expected number of elements first.
    assert_eq!(valid_strings.len(), 2 * VALID_NETWORK_NAMES.len());

    valid_strings
  });

  // ===========================================================================================================================
  // Test check_* methods
  // ===========================================================================================================================

  #[test]
  fn invalid_check_method() {
    let did_key_core: CoreDID = CoreDID::parse("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap();
    assert!(matches!(
      IotaDID::check_method(&did_key_core),
      Err(DIDError::InvalidMethodName)
    ));
  }

  #[test]
  fn valid_check_method() {
    let did_iota_core: CoreDID = CoreDID::parse(&*VALID_IOTA_DID_STRING).unwrap();
    assert!(IotaDID::check_method(&did_iota_core).is_ok());
  }

  #[test]
  fn valid_check_network() {
    let assert_check_network = |input: &str| {
      let did_core: CoreDID =
        CoreDID::parse(input).unwrap_or_else(|_| panic!("expected {input} to parse to a valid CoreDID"));
      assert!(
        IotaDID::check_network(&did_core).is_ok(),
        "test: valid_check_network failed with input {input}",
      );
    };

    for network_name in VALID_NETWORK_NAMES {
      let did_string = format!("did:method:{network_name}:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
      assert_check_network(&did_string);
    }

    assert_check_network("did:method:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
  }

  #[test]
  fn invalid_check_network() {
    // Loop over list of network names known to be invalid, attempt to create a CoreDID containing the given network
    // name in the method_id sub-string and ensure that `IotaDID::check_network` fails. If the provided network
    // name is in conflict with the DID Core spec itself then proceed to the next network name.

    // Ensure that this test is robust to changes in the supplied list of network names, i.e. fail if none of the
    // network names can be contained in a generic CoreDID.

    let mut check_network_executed: bool = false;

    const INVALID_NETWORK_NAMES: [&str; 10] = [
      "Main",
      "fOo",
      "deV",
      "féta",
      "",
      "  ",
      "foo ",
      " foo",
      "123456789",
      "foobar123",
    ];
    for network_name in INVALID_NETWORK_NAMES {
      let did_string: String = format!("did:method:{network_name}:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
      let did_core: CoreDID = {
        match CoreDID::parse(did_string) {
          Ok(did_core) => did_core,
          Err(_) => continue,
        }
      };

      assert!(matches!(IotaDID::check_network(&did_core), Err(DIDError::Other(_))));
      check_network_executed = true;
    }
    assert!(
      check_network_executed,
      "IotaDID::check_network` should have been executed"
    );
  }

  #[test]
  fn valid_check_tag() {
    for input in VALID_IOTA_DID_STRINGS.iter() {
      let did_core: CoreDID = CoreDID::parse(input).unwrap();
      assert!(
        IotaDID::check_tag(&did_core).is_ok(),
        "test: valid_check_method_id failed on input {input}"
      );
    }

    // Should also work for DID's of the form: did:<method_name>:<valid_iota_network (or
    // nothing/normalized)>:<object_id>
    let did_other_string: String = format!("did:method:{VALID_OBJECT_ID_STR}");
    let did_other_with_network: String = format!("did:method:test:{VALID_OBJECT_ID_STR}");
    let did_other_core: CoreDID = CoreDID::parse(did_other_string).unwrap();
    let did_other_with_network_core: CoreDID = CoreDID::parse(did_other_with_network).unwrap();

    assert!(IotaDID::check_tag(&did_other_core).is_ok());
    assert!(IotaDID::check_tag(&did_other_with_network_core).is_ok());
  }

  #[test]
  fn invalid_check_tag() {
    let invalid_method_id_strings = [
      // Too many segments
      format!("did:method:main:test:{VALID_OBJECT_ID_STR}"),
      // Tag is not prefixed
      format!("did:method:{}", &VALID_OBJECT_ID_STR.strip_prefix("0x").unwrap()),
      // Tag is too long
      format!(
        "did:method:{}",
        &VALID_OBJECT_ID_STR.chars().chain("a".chars()).collect::<String>()
      ),
      // Tag is too short (omit last character)
      format!("did:method:main:{}", &VALID_OBJECT_ID_STR[..65]),
    ];

    for input in invalid_method_id_strings {
      let did_core: CoreDID = CoreDID::parse(input).unwrap();
      assert!(
        matches!(IotaDID::check_tag(&did_core), Err(DIDError::InvalidMethodId)),
        "{}",
        did_core
      );
    }
  }

  // ===========================================================================================================================
  // Test constructors
  // ===========================================================================================================================

  #[test]
  fn placeholder_produces_a_did_with_expected_string_representation() {
    assert_eq!(
      IotaDID::placeholder(&NetworkName::try_from(IotaDID::DEFAULT_NETWORK).unwrap()).as_str(),
      format!("did:{}:{}", IotaDID::METHOD, IotaDID::PLACEHOLDER_TAG)
    );

    for name in VALID_NETWORK_NAMES
      .iter()
      .filter(|name| *name != &IotaDID::DEFAULT_NETWORK)
    {
      let network_name: NetworkName = NetworkName::try_from(*name).unwrap();
      let did: IotaDID = IotaDID::placeholder(&network_name);
      assert_eq!(
        did.as_str(),
        format!("did:{}:{}:{}", IotaDID::METHOD, name, IotaDID::PLACEHOLDER_TAG)
      );
    }
  }

  #[test]
  fn normalization_in_constructors() {
    let did_with_default_network_string: String = format!(
      "did:{}:{}:{}",
      IotaDID::METHOD,
      IotaDID::DEFAULT_NETWORK,
      VALID_OBJECT_ID_STR
    );
    let expected_normalization_string_representation: String =
      format!("did:{}:{}", IotaDID::METHOD, VALID_OBJECT_ID_STR);

    assert_eq!(
      IotaDID::parse(did_with_default_network_string).unwrap().as_str(),
      expected_normalization_string_representation
    );
  }

  #[test]
  fn parse_valid() {
    for did_str in VALID_IOTA_DID_STRINGS.iter() {
      assert!(IotaDID::parse(did_str).is_ok());
    }
  }

  #[test]
  fn parse_invalid() {
    let execute_assertions = |valid_object_id: &str| {
      assert!(matches!(
        IotaDID::parse(format!("dod:{}:{}", IotaDID::METHOD, valid_object_id)),
        Err(DIDError::InvalidScheme)
      ));

      assert!(matches!(
        IotaDID::parse(format!("did:key:{valid_object_id}")),
        Err(DIDError::InvalidMethodName)
      ));

      // invalid network name (exceeded eight characters)
      assert!(matches!(
        IotaDID::parse(format!("did:{}:123456789:{}", IotaDID::METHOD, valid_object_id)),
        Err(DIDError::Other(_))
      ));

      // invalid network name (contains non ascii character é)
      assert!(matches!(
        IotaDID::parse(format!("did:{}:féta:{}", IotaDID::METHOD, valid_object_id)),
        Err(DIDError::InvalidMethodId)
      ));

      // invalid tag
      assert!(matches!(
        IotaDID::parse(format!("did:{}:", IotaDID::METHOD)),
        Err(DIDError::InvalidMethodId)
      ));

      // too many segments in method_id
      assert!(matches!(
        IotaDID::parse(format!("did:{}:test:foo:{}", IotaDID::METHOD, valid_object_id)),
        Err(DIDError::InvalidMethodId)
      ));
    };

    execute_assertions(IotaDID::PLACEHOLDER_TAG);
    execute_assertions(VALID_OBJECT_ID_STR);
  }

  // ===========================================================================================================================
  // Test constructors with randomly generated input
  // ===========================================================================================================================

  #[cfg(feature = "iota-client")]
  proptest! {
    #[test]
    fn property_based_new(bytes in proptest::prelude::any::<[u8;32]>()) {
      for network_name in VALID_NETWORK_NAMES.iter().map(|name| NetworkName::try_from(*name).unwrap()) {
        // check that this does not panic
        IotaDID::new(&bytes, &network_name);
      }
    }
  }

  fn arbitrary_object_id_string_replica() -> impl Strategy<Value = String> {
    proptest::string::string_regex(&format!("0x([a-f]|[0-9]){{{}}}", (LEN_VALID_OBJECT_ID_STR - 2)))
      .expect("regex should be ok")
  }

  proptest! {
    #[test]
    fn valid_object_id_string_replicas(tag in arbitrary_object_id_string_replica()) {
      let did : String = format!("did:{}:{}", IotaDID::METHOD, tag);
      assert!(
        IotaDID::parse(did).is_ok()
      );
    }
  }

  fn arbitrary_invalid_tag() -> impl Strategy<Value = String> {
    proptest::string::string_regex("[[:^alpha:]|[a-z]|[1-9]]*")
      .expect("regex should be ok")
      .prop_map(|arb_string| {
        if arb_string
          .chars()
          .all(|c| c.is_ascii_hexdigit() && c.is_ascii_lowercase())
          && arb_string.len() == LEN_VALID_OBJECT_ID_STR
          && arb_string.starts_with("0x")
        {
          // this means we are in the rare case of generating a valid string hence we replace the last 0 with the non
          // ascii character é
          let mut counter = 0;
          arb_string
            .chars()
            .rev()
            .map(|value| {
              if value == '0' && counter == 0 {
                counter += 1;
                'é'
              } else {
                value
              }
            })
            .collect::<String>()
        } else {
          arb_string
        }
      })
  }

  proptest! {
    #[test]
    fn invalid_tag_property_based_parse(tag in arbitrary_invalid_tag()) {
      let did: String = format!("did:{}:{}", IotaDID::METHOD, tag);
      assert!(
        IotaDID::parse(did).is_err()
      );
    }
  }

  fn arbitrary_delimiter_mixed_in_prefix_hex() -> impl Strategy<Value = String> {
    proptest::string::string_regex("0x([a-f]|[:]|[0-9])*").expect("regex should be ok")
  }

  proptest! {
    #[test]
    fn invalid_hex_mixed_with_delimiter(tag in arbitrary_delimiter_mixed_in_prefix_hex()) {
      let did: String = format!("did:{}:{}", IotaDID::METHOD, tag);
      assert!(IotaDID::parse(did).is_err());
    }
  }

  // ===========================================================================================================================
  // Test getters
  // ===========================================================================================================================
  #[test]
  fn test_network() {
    let execute_assertions = |valid_object_id: &str| {
      let did: IotaDID = format!("did:{}:{}", IotaDID::METHOD, valid_object_id).parse().unwrap();
      assert_eq!(did.network_str(), IotaDID::DEFAULT_NETWORK);

      let did: IotaDID = format!("did:{}:dev:{}", IotaDID::METHOD, valid_object_id)
        .parse()
        .unwrap();
      assert_eq!(did.network_str(), "dev");

      let did: IotaDID = format!("did:{}:test:{}", IotaDID::METHOD, valid_object_id)
        .parse()
        .unwrap();
      assert_eq!(did.network_str(), "test");

      let did: IotaDID = format!("did:{}:custom:{}", IotaDID::METHOD, valid_object_id)
        .parse()
        .unwrap();
      assert_eq!(did.network_str(), "custom");
    };

    execute_assertions(IotaDID::PLACEHOLDER_TAG);
    execute_assertions(VALID_OBJECT_ID_STR);
  }

  #[test]
  fn test_tag() {
    let execute_assertions = |valid_object_id: &str| {
      let did: IotaDID = format!("did:{}:{}", IotaDID::METHOD, valid_object_id).parse().unwrap();
      assert_eq!(did.tag_str(), valid_object_id);

      let did: IotaDID = format!(
        "did:{}:{}:{}",
        IotaDID::METHOD,
        IotaDID::DEFAULT_NETWORK,
        valid_object_id
      )
      .parse()
      .unwrap();
      assert_eq!(did.tag_str(), valid_object_id);

      let did: IotaDID = format!("did:{}:dev:{}", IotaDID::METHOD, valid_object_id)
        .parse()
        .unwrap();
      assert_eq!(did.tag_str(), valid_object_id);

      let did: IotaDID = format!("did:{}:custom:{}", IotaDID::METHOD, valid_object_id)
        .parse()
        .unwrap();
      assert_eq!(did.tag_str(), valid_object_id);
    };
    execute_assertions(IotaDID::PLACEHOLDER_TAG);
    execute_assertions(VALID_OBJECT_ID_STR);
  }

  // ===========================================================================================================================
  // Test DIDUrl
  // ===========================================================================================================================

  #[test]
  fn test_parse_did_url_valid() {
    let execute_assertions = |valid_object_id: &str| {
      assert!(DIDUrl::parse(format!("did:{}:{}", IotaDID::METHOD, valid_object_id)).is_ok());
      assert!(DIDUrl::parse(format!("did:{}:{}#fragment", IotaDID::METHOD, valid_object_id)).is_ok());
      assert!(DIDUrl::parse(format!(
        "did:{}:{}?somequery=somevalue",
        IotaDID::METHOD,
        valid_object_id
      ))
      .is_ok());
      assert!(DIDUrl::parse(format!(
        "did:{}:{}?somequery=somevalue#fragment",
        IotaDID::METHOD,
        valid_object_id
      ))
      .is_ok());

      assert!(DIDUrl::parse(format!("did:{}:main:{}", IotaDID::METHOD, valid_object_id)).is_ok());
      assert!(DIDUrl::parse(format!("did:{}:main:{}#fragment", IotaDID::METHOD, valid_object_id)).is_ok());
      assert!(DIDUrl::parse(format!(
        "did:{}:main:{}?somequery=somevalue",
        IotaDID::METHOD,
        valid_object_id
      ))
      .is_ok());
      assert!(DIDUrl::parse(format!(
        "did:{}:main:{}?somequery=somevalue#fragment",
        IotaDID::METHOD,
        valid_object_id
      ))
      .is_ok());

      assert!(DIDUrl::parse(format!("did:{}:dev:{}", IotaDID::METHOD, valid_object_id)).is_ok());
      assert!(DIDUrl::parse(format!("did:{}:dev:{}#fragment", IotaDID::METHOD, valid_object_id)).is_ok());
      assert!(DIDUrl::parse(format!(
        "did:{}:dev:{}?somequery=somevalue",
        IotaDID::METHOD,
        valid_object_id
      ))
      .is_ok());
      assert!(DIDUrl::parse(format!(
        "did:{}:dev:{}?somequery=somevalue#fragment",
        IotaDID::METHOD,
        valid_object_id
      ))
      .is_ok());

      assert!(DIDUrl::parse(format!("did:{}:custom:{}", IotaDID::METHOD, valid_object_id)).is_ok());
      assert!(DIDUrl::parse(format!("did:{}:custom:{}#fragment", IotaDID::METHOD, valid_object_id)).is_ok());
      assert!(DIDUrl::parse(format!(
        "did:{}:custom:{}?somequery=somevalue",
        IotaDID::METHOD,
        valid_object_id
      ))
      .is_ok());
      assert!(DIDUrl::parse(format!(
        "did:{}:custom:{}?somequery=somevalue#fragment",
        IotaDID::METHOD,
        valid_object_id
      ))
      .is_ok());
    };
    execute_assertions(IotaDID::PLACEHOLDER_TAG);
    execute_assertions(VALID_OBJECT_ID_STR);
  }

  #[test]
  fn valid_url_setters() {
    let execute_assertions = |valid_object_id: &str| {
      let mut did_url: DIDUrl = IotaDID::parse(format!("did:{}:{}", IotaDID::METHOD, valid_object_id))
        .unwrap()
        .into_url();

      did_url.set_path(Some("/foo")).unwrap();
      did_url.set_query(Some("diff=true")).unwrap();
      did_url.set_fragment(Some("foo")).unwrap();

      assert_eq!(did_url.path(), Some("/foo"));
      assert_eq!(did_url.query(), Some("diff=true"));
      assert_eq!(did_url.fragment(), Some("foo"));
    };
    execute_assertions(IotaDID::PLACEHOLDER_TAG);
    execute_assertions(VALID_OBJECT_ID_STR);
  }
}
