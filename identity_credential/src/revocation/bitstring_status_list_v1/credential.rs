// Copyright 2020-2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Types for the [`BitstringStatusListCredential`], the [Verifiable Credential](CredentialV2) that hosts the
//! statuses referenced by [`BitstringStatusListEntry`] objects, as defined in
//! [Bitstring Status List Credential](https://www.w3.org/TR/vc-bitstring-status-list/#bitstringstatuslistcredential).
//!
//! Such a credential carries a bitstring in which each entry occupies [`entry_size`] bits: the entry
//! referenced by a `statusListIndex` of `i` is found at bit `i * entry_size`, counting from the left-most
//! (most significant) bit of the bitstring. Issuers publish the bitstring GZIP-compressed and
//! multibase-encoded in `credentialSubject.encodedList`, which is what [`encoded_list`] returns.
//!
//! An issuer creates a list with [`BitstringStatusListCredentialBuilder`], hosts it at the URL its entries
//! point to, and changes the status of an entry through [`update`]:
//!
//! ```
//! use identity_core::common::Url;
//! use identity_credential::credential::Issuer;
//! use identity_credential::revocation::bitstring_status_list_v1::BitstringStatusListCredentialBuilder;
//! use identity_credential::revocation::bitstring_status_list_v1::BitstringStatusListEntryBuilder;
//! use identity_credential::revocation::bitstring_status_list_v1::StatusPurpose;
//!
//! let list_url = Url::parse("https://example.com/credentials/status/3")?;
//!
//! // The issuer hosts a status list credential at `list_url`...
//! let mut status_list = BitstringStatusListCredentialBuilder::new()
//!   .id(list_url.clone())
//!   .issuer(Issuer::Url(Url::parse("did:example:12345")?))
//!   .status_purposes(StatusPurpose::Revocation)
//!   .build()?;
//!
//! // ...and references one of its entries from the credentials it issues.
//! let entry = BitstringStatusListEntryBuilder::new()
//!   .credential(list_url)
//!   .index(94567)
//!   .status_purpose(StatusPurpose::Revocation)
//!   .build()?;
//!
//! assert!(status_list.entry(94567, &StatusPurpose::Revocation)?.valid);
//!
//! // Revoking the referenced credential sets its bit and re-encodes the list.
//! status_list.update().set_entry(&entry, true)?;
//! assert!(!status_list.entry(94567, &StatusPurpose::Revocation)?.valid);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! [`entry_size`]: BitstringStatusListCredential::entry_size
//! [`encoded_list`]: BitstringStatusListCredential::encoded_list
//! [`update`]: BitstringStatusListCredential::update

use std::ops::Range;

use bitvec::bitvec;
use bitvec::field::BitField;
use bitvec::order::Msb0;
use bitvec::vec::BitVec;
use identity_core::common::Context;
use identity_core::common::Object;
use identity_core::common::OneOrMany;
use identity_core::common::Timestamp;
use identity_core::common::Url;
use serde::Deserialize;
use serde::Serialize;
use serde::Serializer;
use serde_json::Value;

use crate::credential::CredentialBuilder;
use crate::credential::CredentialV2;
use crate::credential::Issuer;
use crate::credential::Proof;
use crate::credential::Subject;
use crate::revocation::bitstring_status_list_v1::entry::BitstringStatusListEntry;
use crate::revocation::bitstring_status_list_v1::StatusMessage;
use crate::revocation::bitstring_status_list_v1::StatusPurpose;
use crate::revocation::bitstring_status_list_v1::StatusValue;

/// Type of a `BitstringStatusList` VC.
pub const CREDENTIAL_TYPE: &str = "BitstringStatusListCredential";
/// `credentialSubject.type` of a `BitstringStatusList` VC.
pub const CREDENTIAL_SUBJECT_TYPE: &str = "BitstringStatusList";
/// The number of entries the specification mandates as a minimum, i.e. a 16KB bitstring.
const MINIMUM_NUMBER_OF_ENTRIES: usize = 16 * 1024 * 8;
/// The greatest [`entry_size`](BitstringStatusListCredential::entry_size) a list may declare: a
/// status is read into a `usize`, and the number of values it can take — `2^entry_size` — must
/// itself be representable.
const MAXIMUM_ENTRY_SIZE: usize = usize::BITS as usize - 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialSubject {
  #[serde(rename = "type")]
  type_: String,
  status_purpose: OneOrMany<StatusPurpose>,
  #[serde(skip_serializing_if = "Option::is_none")]
  status_size: Option<usize>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  status_messages: Vec<StatusMessage>,
  encoded_list: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  ttl: Option<u64>,
}

impl CredentialSubject {
  /// The number of bits each entry occupies; `statusSize` defaults to 1.
  fn entry_size(&self) -> usize {
    self.status_size.unwrap_or(1)
  }
}

impl Default for CredentialSubject {
  fn default() -> Self {
    Self {
      type_: CREDENTIAL_SUBJECT_TYPE.to_owned(),
      status_purpose: OneOrMany::default(),
      status_size: None,
      status_messages: Vec::default(),
      encoded_list: String::default(),
      ttl: None,
    }
  }
}

/// A parsed [Bitstring Status List Credential](https://www.w3.org/TR/vc-bitstring-status-list/#bitstringstatuslistcredential),
/// i.e. a [`CredentialV2`] of type [`CREDENTIAL_TYPE`] whose single credential subject holds the encoded
/// bitstring.
///
/// Deserializing one validates its structure and decodes its `encodedList`; see
/// [`InvalidCredentialError`] for the ways in which that can fail. Serializing one yields the wrapped
/// Verifiable Credential unchanged, which is also reachable through [`AsRef<CredentialV2>`](AsRef) and
/// [`From<BitstringStatusListCredential>`](CredentialV2).
///
/// A verifier that has fetched the credential referenced by a `statusListIndex` reads that entry's status
/// with [`entry`](Self::entry):
///
/// ```
/// use identity_credential::revocation::bitstring_status_list_v1::BitstringStatusListCredential;
/// use identity_credential::revocation::bitstring_status_list_v1::StatusPurpose;
///
/// // The example credential from the specification.
/// let json = r#"{
///   "@context": ["https://www.w3.org/ns/credentials/v2"],
///   "id": "https://example.com/credentials/status/3",
///   "type": ["VerifiableCredential", "BitstringStatusListCredential"],
///   "issuer": "did:example:12345",
///   "validFrom": "2021-04-05T14:27:40Z",
///   "credentialSubject": {
///     "id": "https://example.com/status/3#list",
///     "type": "BitstringStatusList",
///     "statusPurpose": "revocation",
///     "encodedList": "uH4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAIC3AYbSVKsAQAAA"
///   }
/// }"#;
///
/// let status_list: BitstringStatusListCredential = serde_json::from_str(json)?;
///
/// assert_eq!(status_list.purposes(), [StatusPurpose::Revocation]);
/// assert!(status_list.entry(94567, &StatusPurpose::Revocation)?.valid);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "CredentialV2")]
pub struct BitstringStatusListCredential {
  credential: CredentialV2,
  subject: CredentialSubject,
  decoded_list: BitVec<u8, Msb0>,
}

impl BitstringStatusListCredential {
  /// Returns the credential's ID, i.e. the URL the entries of this list are expected to reference.
  pub fn id(&self) -> Option<&Url> {
    self.credential.id.as_ref()
  }

  /// Returns the purposes this status list serves, i.e. what the bits of its entries encode.
  ///
  /// Only entries whose
  /// [`status_purpose`](crate::revocation::bitstring_status_list_v1::entry::BitstringStatusListEntry::status_purpose)
  /// is one of these can be read or written.
  pub fn purposes(&self) -> &[StatusPurpose] {
    self.subject.status_purpose.as_slice()
  }

  /// Returns `credentialSubject.encodedList`: the credential's bitstring, GZIP-compressed and
  /// multibase-encoded.
  ///
  /// It is kept in sync with the statuses set through [`update`](Self::update).
  pub fn encoded_list(&self) -> &str {
    &self.subject.encoded_list
  }

  /// Returns the optional `credentialSubject.ttl`: how long, in milliseconds, a cached copy of this
  /// credential may be used before it should be fetched again.
  pub fn ttl(&self) -> Option<u64> {
    self.subject.ttl
  }

  /// Returns the number of bits each entry of this list occupies, i.e. `credentialSubject.statusSize`,
  /// which defaults to 1.
  ///
  /// An entry's status is therefore a value in `0..2^entry_size`, and lists with an `entry_size` greater
  /// than 1 name each of those values through a [`StatusMessage`].
  pub fn entry_size(&self) -> usize {
    self.subject.entry_size()
  }

  /// Returns the status of the entry at `index` for the given `purpose`.
  ///
  /// ```
  /// # use identity_core::common::Url;
  /// # use identity_credential::credential::Issuer;
  /// # use identity_credential::revocation::bitstring_status_list_v1::BitstringStatusListCredentialBuilder;
  /// # use identity_credential::revocation::bitstring_status_list_v1::StatusPurpose;
  /// # let status_list = BitstringStatusListCredentialBuilder::new()
  /// #   .issuer(Issuer::Url(Url::parse("did:example:12345")?))
  /// #   .status_purposes(StatusPurpose::Revocation)
  /// #   .build()?;
  /// let status = status_list.entry(94567, &StatusPurpose::Revocation)?;
  ///
  /// // Nothing has been revoked in this list yet.
  /// assert_eq!(status.status, 0);
  /// assert!(status.valid);
  /// # Ok::<(), Box<dyn std::error::Error>>(())
  /// ```
  ///
  /// ## Errors
  /// - [EntryStatusError::PurposeMismatch] if this list does not serve `purpose`;
  /// - [EntryStatusError::OutOfRange] if `index` is beyond the end of the list;
  /// - [EntryStatusError::InvalidStatusMessage] if `purpose` is [`StatusPurpose::Message`] but the entry's value is not
  ///   one of the credential's `statusMessages`.
  pub fn entry(&self, index: usize, purpose: &StatusPurpose) -> Result<EntryStatus<'_>, EntryStatusError> {
    if !self.subject.status_purpose.contains(purpose) {
      return Err(EntryStatusError::PurposeMismatch(purpose.clone()));
    }

    let range = self.entry_range(index)?;
    // `entry_size` is `1..=MAXIMUM_ENTRY_SIZE` for any credential that can be built or parsed, so
    // the region is neither empty nor wider than the `usize` it is read into.
    let status: usize = self.decoded_list[range].load_be();
    let mut result = EntryStatus {
      status,
      valid: status == 0,
      purpose: purpose.clone(),
      message: None,
    };

    if purpose == &StatusPurpose::Message {
      let message = self
        .subject
        .status_messages
        .iter()
        .find(|message| message.status == status)
        .ok_or(EntryStatusError::InvalidStatusMessage(status))?;
      result.message = Some(message);
    }

    Ok(result)
  }

  /// Returns a handle through which the statuses of this credential's entries can be set.
  ///
  /// The credential's [`encoded_list`](Self::encoded_list) is recomputed when the returned
  /// [`StatusListMut`] is dropped, and only if a status actually changed.
  pub fn update(&mut self) -> StatusListMut<'_> {
    StatusListMut {
      credential: self,
      dirty: false,
    }
  }

  /// Returns the range of bits the entry at `index` occupies.
  fn entry_range(&self, index: usize) -> Result<Range<usize>, IndexOutOfBounds> {
    let entry_size = self.entry_size();
    let left = index.checked_mul(entry_size).ok_or(IndexOutOfBounds(index))?;
    let right = left.checked_add(entry_size).ok_or(IndexOutOfBounds(index))?;

    if self.decoded_list.len() < right {
      return Err(IndexOutOfBounds(index));
    }

    Ok(left..right)
  }

  /// Re-encodes the bitstring into `encodedList`, the two copies of which — the parsed subject's and
  /// the wrapped credential's — must always agree.
  fn sync_encoded_list(&mut self) {
    let encoded_list = encode_status_list(&self.decoded_list);

    self
      .credential
      .credential_subject
      .get_mut(0)
      .expect("a status list credential has exactly one credential subject")
      .properties
      .insert("encodedList".to_owned(), encoded_list.clone().into());
    self.subject.encoded_list = encoded_list;
  }
}

impl Serialize for BitstringStatusListCredential {
  /// Serializes the wrapped Verifiable Credential, unchanged.
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    self.credential.serialize(serializer)
  }
}

impl AsRef<CredentialV2> for BitstringStatusListCredential {
  fn as_ref(&self) -> &CredentialV2 {
    &self.credential
  }
}

impl TryFrom<CredentialV2> for BitstringStatusListCredential {
  type Error = InvalidCredentialError;
  fn try_from(credential: CredentialV2) -> Result<Self, Self::Error> {
    // Ensure Credential has type "BitstringStatusListCredential".
    if !credential.types.iter().any(|ty| ty.as_str() == CREDENTIAL_TYPE) {
      return Err(InvalidCredentialError::InvalidCredentialType);
    }

    // A status list credential describes exactly one status list. Note that a single subject may be
    // encoded either on its own or as a one-element array.
    let [subject] = credential.credential_subject.as_slice() else {
      return Err(InvalidCredentialError::MultipleCredentialSubjects);
    };

    let subject_properties = Value::Object(subject.properties.clone().into_iter().collect());
    let subject: CredentialSubject =
      serde_json::from_value(subject_properties).map_err(InvalidCredentialError::InvalidCredentialSubject)?;

    if subject.type_.as_str() != CREDENTIAL_SUBJECT_TYPE {
      return Err(InvalidCredentialError::InvalidSubjectType(subject.type_));
    }

    // An entry's status is read into a `usize`, which bounds how wide `statusSize` may be.
    let entry_size = subject.entry_size();
    if !(1..=MAXIMUM_ENTRY_SIZE).contains(&entry_size) {
      return Err(InvalidCredentialError::InvalidStatusSize(entry_size));
    }

    // A "message" list names each of the values its entries can take.
    if subject.status_purpose.contains(&StatusPurpose::Message) {
      let size = subject.status_size.ok_or(InvalidCredentialError::MissingStatusSize)?;
      // `size` is at most `MAXIMUM_ENTRY_SIZE`, so the shift cannot overflow.
      let expected = 1usize << size;
      if subject.status_messages.len() != expected {
        return Err(InvalidCredentialError::InvalidMessageCount {
          got: subject.status_messages.len(),
          expected,
        });
      }
    }

    let decoded_list = decode_status_list(&subject.encoded_list)?;

    Ok(Self {
      credential,
      subject,
      decoded_list,
    })
  }
}

impl From<BitstringStatusListCredential> for CredentialV2 {
  fn from(value: BitstringStatusListCredential) -> Self {
    value.credential
  }
}

/// The status of a single entry of a [`BitstringStatusListCredential`], as returned by
/// [`BitstringStatusListCredential::entry`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct EntryStatus<'a> {
  /// The value encoded by the entry's bits.
  pub status: usize,
  /// Whether the entry is unset, i.e. whether [`status`](Self::status) is 0.
  ///
  /// For a `revocation` list this means the referenced credential has not been revoked, for a `suspension`
  /// list that it is not suspended, and so on.
  pub valid: bool,
  /// The purpose the status was read for, which describes what [`status`](Self::status) means.
  pub purpose: StatusPurpose,
  /// The message naming this status, set only for [`StatusPurpose::Message`] entries.
  pub message: Option<&'a StatusMessage>,
}

/// A handle that sets the statuses of a [`BitstringStatusListCredential`]'s entries, obtained from
/// [`BitstringStatusListCredential::update`].
///
/// Dropping it re-encodes the credential's `encodedList` from the updated bitstring, unless every
/// [`set_entry`](Self::set_entry) call returned an error and the bitstring is therefore unchanged.
#[derive(Debug)]
pub struct StatusListMut<'a> {
  credential: &'a mut BitstringStatusListCredential,
  /// Whether a status was changed, i.e. whether `encodedList` has to be recomputed.
  dirty: bool,
}

impl StatusListMut<'_> {
  /// Sets the status of the entry referenced by `entry` to `value`.
  ///
  /// `value` is either a `bool`, for the single-bit entries of a `revocation`, `suspension` or `refresh`
  /// list, or one of the credential's [`StatusMessage`]s, for the wider entries of a `message` list.
  ///
  /// ```
  /// # use identity_core::common::Url;
  /// # use identity_credential::credential::Issuer;
  /// # use identity_credential::revocation::bitstring_status_list_v1::credential::SetEntryError;
  /// # use identity_credential::revocation::bitstring_status_list_v1::BitstringStatusListCredentialBuilder;
  /// # use identity_credential::revocation::bitstring_status_list_v1::BitstringStatusListEntryBuilder;
  /// # use identity_credential::revocation::bitstring_status_list_v1::StatusPurpose;
  /// # let list_url = Url::parse("https://example.com/credentials/status/3")?;
  /// # let mut status_list = BitstringStatusListCredentialBuilder::new()
  /// #   .id(list_url.clone())
  /// #   .issuer(Issuer::Url(Url::parse("did:example:12345")?))
  /// #   .status_purposes(StatusPurpose::Revocation)
  /// #   .build()?;
  /// let entry = BitstringStatusListEntryBuilder::new()
  ///   .credential(list_url)
  ///   .index(94567)
  ///   .status_purpose(StatusPurpose::Revocation)
  ///   .build()?;
  ///
  /// status_list.update().set_entry(&entry, true)?;
  /// assert!(!status_list.entry(94567, &StatusPurpose::Revocation)?.valid);
  ///
  /// // A revocation cannot be taken back.
  /// let err = status_list.update().set_entry(&entry, false).unwrap_err();
  /// assert!(matches!(err, SetEntryError::IrreversibleStatus));
  /// # Ok::<(), Box<dyn std::error::Error>>(())
  /// ```
  ///
  /// ## Errors
  /// - [SetEntryError::CredentialMismatch] if `entry` references a different status list credential;
  /// - [SetEntryError::InvalidPurpose] if this list does not serve the entry's purpose;
  /// - [SetEntryError::EntrySizeMismatch] if the entry's statuses are not as wide as this credential's;
  /// - [SetEntryError::InvalidMessage] if `value` is a message that either this credential or `entry` does not declare;
  /// - [SetEntryError::StatusOutOfRange] if `value` does not fit in an entry of this credential;
  /// - [SetEntryError::OutOfRange] if the entry's index is beyond the end of the list;
  /// - [SetEntryError::IrreversibleStatus] if `value` would unset a `revocation` or `refresh` entry.
  pub fn set_entry<'v>(
    &mut self,
    entry: &BitstringStatusListEntry,
    value: impl Into<StatusValue<'v>>,
  ) -> Result<&mut Self, SetEntryError> {
    // Ensure entry actually references this credential. An unidentified credential cannot be
    // referenced by an entry, so there is nothing to compare it against.
    if let Some(id) = self.credential.id() {
      if id != entry.status_list_credential() {
        return Err(SetEntryError::CredentialMismatch {
          expected: entry.status_list_credential().clone(),
          got: id.clone(),
        });
      }
    }
    // Ensure entry's purpose is among the credential's purpose.
    if !self.credential.subject.status_purpose.contains(entry.status_purpose()) {
      return Err(SetEntryError::InvalidPurpose(entry.status_purpose().clone()));
    }
    // Ensure the entry describes statuses as wide as this credential's; otherwise its index would
    // address a different range of bits than the issuer intended.
    let entry_size = self.credential.entry_size();
    if entry.status_size() != entry_size {
      return Err(SetEntryError::EntrySizeMismatch {
        expected: entry_size,
        got: entry.status_size(),
      });
    }

    let value = value.into();
    if let StatusValue::Message(message) = value {
      if !self.credential.subject.status_messages.contains(message) || !entry.status_message().contains(message) {
        return Err(SetEntryError::InvalidMessage(message.clone()));
      }
    }

    let new_status_value = usize::from(value);
    // Storing a wider value than the entry would silently discard its most significant bits.
    if new_status_value >= 1usize << entry_size {
      return Err(SetEntryError::StatusOutOfRange {
        status: new_status_value,
        entry_size,
      });
    }

    let range = self.credential.entry_range(entry.status_list_index())?;
    let current_status_value = self.credential.decoded_list[range.clone()].load_be::<usize>();

    // Ensure revoked and refreshed entries cannot be reverted.
    if matches!(
      entry.status_purpose(),
      StatusPurpose::Refresh | StatusPurpose::Revocation
    ) && current_status_value != 0
      && new_status_value == 0
    {
      return Err(SetEntryError::IrreversibleStatus);
    }

    self.credential.decoded_list[range].store_be(new_status_value);
    self.dirty = true;

    Ok(self)
  }
}

impl Drop for StatusListMut<'_> {
  fn drop(&mut self) {
    if self.dirty {
      self.credential.sync_encoded_list();
    }
  }
}

/// Builder structure for [`BitstringStatusListCredential`]s.
///
/// [`issuer`](Self::issuer) and at least one purpose — set through
/// [`status_purposes`](Self::status_purposes), or implied by [`status_messages`](Self::status_messages) —
/// are required; everything else has a default.
///
/// ```
/// # use identity_core::common::Url;
/// # use identity_credential::credential::Issuer;
/// use identity_credential::revocation::bitstring_status_list_v1::BitstringStatusListCredentialBuilder;
/// use identity_credential::revocation::bitstring_status_list_v1::StatusPurpose;
///
/// let status_list = BitstringStatusListCredentialBuilder::new()
///   .id(Url::parse("https://example.com/credentials/status/3")?)
///   .issuer(Issuer::Url(Url::parse("did:example:12345")?))
///   .status_purposes(vec![StatusPurpose::Revocation, StatusPurpose::Suspension])
///   .number_of_entries(200_000)
///   .ttl(300_000)
///   .build()?;
///
/// assert_eq!(
///   status_list.purposes(),
///   [StatusPurpose::Revocation, StatusPurpose::Suspension]
/// );
/// assert_eq!(status_list.entry_size(), 1);
/// assert_eq!(status_list.ttl(), Some(300_000));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug)]
pub struct BitstringStatusListCredentialBuilder {
  inner_builder: CredentialBuilder,
  subject: CredentialSubject,
  number_of_entries: Option<usize>,
}

impl Default for BitstringStatusListCredentialBuilder {
  fn default() -> Self {
    Self::new()
  }
}

impl BitstringStatusListCredentialBuilder {
  /// Returns a new [`BitstringStatusListCredentialBuilder`].
  pub fn new() -> Self {
    Self {
      inner_builder: CredentialBuilder::new(Object::default()),
      number_of_entries: None,
      subject: CredentialSubject::default(),
    }
  }

  /// Sets how many entries the status list can hold, i.e. the greatest `statusListIndex` an entry may
  /// reference, plus one.
  ///
  /// Defaults to — and may not be less than — the 131072 entries the specification mandates as a minimum to
  /// provide herd privacy.
  pub fn number_of_entries(mut self, n: usize) -> Self {
    self.number_of_entries = Some(n);
    self
  }

  /// Sets the purposes this status list serves, i.e. what the bits of its entries encode.
  pub fn status_purposes(mut self, purposes: impl Into<OneOrMany<StatusPurpose>>) -> Self {
    self.subject.status_purpose = purposes.into();
    self
  }

  /// Sets the messages naming the statuses this list's entries can take.
  ///
  /// Their number must be a power of two greater than 1, and determines how many bits each entry occupies:
  /// `N` messages make for `log2(N)`-bit entries. Setting them also adds [`StatusPurpose::Message`] to the
  /// list's purposes.
  ///
  /// ```
  /// # use identity_core::common::Url;
  /// # use identity_credential::credential::Issuer;
  /// # use identity_credential::revocation::bitstring_status_list_v1::BitstringStatusListCredentialBuilder;
  /// # use identity_credential::revocation::bitstring_status_list_v1::BitstringStatusListEntryBuilder;
  /// use identity_credential::revocation::bitstring_status_list_v1::StatusMessage;
  /// use identity_credential::revocation::bitstring_status_list_v1::StatusPurpose;
  ///
  /// let messages = vec![
  ///   StatusMessage::new(0, "pending_review"),
  ///   StatusMessage::new(1, "accepted"),
  ///   StatusMessage::new(2, "rejected"),
  ///   StatusMessage::new(3, "withdrawn"),
  /// ];
  /// # let list_url = Url::parse("https://example.com/credentials/status/8")?;
  /// let mut status_list = BitstringStatusListCredentialBuilder::new()
  ///   .id(list_url.clone())
  ///   .issuer(Issuer::Url(Url::parse("did:example:12345")?))
  ///   .status_messages(messages.clone())
  ///   .build()?;
  ///
  /// // Four messages need two bits per entry, and imply the "message" purpose.
  /// assert_eq!(status_list.entry_size(), 2);
  /// assert_eq!(status_list.purposes(), [StatusPurpose::Message]);
  ///
  /// # let entry = BitstringStatusListEntryBuilder::new()
  /// #   .credential(list_url)
  /// #   .index(4711)
  /// #   .status_purpose(StatusPurpose::Message)
  /// #   .messages(messages.clone())
  /// #   .build()?;
  /// status_list.update().set_entry(&entry, &messages[2])?;
  ///
  /// let status = status_list.entry(4711, &StatusPurpose::Message)?;
  /// assert_eq!(status.status, 2);
  /// assert_eq!(status.message, Some(&messages[2]));
  /// # Ok::<(), Box<dyn std::error::Error>>(())
  /// ```
  pub fn status_messages(mut self, messages: Vec<StatusMessage>) -> Self {
    self.subject.status_messages = messages;
    self
  }

  /// Sets `credentialSubject.ttl`: how long, in milliseconds, a cached copy of this credential may be used
  /// before it should be fetched again.
  pub fn ttl(mut self, ttl: u64) -> Self {
    self.subject.ttl = Some(ttl);
    self
  }

  /// Sets the credential's ID.
  pub fn id(mut self, id: Url) -> Self {
    self.inner_builder.id = Some(id);
    self
  }

  /// Sets `validFrom`.
  pub fn valid_from(mut self, time: Timestamp) -> Self {
    self.inner_builder.issuance_date = Some(time);
    self
  }

  /// Sets `validUntil`.
  pub fn valid_until(mut self, time: Timestamp) -> Self {
    self.inner_builder.expiration_date = Some(time);
    self
  }

  /// Sets `issuer`.
  pub fn issuer(mut self, issuer: Issuer) -> Self {
    self.inner_builder.issuer = Some(issuer);
    self
  }

  /// Adds a `@context` entry.
  pub fn context(mut self, ctx: Context) -> Self {
    self.inner_builder.context.push(ctx);
    self
  }

  /// Adds a `type` entry.
  pub fn add_type(mut self, type_: String) -> Self {
    self.inner_builder.types.push(type_);
    self
  }

  /// Adds a credential proof.
  pub fn proof(mut self, proof: Proof) -> Self {
    self.inner_builder.proof = Some(proof);
    self
  }

  /// Consumes this builder, returning a [`BitstringStatusListCredential`] whose entries are all unset.
  ///
  /// ## Errors
  /// - [BuilderError::TooFewEntries] if fewer entries than the specification's minimum were requested;
  /// - [BuilderError::MissingPurpose] if no purpose was set;
  /// - [BuilderError::InvalidNumberOfStatusMessages] if the number of status messages is not a power of two greater
  ///   than 1;
  /// - [BuilderError::InvalidStatusMessageValues] if the status messages do not name each of the values an entry can
  ///   take exactly once;
  /// - [BuilderError::CredentialBuilderError] if the underlying Verifiable Credential is incomplete, e.g. when no
  ///   issuer was set.
  pub fn build(mut self) -> Result<BitstringStatusListCredential, BuilderError> {
    let number_of_entries = match self.number_of_entries {
      Some(n) if n >= MINIMUM_NUMBER_OF_ENTRIES => n,
      Some(n) => return Err(BuilderError::TooFewEntries(n)),
      None => MINIMUM_NUMBER_OF_ENTRIES,
    };
    if !self.subject.status_messages.is_empty() || self.subject.status_purpose.contains(&StatusPurpose::Message) {
      // `N` messages name the values of a `log2(N)`-bit status.
      let number_of_messages = self.subject.status_messages.len();
      if !(number_of_messages.is_power_of_two() && number_of_messages > 1) {
        return Err(BuilderError::InvalidNumberOfStatusMessages);
      }

      // Every one of those values must be named exactly once: an unnamed value cannot be read back
      // out, and one that does not fit in an entry cannot be stored in the first place.
      let mut is_named = vec![false; number_of_messages];
      for message in &self.subject.status_messages {
        match is_named.get_mut(message.status) {
          Some(is_named) if !*is_named => *is_named = true,
          _ => return Err(BuilderError::InvalidStatusMessageValues(number_of_messages)),
        }
      }

      self.subject.status_size = Some(number_of_messages.trailing_zeros() as usize);
      if !self.subject.status_purpose.contains(&StatusPurpose::Message) {
        self.subject.status_purpose.push(StatusPurpose::Message);
      }
    }

    if self.subject.status_purpose.is_empty() {
      return Err(BuilderError::MissingPurpose);
    }

    // Everything is valid, so the list can be allocated and encoded.
    let status_list = bitvec![u8, Msb0; 0; number_of_entries * self.subject.entry_size()];
    self.subject.encoded_list = encode_status_list(&status_list);

    self.inner_builder.types.push(CREDENTIAL_TYPE.to_owned());
    let Value::Object(subject_properties) =
      serde_json::to_value(&self.subject).expect("a credential subject serializes to a JSON object")
    else {
      unreachable!("a credential subject serializes to a JSON object")
    };
    let subject = Subject::with_properties(subject_properties.into_iter().collect());
    self.inner_builder.subject.push(subject);
    let credential = self.inner_builder.build_v2()?;

    Ok(BitstringStatusListCredential {
      credential,
      subject: self.subject,
      decoded_list: status_list,
    })
  }
}

/// Error that may be returned by [`BitstringStatusListCredentialBuilder::build`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BuilderError {
  /// Fewer entries than the specification's minimum were requested.
  #[error("the minimum number of entries in the status list is {MINIMUM_NUMBER_OF_ENTRIES}, got {0}")]
  TooFewEntries(usize),
  /// No status purpose was set.
  #[error("a status purpose must be specified")]
  MissingPurpose,
  /// Invalid number of status messages.
  #[error("the number of status messages must be a power of two greater than 1")]
  InvalidNumberOfStatusMessages,
  /// The status messages do not name each of the values an entry can take exactly once.
  #[error("status messages must name each of the {0} values an entry can take exactly once")]
  InvalidStatusMessageValues(usize),
  /// The underlying Verifiable Credential could not be built.
  #[error(transparent)]
  CredentialBuilderError(#[from] crate::Error),
}

/// Error that may be returned by [`StatusListMut::set_entry`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SetEntryError {
  /// The entry references another status list credential.
  #[error("expected credential with ID \"{expected}\", got \"{got}\"")]
  CredentialMismatch {
    /// The credential the entry references.
    expected: Url,
    /// The credential the entry was applied to.
    got: Url,
  },
  /// The credential does not serve the entry's purpose.
  #[error("credential does not contain purpose \"{}\"", .0.as_str())]
  InvalidPurpose(StatusPurpose),
  /// The entry's statuses are not as wide as the credential's.
  #[error("expected an entry with a status size of {expected}, got {got}")]
  EntrySizeMismatch {
    /// The number of bits the credential's entries occupy.
    expected: usize,
    /// The number of bits the entry declares.
    got: usize,
  },
  /// The status message is not one of those the credential and the entry declare.
  #[error("credential does not contain status message \"{}\"", .0.message.as_str())]
  InvalidMessage(StatusMessage),
  /// The status does not fit in the credential's entries.
  #[error("status {status:#x} does not fit in a {entry_size}-bit entry")]
  StatusOutOfRange {
    /// The status that was to be set.
    status: usize,
    /// The number of bits the credential's entries occupy.
    entry_size: usize,
  },
  /// The entry's index lies outside the status list.
  #[error(transparent)]
  OutOfRange(#[from] IndexOutOfBounds),
  /// An attempt was made to unset a `revocation` or `refresh` entry, which the specification defines as
  /// irreversible.
  #[error("status \"revocation\" and \"refresh\" cannot be reverted")]
  IrreversibleStatus,
}

/// Error returned when a [`CredentialV2`] is not a valid [`BitstringStatusListCredential`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum InvalidCredentialError {
  /// The credential's `type` does not include [`CREDENTIAL_TYPE`].
  #[error("invalid credential type, \"BitstringStatusListCredential\" was expected")]
  InvalidCredentialType,
  /// The credential does not have exactly one `credentialSubject`.
  #[error("expected exactly one credential subject")]
  MultipleCredentialSubjects,
  /// The credential subject's `type` is not [`CREDENTIAL_SUBJECT_TYPE`].
  #[error("invalid credential subject's type: got \"{0}\", expected \"{CREDENTIAL_SUBJECT_TYPE}\"")]
  InvalidSubjectType(String),
  /// `statusSize` is zero, or wider than a status can be read into.
  #[error("invalid \"statusSize\" {0}, expected an integer between 1 and {MAXIMUM_ENTRY_SIZE}")]
  InvalidStatusSize(usize),
  /// `statusSize` is missing from a credential that serves the `message` purpose.
  #[error("property \"statusSize\" must be set when \"statusPurpose\" is \"message\"")]
  MissingStatusSize,
  /// The number of `statusMessages` does not match the one `statusSize` calls for, i.e. `2^statusSize`.
  #[error("invalid number of \"statusMessages\": got {got}, expected {expected}")]
  InvalidMessageCount {
    /// The number of messages the credential declares.
    got: usize,
    /// The number of messages `statusSize` calls for.
    expected: usize,
  },
  /// The credential subject is missing a mandatory property, or one of its properties has the wrong type.
  #[error("failed to parse a valid \"BitstringStatusList\" credential subject")]
  InvalidCredentialSubject(#[source] serde_json::Error),
  /// `encodedList` is not a multibase string.
  ///
  /// The source error is deliberately opaque: it comes from a pre-1.0 crate whose type must not leak
  /// into this crate's public API.
  #[error("\"encodedList\" is not a valid multibase string")]
  InvalidStatusListEncoding(#[source] Box<dyn std::error::Error + Send + Sync>),
  /// `encodedList` is not a GZIP-compressed bitstring.
  #[error("failed to decode \"encodedList\"")]
  StatusListDecoding(#[source] std::io::Error),
}

/// Error that may be returned by [`BitstringStatusListCredential::entry`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EntryStatusError {
  /// The requested index lies outside the status list.
  #[error(transparent)]
  OutOfRange(#[from] IndexOutOfBounds),
  /// The credential does not serve the requested purpose.
  #[error("credential does not contain purpose \"{}\"", .0.as_str())]
  PurposeMismatch(StatusPurpose),
  /// The entry's value is not one of the statuses the credential's `statusMessages` name.
  #[error("status message \"{0:#x}\" does not exist")]
  InvalidStatusMessage(usize),
}

/// Error returned when an entry's index lies outside the bounds of a status list.
#[derive(Debug, thiserror::Error)]
#[error("entry {0} is outside the list's bounds")]
pub struct IndexOutOfBounds(usize);

impl IndexOutOfBounds {
  /// Returns the `statusListIndex` that lies outside the list.
  pub fn index(&self) -> usize {
    self.0
  }
}

fn encode_status_list(status_list: &BitVec<u8, Msb0>) -> String {
  use flate2::read::GzEncoder;
  use multibase::Base;
  use std::io::Read as _;

  let mut encoder = GzEncoder::new(status_list.as_raw_slice(), flate2::Compression::best());
  let mut compressed_bitstring = vec![];
  encoder
    .read_to_end(&mut compressed_bitstring)
    .expect("compressing an in-memory buffer cannot fail");
  multibase::encode(Base::Base64Url, compressed_bitstring)
}

fn decode_status_list(encoded_list: &str) -> Result<BitVec<u8, Msb0>, InvalidCredentialError> {
  use std::io::Write as _;

  let (_base, compressed_list) =
    multibase::decode(encoded_list).map_err(|err| InvalidCredentialError::InvalidStatusListEncoding(Box::new(err)))?;

  let mut decoder = flate2::write::GzDecoder::new(Vec::<u8>::new());
  let bitstring = decoder
    .write_all(&compressed_list)
    .and_then(move |_| decoder.finish())
    .map_err(InvalidCredentialError::StatusListDecoding)?;

  Ok(BitVec::from_vec(bitstring))
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::revocation::bitstring_status_list_v1::entry::BitstringStatusListEntryBuilder;

  /// The example `BitstringStatusListCredential` taken verbatim from
  /// [the specification](https://www.w3.org/TR/vc-bitstring-status-list/#bitstringstatuslistcredential).
  const SPEC_CREDENTIAL_JSON: &str = include_str!("./fixtures/credential-1.json");
  const CREDENTIAL_URL: &str = "https://example.com/credentials/status/3";
  const MESSAGE_CREDENTIAL_URL: &str = "https://example.com/credentials/status/8";

  fn url(url: &str) -> Url {
    Url::parse(url).unwrap()
  }

  fn issuer() -> Issuer {
    Issuer::Url(url("did:example:12345"))
  }

  fn spec_credential() -> BitstringStatusListCredential {
    serde_json::from_str(SPEC_CREDENTIAL_JSON).expect("the specification's example credential is valid")
  }

  /// Returns the specification's example credential, after applying `f` to its JSON representation.
  fn patched_credential(f: impl FnOnce(&mut serde_json::Map<String, Value>)) -> CredentialV2 {
    let mut credential: Value = serde_json::from_str(SPEC_CREDENTIAL_JSON).unwrap();
    f(credential.as_object_mut().unwrap());
    serde_json::from_value(credential).expect("a valid VC 2.0 credential")
  }

  /// Returns the specification's example credential, after applying `f` to its `credentialSubject`.
  fn patched_subject(f: impl FnOnce(&mut serde_json::Map<String, Value>)) -> CredentialV2 {
    patched_credential(|credential| {
      let subject = credential
        .get_mut("credentialSubject")
        .and_then(Value::as_object_mut)
        .unwrap();
      f(subject)
    })
  }

  fn credential_builder() -> BitstringStatusListCredentialBuilder {
    BitstringStatusListCredentialBuilder::new()
      .issuer(issuer())
      .id(url(CREDENTIAL_URL))
  }

  fn entry(index: usize, purpose: StatusPurpose) -> BitstringStatusListEntry {
    BitstringStatusListEntryBuilder::new()
      .credential(url(CREDENTIAL_URL))
      .index(index)
      .status_purpose(purpose)
      .build()
      .unwrap()
  }

  fn status_messages() -> Vec<StatusMessage> {
    vec![
      StatusMessage::new(0, "pending_review"),
      StatusMessage::new(1, "accepted"),
      StatusMessage::new(2, "rejected"),
      StatusMessage::new(3, "withdrawn"),
    ]
  }

  fn decoded(encoded_list: &str) -> BitVec<u8, Msb0> {
    decode_status_list(encoded_list).expect("a valid encoded status list")
  }

  #[test]
  fn deserialization_of_the_spec_example_credential_works() {
    let credential = spec_credential();

    assert_eq!(credential.purposes(), [StatusPurpose::Revocation]);
    assert_eq!(credential.entry_size(), 1);
    assert_eq!(credential.ttl(), None);
    assert_eq!(credential.id(), Some(&url(CREDENTIAL_URL)));
    // The list is a 16KB bitstring in which nothing is revoked.
    assert_eq!(credential.decoded_list.len(), MINIMUM_NUMBER_OF_ENTRIES);
    assert_eq!(decoded(credential.encoded_list()).len(), MINIMUM_NUMBER_OF_ENTRIES);
    assert!(credential.decoded_list.not_any());
  }

  #[test]
  fn serialization_of_a_deserialized_credential_is_lossless() {
    let expected: Value = serde_json::from_str(SPEC_CREDENTIAL_JSON).unwrap();
    let credential = spec_credential();

    assert_eq!(serde_json::to_value(&credential).unwrap(), expected);
  }

  #[test]
  fn reading_the_status_of_an_unrevoked_entry_works() {
    let credential = spec_credential();

    let status = credential.entry(94567, &StatusPurpose::Revocation).unwrap();

    assert_eq!(status.status, 0);
    assert!(status.valid);
    assert_eq!(status.purpose, StatusPurpose::Revocation);
    assert_eq!(status.message, None);
  }

  #[test]
  fn reading_an_entry_with_a_purpose_the_credential_does_not_serve_fails() {
    let err = spec_credential().entry(94567, &StatusPurpose::Suspension).unwrap_err();

    std::assert_matches!(err, EntryStatusError::PurposeMismatch(StatusPurpose::Suspension));
  }

  #[test]
  fn reading_an_out_of_bounds_entry_fails() {
    let err = spec_credential()
      .entry(MINIMUM_NUMBER_OF_ENTRIES, &StatusPurpose::Revocation)
      .unwrap_err();

    std::assert_matches!(
      err,
      EntryStatusError::OutOfRange(IndexOutOfBounds(MINIMUM_NUMBER_OF_ENTRIES))
    );
  }

  #[test]
  fn deserialization_of_a_credential_without_the_expected_type_fails() {
    let credential = patched_credential(|credential| {
      credential.insert("type".to_owned(), serde_json::json!(["VerifiableCredential"]));
    });

    let err = BitstringStatusListCredential::try_from(credential).unwrap_err();

    std::assert_matches!(err, InvalidCredentialError::InvalidCredentialType);
  }

  #[test]
  fn deserialization_of_a_credential_with_multiple_subjects_fails() {
    let credential = patched_credential(|credential| {
      let subject = credential.get("credentialSubject").cloned().unwrap();
      credential.insert("credentialSubject".to_owned(), serde_json::json!([subject, subject]));
    });

    let err = BitstringStatusListCredential::try_from(credential).unwrap_err();

    std::assert_matches!(err, InvalidCredentialError::MultipleCredentialSubjects);
  }

  #[test]
  fn deserialization_of_a_credential_with_an_invalid_subject_type_fails() {
    let credential = patched_subject(|subject| {
      subject.insert("type".to_owned(), "StatusList2021".into());
    });

    let err = BitstringStatusListCredential::try_from(credential).unwrap_err();

    std::assert_matches!(err, InvalidCredentialError::InvalidSubjectType(ty) if ty == "StatusList2021");
  }

  #[test]
  fn deserialization_of_a_credential_without_an_encoded_list_fails() {
    let credential = patched_subject(|subject| {
      subject.remove("encodedList");
    });

    let err = BitstringStatusListCredential::try_from(credential).unwrap_err();

    std::assert_matches!(err, InvalidCredentialError::InvalidCredentialSubject(_));
  }

  #[test]
  fn deserialization_of_a_message_credential_without_status_size_fails() {
    let credential = patched_subject(|subject| {
      subject.insert("statusPurpose".to_owned(), "message".into());
      subject.insert(
        "statusMessages".to_owned(),
        serde_json::to_value(status_messages()).unwrap(),
      );
    });

    let err = BitstringStatusListCredential::try_from(credential).unwrap_err();

    std::assert_matches!(err, InvalidCredentialError::MissingStatusSize);
  }

  #[test]
  fn deserialization_of_a_message_credential_with_a_wrong_number_of_messages_fails() {
    let credential = patched_subject(|subject| {
      let mut messages = status_messages();
      messages.pop();
      subject.insert("statusPurpose".to_owned(), "message".into());
      subject.insert("statusSize".to_owned(), 2.into());
      subject.insert("statusMessages".to_owned(), serde_json::to_value(messages).unwrap());
    });

    let err = BitstringStatusListCredential::try_from(credential).unwrap_err();

    std::assert_matches!(err, InvalidCredentialError::InvalidMessageCount { got: 3, expected: 4 });
  }

  #[test]
  fn deserialization_of_a_credential_with_a_non_multibase_encoded_list_fails() {
    let credential = patched_subject(|subject| {
      subject.insert("encodedList".to_owned(), "not a multibase string".into());
    });

    let err = BitstringStatusListCredential::try_from(credential).unwrap_err();

    std::assert_matches!(err, InvalidCredentialError::InvalidStatusListEncoding(_));
  }

  #[test]
  fn deserialization_of_a_credential_with_a_non_compressed_encoded_list_fails() {
    let credential = patched_subject(|subject| {
      let uncompressed = multibase::encode(multibase::Base::Base64Url, b"not a gzip stream");
      subject.insert("encodedList".to_owned(), uncompressed.into());
    });

    let err = BitstringStatusListCredential::try_from(credential).unwrap_err();

    std::assert_matches!(err, InvalidCredentialError::StatusListDecoding(_));
  }

  #[test]
  fn building_a_credential_works() {
    let credential = credential_builder()
      .status_purposes(StatusPurpose::Revocation)
      .ttl(300_000)
      .valid_from(Timestamp::parse("2021-04-05T14:27:40Z").unwrap())
      .valid_until(Timestamp::parse("2031-04-05T14:27:40Z").unwrap())
      .build()
      .unwrap();

    assert_eq!(credential.purposes(), [StatusPurpose::Revocation]);
    assert_eq!(credential.entry_size(), 1);
    assert_eq!(credential.ttl(), Some(300_000));
    assert_eq!(credential.decoded_list.len(), MINIMUM_NUMBER_OF_ENTRIES);
    assert!(credential.decoded_list.not_any());

    let json = serde_json::to_value(&credential).unwrap();
    assert_eq!(
      json["type"],
      serde_json::json!(["VerifiableCredential", CREDENTIAL_TYPE])
    );
    assert_eq!(json["credentialSubject"]["type"], CREDENTIAL_SUBJECT_TYPE);
    assert_eq!(json["credentialSubject"]["statusPurpose"], "revocation");
    assert_eq!(json["credentialSubject"]["ttl"], 300_000);
    assert_eq!(json["validUntil"], "2031-04-05T14:27:40Z");
  }

  #[test]
  fn an_empty_built_status_list_matches_the_spec_example() {
    let credential = credential_builder()
      .status_purposes(StatusPurpose::Revocation)
      .build()
      .unwrap();

    // The compressed representations may differ, the encoded bitstrings must not.
    assert_eq!(
      decoded(credential.encoded_list()),
      decoded(spec_credential().encoded_list())
    );
  }

  #[test]
  fn a_built_credential_can_be_serialized_and_deserialized() {
    let credential = credential_builder()
      .status_purposes(vec![StatusPurpose::Revocation, StatusPurpose::Suspension])
      .build()
      .unwrap();

    let json = serde_json::to_string(&credential).unwrap();
    let deserialized: BitstringStatusListCredential = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.purposes(), credential.purposes());
    assert_eq!(deserialized.encoded_list(), credential.encoded_list());
    assert_eq!(deserialized.decoded_list, credential.decoded_list);
  }

  #[test]
  fn building_a_credential_with_status_messages_works() {
    let messages = status_messages();
    let credential = credential_builder().status_messages(messages.clone()).build().unwrap();

    // A credential carrying status messages implicitly serves the "message" purpose,
    // and its status size is derived from the number of messages.
    assert_eq!(credential.purposes(), [StatusPurpose::Message]);
    assert_eq!(credential.entry_size(), 2);
    assert_eq!(credential.decoded_list.len(), MINIMUM_NUMBER_OF_ENTRIES * 2);
  }

  #[test]
  fn building_a_credential_with_too_few_entries_fails() {
    let err = credential_builder()
      .status_purposes(StatusPurpose::Revocation)
      .number_of_entries(MINIMUM_NUMBER_OF_ENTRIES - 1)
      .build()
      .unwrap_err();

    std::assert_matches!(err, BuilderError::TooFewEntries(131_071));
  }

  #[test]
  fn building_a_credential_without_a_purpose_fails() {
    let err = credential_builder().build().unwrap_err();

    std::assert_matches!(err, BuilderError::MissingPurpose);
  }

  #[test]
  fn building_a_credential_with_an_invalid_number_of_status_messages_fails() {
    let mut messages = status_messages();
    messages.pop();

    let err = credential_builder().status_messages(messages).build().unwrap_err();

    std::assert_matches!(err, BuilderError::InvalidNumberOfStatusMessages);
  }

  #[test]
  fn building_a_credential_without_an_issuer_fails() {
    let err = BitstringStatusListCredentialBuilder::new()
      .status_purposes(StatusPurpose::Revocation)
      .build()
      .unwrap_err();

    std::assert_matches!(err, BuilderError::CredentialBuilderError(crate::Error::MissingIssuer));
  }

  #[test]
  fn revoking_an_entry_works() {
    let mut credential = spec_credential();
    let entry = entry(94567, StatusPurpose::Revocation);
    let encoded_list_before = credential.encoded_list().to_owned();

    credential.update().set_entry(&entry, true).unwrap();

    let status = credential.entry(94567, &StatusPurpose::Revocation).unwrap();
    assert_eq!(status.status, 1);
    assert!(!status.valid);

    // Only the referenced entry has been set, at the position mandated by the specification:
    // index 0 is the left-most (most significant) bit of the first byte, which is exactly how a
    // `Msb0`-ordered bitstring is indexed.
    assert_eq!(credential.decoded_list.count_ones(), 1);
    assert!(credential.decoded_list[94567]);

    // The credential's `encodedList` has been kept in sync with the updated bitstring.
    assert_ne!(credential.encoded_list(), encoded_list_before);
    let json = serde_json::to_value(&credential).unwrap();
    assert_eq!(json["credentialSubject"]["encodedList"], credential.encoded_list());
  }

  #[test]
  fn a_revoked_entry_cannot_be_unrevoked() {
    let mut credential = spec_credential();
    let entry = entry(94567, StatusPurpose::Revocation);
    credential.update().set_entry(&entry, true).unwrap();

    let err = credential.update().set_entry(&entry, false).unwrap_err();

    std::assert_matches!(err, SetEntryError::IrreversibleStatus);
    assert!(!credential.entry(94567, &StatusPurpose::Revocation).unwrap().valid);
  }

  #[test]
  fn a_suspended_entry_can_be_unsuspended() {
    let mut credential = credential_builder()
      .status_purposes(StatusPurpose::Suspension)
      .build()
      .unwrap();
    let entry = entry(23452, StatusPurpose::Suspension);

    credential.update().set_entry(&entry, true).unwrap();
    assert!(!credential.entry(23452, &StatusPurpose::Suspension).unwrap().valid);

    credential.update().set_entry(&entry, false).unwrap();
    assert!(credential.entry(23452, &StatusPurpose::Suspension).unwrap().valid);
    assert!(credential.decoded_list.not_any());
  }

  #[test]
  fn setting_an_entry_of_another_credential_fails() {
    let mut credential = spec_credential();
    let entry = BitstringStatusListEntryBuilder::new()
      .credential(url("https://example.com/credentials/status/4"))
      .index(94567)
      .status_purpose(StatusPurpose::Revocation)
      .build()
      .unwrap();

    let err = credential.update().set_entry(&entry, true).unwrap_err();

    std::assert_matches!(err, SetEntryError::CredentialMismatch { .. });
  }

  #[test]
  fn setting_an_entry_with_a_purpose_the_credential_does_not_serve_fails() {
    let mut credential = spec_credential();
    let entry = entry(94567, StatusPurpose::Suspension);

    let err = credential.update().set_entry(&entry, true).unwrap_err();

    std::assert_matches!(err, SetEntryError::InvalidPurpose(StatusPurpose::Suspension));
  }

  #[test]
  fn setting_an_out_of_bounds_entry_fails() {
    let mut credential = spec_credential();
    let entry = entry(MINIMUM_NUMBER_OF_ENTRIES, StatusPurpose::Revocation);

    let err = credential.update().set_entry(&entry, true).unwrap_err();

    std::assert_matches!(
      err,
      SetEntryError::OutOfRange(IndexOutOfBounds(MINIMUM_NUMBER_OF_ENTRIES))
    );
  }

  #[test]
  fn setting_a_status_message_works() {
    let messages = status_messages();
    let mut credential = BitstringStatusListCredentialBuilder::new()
      .issuer(issuer())
      .id(url(MESSAGE_CREDENTIAL_URL))
      .status_messages(messages.clone())
      .build()
      .unwrap();
    let entry = BitstringStatusListEntryBuilder::new()
      .credential(url(MESSAGE_CREDENTIAL_URL))
      .index(4711)
      .status_purpose(StatusPurpose::Message)
      .messages(messages.clone())
      .build()
      .unwrap();

    credential.update().set_entry(&entry, &messages[2]).unwrap();

    let status = credential.entry(4711, &StatusPurpose::Message).unwrap();
    assert_eq!(status.status, 2);
    assert_eq!(status.message, Some(&messages[2]));
    // A 2-bit wide status of `0x2` occupies the two bits starting at index 4711 * 2.
    assert!(credential.decoded_list[4711 * 2]);
    assert!(!credential.decoded_list[4711 * 2 + 1]);
  }

  #[test]
  fn setting_a_status_message_the_credential_does_not_declare_fails() {
    let messages = status_messages();
    let unknown_message = StatusMessage::new(2, "unknown");
    let mut credential = BitstringStatusListCredentialBuilder::new()
      .issuer(issuer())
      .id(url(MESSAGE_CREDENTIAL_URL))
      .status_messages(messages.clone())
      .build()
      .unwrap();
    let entry = BitstringStatusListEntryBuilder::new()
      .credential(url(MESSAGE_CREDENTIAL_URL))
      .index(4711)
      .status_purpose(StatusPurpose::Message)
      .messages(messages)
      .build()
      .unwrap();

    let err = credential.update().set_entry(&entry, &unknown_message).unwrap_err();

    std::assert_matches!(err, SetEntryError::InvalidMessage(_));
  }
}
