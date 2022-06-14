// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::io::Write;

use dataurl::DataUrl;
use flate2::write::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use identity_core::common::Url;
use identity_core::utils::Base;
use identity_core::utils::BaseEncoding;
use roaring::RoaringBitmap;

use crate::did::DID;
use crate::error::Error;
use crate::error::Result;
use crate::service::Service;
use crate::service::ServiceEndpoint;

const DATA_URL_MEDIA_TYPE: &str = "application/octet-stream";

/// A compressed bitmap for managing credential revocation.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RevocationBitmap(RoaringBitmap);

impl RevocationBitmap {
  /// The name of the service type.
  pub const TYPE: &'static str = "RevocationBitmap2022";

  /// Constructs a new empty [`RevocationBitmap`].
  pub fn new() -> Self {
    Self(RoaringBitmap::new())
  }

  /// Returns `true` if the credential at the given `index` is revoked.
  pub fn is_revoked(&self, index: u32) -> bool {
    self.0.contains(index)
  }

  /// Mark the given `index` as revoked.
  ///
  /// Returns true if the `index` was absent from the set.
  pub fn revoke(&mut self, index: u32) -> bool {
    self.0.insert(index)
  }

  /// Mark the `index` as not revoked.
  ///
  /// Returns true if the `index` was present in the set.
  pub fn unrevoke(&mut self, index: u32) -> bool {
    self.0.remove(index)
  }

  /// Returns the number of revoked credentials.
  pub fn len(&self) -> u64 {
    self.0.len()
  }

  /// Returns `true` if no credentials are revoked, `false` otherwise.
  pub fn is_empty(&self) -> bool {
    self.0.is_empty()
  }

  /// Return the bitmap as a data url embedded in a service endpoint.
  pub fn to_endpoint(&self) -> Result<ServiceEndpoint> {
    let endpoint_data: String = self.serialize_compressed_base64()?;

    let mut data_url: DataUrl = DataUrl::new();
    data_url.set_media_type(Some(DATA_URL_MEDIA_TYPE.to_owned()));
    data_url.set_is_base64_encoded(true);
    data_url.set_data(endpoint_data.as_bytes());

    Ok(ServiceEndpoint::One(Url::parse(data_url.to_string())?))
  }

  /// Construct a `RevocationBitmap` from a data url embedded in `service_endpoint`.
  pub fn from_endpoint(service_endpoint: &ServiceEndpoint) -> Result<Self> {
    if let ServiceEndpoint::One(url) = service_endpoint {
      let data_url: DataUrl =
        DataUrl::parse(url.as_str()).map_err(|_| Error::InvalidService("invalid url - expected a data url"))?;

      if !data_url.get_is_base64_encoded() || data_url.get_media_type() != DATA_URL_MEDIA_TYPE {
        return Err(Error::InvalidService(
          "invalid url - expected an `application/octet-stream;base64` data url",
        ));
      }

      RevocationBitmap::deserialize_compressed_base64(
        std::str::from_utf8(data_url.get_data())
          .map_err(|_| Error::InvalidService("invalid data url - expected valid utf-8"))?,
      )
    } else {
      Err(Error::InvalidService("invalid endpoint - expected a single data url"))
    }
  }

  /// Deserializes a compressed [`RevocationBitmap`] base64-encoded `data`.
  pub(crate) fn deserialize_compressed_base64<T>(data: &T) -> Result<Self>
  where
    T: AsRef<str> + ?Sized,
  {
    let decoded_data: Vec<u8> = BaseEncoding::decode(data, Base::Base64Url)
      .map_err(|e| Error::Base64DecodingError(data.as_ref().to_owned(), e))?;
    let decompressed_data: Vec<u8> = Self::decompress_zlib(decoded_data)?;
    Self::deserialize_slice(&decompressed_data)
  }

  /// Serializes and compressess [`RevocationBitmap`] as a base64-encoded `String`.
  pub(crate) fn serialize_compressed_base64(&self) -> Result<String> {
    let serialized_data: Vec<u8> = self.serialize_vec()?;
    Self::compress_zlib(&serialized_data).map(|data| BaseEncoding::encode(&data, Base::Base64Url))
  }

  /// Deserializes [`RevocationBitmap`] from a slice of bytes.
  fn deserialize_slice(data: &[u8]) -> Result<Self> {
    RoaringBitmap::deserialize_from(data)
      .map_err(Error::BitmapDecodingError)
      .map(Self)
  }

  /// Serializes a [`RevocationBitmap`] as a vector of bytes.
  fn serialize_vec(&self) -> Result<Vec<u8>> {
    let mut output: Vec<u8> = Vec::with_capacity(self.0.serialized_size());
    self.0.serialize_into(&mut output).map_err(Error::BitmapEncodingError)?;
    Ok(output)
  }

  fn compress_zlib<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(input.as_ref()).map_err(Error::BitmapEncodingError)?;
    encoder.finish().map_err(Error::BitmapEncodingError)
  }

  fn decompress_zlib<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>> {
    let mut writer = Vec::new();
    let mut decoder = ZlibDecoder::new(writer);
    decoder.write_all(input.as_ref()).map_err(Error::BitmapDecodingError)?;
    writer = decoder.finish().map_err(Error::BitmapDecodingError)?;
    Ok(writer)
  }
}

impl<D: DID + Sized> TryFrom<&Service<D>> for RevocationBitmap {
  type Error = Error;

  fn try_from(service: &Service<D>) -> Result<Self> {
    if service.type_() != Self::TYPE {
      return Err(Error::InvalidService(
        "invalid service - expected a `RevocationBitmap2022`",
      ));
    }

    Self::from_endpoint(service.service_endpoint())
  }
}

#[cfg(test)]
mod tests {
  use identity_core::common::Url;

  use super::RevocationBitmap;

  #[test]
  fn test_serialize_base64_round_trip() {
    let mut embedded_revocation_list = RevocationBitmap::new();
    let base64_compressed_revocation_list: String = embedded_revocation_list.serialize_compressed_base64().unwrap();

    assert_eq!(&base64_compressed_revocation_list, "eJyzMmAAAwADKABr");
    assert_eq!(
      RevocationBitmap::deserialize_compressed_base64(&base64_compressed_revocation_list).unwrap(),
      embedded_revocation_list
    );

    for credential in [0, 5, 6, 8] {
      embedded_revocation_list.revoke(credential);
    }
    let base64_compressed_revocation_list: String = embedded_revocation_list.serialize_compressed_base64().unwrap();

    assert_eq!(
      &base64_compressed_revocation_list,
      "eJyzMmBgYGQAAWYGATDNysDGwMEAAAscAJI"
    );
    assert_eq!(
      RevocationBitmap::deserialize_compressed_base64(&base64_compressed_revocation_list).unwrap(),
      embedded_revocation_list
    );
  }

  #[test]
  fn test_revocation_bitmap_test_vector_1() {
    const URL: &str = "data:application/octet-stream;base64,ZUp5ek1tQUFBd0FES0FCcg==";

    let bitmap: RevocationBitmap =
      RevocationBitmap::from_endpoint(&crate::service::ServiceEndpoint::One(Url::parse(URL).unwrap())).unwrap();

    assert!(bitmap.is_empty());
  }

  #[test]
  fn test_revocation_bitmap_test_vector_2() {
    const URL: &str = "data:application/octet-stream;base64,ZUp5ek1tQmdZR0lBQVVZZ1pHQ1FBR0laSUdabDZHUGN3UW9BRXVvQjlB";
    const EXPECTED: &[u32] = &[5, 398, 67000];

    let bitmap: RevocationBitmap =
      RevocationBitmap::from_endpoint(&crate::service::ServiceEndpoint::One(Url::parse(URL).unwrap())).unwrap();

    for revoked in EXPECTED {
      assert!(bitmap.is_revoked(*revoked));
    }

    assert_eq!(bitmap.len(), 3);
  }

  #[test]
  fn test_revocation_bitmap_test_vector_3() {
    const URL: &str = "data:application/octet-stream;base64,ZUp6dHhERVJBQ0FNQkxESEFWS1lXZkN2Q3E0MmFESmtyMlNrM0ROckFLQ2RBQUFBQUFBQTMzbGhHZm9q";

    let bitmap: RevocationBitmap =
      RevocationBitmap::from_endpoint(&crate::service::ServiceEndpoint::One(Url::parse(URL).unwrap())).unwrap();

    for index in 0..2u32.pow(14) {
      assert!(bitmap.is_revoked(index));
    }

    assert_eq!(bitmap.len(), 2u64.pow(14));
  }
}
