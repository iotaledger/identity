use core::{
    convert::TryFrom,
    fmt::{Debug, Display, Error as FmtError, Formatter, Result as FmtResult},
    ops::{Deref, DerefMut},
};
use identity_core::{
    common::{OneOrMany, ToJson as _},
    did::{DIDDocument as Document, DIDDocumentBuilder as DocumentBuilder, DID},
    diff::Diff as _,
    key::{KeyData, KeyRelation, KeyType, PublicKey, PublicKeyBuilder},
    utils::encode_b58,
};
use identity_crypto::{KeyPair, SecretKey};
use identity_proof::{signature::jcsed25519signature2020, HasProof, LdRead, LdSignature, LdWrite, SignatureOptions};
use iota::transaction::bundled::Address;
use multihash::{Blake2b256, MultihashGeneric};
use serde::{Deserialize, Serialize};

use crate::{
    did::{DIDDiff, IotaDID},
    error::{Error, Result},
    utils::{create_address_from_trits, utf8_to_trytes},
};

#[derive(Clone, PartialEq, Deserialize, Serialize)]
#[serde(try_from = "Document", into = "Document")]
pub struct IotaDocument {
    document: Document,
    did: IotaDID,
}

impl IotaDocument {
    pub fn generate_ed25519<'a, T>(tag: &str, network: T) -> Result<(Self, KeyPair)>
    where
        T: Into<Option<&'a str>>,
    {
        let (did, keypair): (IotaDID, KeyPair) = IotaDID::generate_ed25519(network)?;

        let authentication: PublicKey = PublicKeyBuilder::default()
            .id(format!("{}#{}", did, tag).parse()?)
            .controller(did.into())
            .key_type(KeyType::Ed25519VerificationKey2018)
            .key_data(KeyData::PublicKeyBase58(encode_b58(keypair.public())))
            .build()
            .expect("FIXME");

        Self::try_from_key(authentication).map(|this| (this, keypair))
    }

    pub fn try_from_document(document: Document) -> Result<Self> {
        let did: IotaDID = IotaDID::try_from_did(document.did().clone())?;

        let authentication: &PublicKey = document
            .resolve_key(0, KeyRelation::Authentication)
            .ok_or(Error::InvalidAuthenticationKey)?;

        Self::check_authentication_key_id(authentication, &did)?;

        Ok(Self { document, did })
    }

    pub fn try_from_key(authentication: PublicKey) -> Result<Self> {
        let mut base: DID = authentication.id().clone();

        base.fragment = None;
        base.query = None;
        base.path_segments = None;

        Self::create_document(base, authentication).and_then(Self::try_from_document)
    }

    fn create_document(did: impl Into<DID>, authentication: PublicKey) -> Result<Document> {
        let mut document: Document = DocumentBuilder::default()
            .context(OneOrMany::One(DID::BASE_CONTEXT.into()))
            .id(did.into())
            .auth(vec![authentication.id().clone().into()])
            .public_keys(vec![authentication])
            .build()
            .expect("FIXME");

        document.init_timestamps();

        Ok(document)
    }

    pub fn did(&self) -> &IotaDID {
        &self.did
    }

    pub fn supersedes(&self) -> Option<&str> {
        None // TODO
    }

    pub fn diff_chain(&self) -> Option<&str> {
        None // TODO
    }

    pub fn has_diff_chain(&self) -> bool {
        self.diff_chain().is_some()
    }

    pub fn authentication_key(&self) -> &PublicKey {
        self.resolve_key(0, KeyRelation::Authentication).expect("infallible")
    }

    pub fn authentication_key_bytes(&self) -> Vec<u8> {
        self.authentication_key()
            .key_data()
            .try_decode()
            .transpose()
            .ok()
            .flatten()
            .unwrap_or_default()
    }

    pub fn sign(&mut self, secret: &SecretKey) -> Result<()> {
        let key: &PublicKey = self.authentication_key();

        let fragment: String = format!("{}", key.id());
        let options: SignatureOptions = SignatureOptions::new(fragment);

        match key.key_type() {
            KeyType::Ed25519VerificationKey2018 => {
                jcsed25519signature2020::sign_lds(&mut self.document, options, secret)?;
            }
            _ => {
                return Err(Error::InvalidAuthenticationKey);
            }
        }

        Ok(())
    }

    pub fn verify(&self) -> Result<()> {
        let key: &PublicKey = self.authentication_key();

        match key.key_type() {
            KeyType::Ed25519VerificationKey2018 => {
                jcsed25519signature2020::verify_lds(&self.document)?;
            }
            _ => {
                return Err(Error::InvalidAuthenticationKey);
            }
        }

        Ok(())
    }

    pub fn diff(&self, mut other: Document, secret: &SecretKey) -> Result<DIDDiff> {
        // Update the `updated` timestamp of the new document
        other.update_time();

        // Create a diff of changes between the two documents.
        let mut diff: DIDDiff = DIDDiff {
            id: self.document.did().clone(),
            diff: self.document.diff(&other)?,
            proof: LdSignature::new("", SignatureOptions::new("")),
        };

        self.sign_data(&mut diff, secret)?;

        Ok(diff)
    }

    pub fn verify_diff(&self, diff: &DIDDiff) -> Result<()> {
        self.verify_data(diff)
    }

    pub fn sign_data<T>(&self, data: &mut T, secret: &SecretKey) -> Result<()>
    where
        T: HasProof + Serialize,
    {
        // Get the first authentication key from the document.
        let key: &PublicKey = self.authentication_key();

        let fragment: String = format!("{}", key.id());
        let options: SignatureOptions = SignatureOptions::new(fragment);

        // Wrap the diff/document in a signable type.
        let mut target: LdWrite<T> = LdWrite::new(data, &self.document);

        // Create and apply the signature
        match key.key_type() {
            KeyType::Ed25519VerificationKey2018 => {
                jcsed25519signature2020::sign_lds(&mut target, options, secret)?;
            }
            _ => {
                return Err(Error::InvalidAuthenticationKey);
            }
        }

        Ok(())
    }

    pub fn verify_data<T>(&self, data: &T) -> Result<()>
    where
        T: HasProof + Serialize,
    {
        // Wrap the data/document in a verifiable type.
        let target: LdRead<T> = LdRead::new(data, &self.document);

        match self.authentication_key().key_type() {
            KeyType::Ed25519VerificationKey2018 => {
                jcsed25519signature2020::verify_lds(&target)?;
            }
            _ => {
                return Err(Error::InvalidAuthenticationKey);
            }
        }

        Ok(())
    }

    pub fn diff_address_hash(&self) -> String {
        Self::create_diff_address_hash(&self.authentication_key_bytes())
    }

    pub fn diff_address(&self) -> Result<Address> {
        create_address_from_trits(self.diff_address_hash())
    }

    /// Creates an 81 Trytes IOTA address from public key bytes for a diff
    pub fn create_diff_address_hash(public_key: &[u8]) -> String {
        let hash: MultihashGeneric<_> = Blake2b256::digest(public_key);
        let hash: MultihashGeneric<_> = Blake2b256::digest(hash.digest());

        let mut trytes: String = utf8_to_trytes(&encode_b58(hash.digest()));

        trytes.truncate(iota_constants::HASH_TRYTES_SIZE);

        trytes
    }

    pub fn create_diff_address(public_key: &[u8]) -> Result<Address> {
        create_address_from_trits(Self::create_diff_address_hash(public_key))
    }

    fn check_authentication_key_id(authentication: &PublicKey, did: &IotaDID) -> Result<()> {
        let key: &DID = authentication.id();

        if key.fragment.is_none() {
            return Err(Error::InvalidAuthenticationKey);
        }

        if !key.matches_base(did) {
            return Err(Error::InvalidAuthenticationKey);
        }

        Ok(())
    }
}

impl Display for IotaDocument {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        if f.alternate() {
            f.write_str(&self.to_json_pretty().map_err(|_| FmtError)?)
        } else {
            f.write_str(&self.to_json().map_err(|_| FmtError)?)
        }
    }
}

impl Debug for IotaDocument {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        Debug::fmt(&self.document, f)
    }
}

impl Deref for IotaDocument {
    type Target = Document;

    fn deref(&self) -> &Self::Target {
        &self.document
    }
}

// TODO: Remove this
impl DerefMut for IotaDocument {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.document
    }
}

impl From<IotaDocument> for Document {
    fn from(other: IotaDocument) -> Self {
        other.document
    }
}

impl TryFrom<Document> for IotaDocument {
    type Error = Error;

    fn try_from(other: Document) -> Result<Self, Self::Error> {
        Self::try_from_document(other)
    }
}
