use super::Jwk;
use super::JwkOperation;
use super::JwkParams;
use super::JwkParamsOkp;
use super::JwkType;
use super::JwkUse;
use identity_core::common::Url;
use jsonprooftoken::jpa::algs::ProofAlgorithm;
use jsonprooftoken::jwk::alg_parameters::Algorithm;
use jsonprooftoken::jwk::alg_parameters::JwkAlgorithmParameters;
use jsonprooftoken::jwk::alg_parameters::JwkOctetKeyPairParameters;
use jsonprooftoken::jwk::curves::EllipticCurveTypes;
use jsonprooftoken::jwk::key::Jwk as JwkExt;
use jsonprooftoken::jwk::key::KeyOps;
use jsonprooftoken::jwk::key::PKUse;
use jsonprooftoken::jwk::types::KeyType;
use std::str::FromStr;

impl From<KeyOps> for JwkOperation {
  fn from(value: KeyOps) -> Self {
    match value {
      KeyOps::Sign => Self::Sign,
      KeyOps::Verify => Self::Verify,
      KeyOps::Encrypt => Self::Encrypt,
      KeyOps::Decrypt => Self::Decrypt,
      KeyOps::WrapKey => Self::WrapKey,
      KeyOps::UnwrapKey => Self::UnwrapKey,
      KeyOps::DeriveKey => Self::DeriveKey,
      KeyOps::DeriveBits => Self::DeriveBits,
      KeyOps::ProofGeneration => Self::ProofGeneration,
      KeyOps::ProofVerification => Self::ProofVerification,
    }
  }
}

impl From<JwkOperation> for KeyOps {
  fn from(value: JwkOperation) -> Self {
    match value {
      JwkOperation::Sign => Self::Sign,
      JwkOperation::Verify => Self::Verify,
      JwkOperation::Encrypt => Self::Encrypt,
      JwkOperation::Decrypt => Self::Decrypt,
      JwkOperation::WrapKey => Self::WrapKey,
      JwkOperation::UnwrapKey => Self::UnwrapKey,
      JwkOperation::DeriveKey => Self::DeriveKey,
      JwkOperation::DeriveBits => Self::DeriveBits,
      JwkOperation::ProofGeneration => Self::ProofGeneration,
      JwkOperation::ProofVerification => Self::ProofVerification,
    }
  }
}

// impl Into<KeyOps> for JwkOperation {
//     fn into(self) -> KeyOps {
//         match self {
//             Self::Sign => KeyOps::Sign,
//             Self::Verify => KeyOps::Verify,
//             Self::Encrypt => KeyOps::Encrypt,
//             Self::Decrypt => KeyOps::Decrypt,
//             Self::WrapKey => KeyOps::WrapKey,
//             Self::UnwrapKey => KeyOps::UnwrapKey,
//             Self::DeriveKey => KeyOps::DeriveKey,
//             Self::DeriveBits => KeyOps::DeriveBits,
//             Self::ProofGeneration => KeyOps::ProofGeneration,
//             Self::ProofVerification => KeyOps::ProofVerification,
//         }
//     }
// }

impl From<PKUse> for JwkUse {
  fn from(value: PKUse) -> Self {
    match value {
      PKUse::Signature => Self::Signature,
      PKUse::Encryption => Self::Encryption,
      PKUse::Proof => Self::Proof,
    }
  }
}

impl From<JwkUse> for PKUse {
  fn from(value: JwkUse) -> Self {
    match value {
      JwkUse::Signature => Self::Signature,
      JwkUse::Encryption => Self::Encryption,
      JwkUse::Proof => Self::Proof,
    }
  }
}

impl From<JwkOctetKeyPairParameters> for JwkParamsOkp {
  fn from(value: JwkOctetKeyPairParameters) -> Self {
    Self {
      crv: value.crv.to_string(),
      x: value.x,
      d: value.d,
    }
  }
}

impl TryInto<JwkOctetKeyPairParameters> for &JwkParamsOkp {
  type Error = crate::error::Error;

  fn try_into(self) -> Result<JwkOctetKeyPairParameters, Self::Error> {
    Ok(JwkOctetKeyPairParameters {
      kty: KeyType::OctetKeyPair,
      crv: EllipticCurveTypes::from_str(&self.crv).map_err(|_| Self::Error::KeyError("Invalid crv!"))?,
      x: self.x.clone(),
      d: self.d.clone(),
    })
  }
}

impl TryFrom<JwkExt> for Jwk {
  type Error = crate::error::Error;

  fn try_from(value: JwkExt) -> Result<Self, Self::Error> {
    let x5u = match value.x5u {
      Some(v) => Some(Url::from_str(&v).map_err(|_| Self::Error::InvalidClaim("x5u"))?),
      None => None,
    };

    let (kty, params) = match value.key_params {
      JwkAlgorithmParameters::OctetKeyPair(p) => (JwkType::Okp, JwkParams::Okp(JwkParamsOkp::from(p))),
    };

    Ok(Self {
      kty,
      use_: value.pk_use.map(JwkUse::from),
      key_ops: value
        .key_ops
        .map(|vec_key_ops| vec_key_ops.into_iter().map(JwkOperation::from).collect()),
      alg: value.alg.map(|a| a.to_string()),
      kid: value.kid,
      x5u,
      x5c: value.x5c,
      x5t: value.x5t,
      x5t_s256: None,
      params,
    })
  }
}

impl TryInto<JwkExt> for &Jwk {
  type Error = crate::error::Error;

  fn try_into(self) -> Result<JwkExt, Self::Error> {
    let params = match &self.params {
      JwkParams::Okp(p) => JwkAlgorithmParameters::OctetKeyPair(p.try_into()?),
      _ => return Err(Self::Error::InvalidParam("Parameters not supported!")),
    };

    let alg = match &self.alg {
      Some(a) => Some(Algorithm::Proof(
        ProofAlgorithm::from_str(a).map_err(|_| Self::Error::KeyError("Invalid alg"))?,
      )),
      None => None,
    };

    Ok(JwkExt {
      kid: self.kid.clone(),
      pk_use: self.use_.map(|u| u.into()),
      key_ops: self
        .key_ops
        .as_deref()
        .and_then(|vec_key_ops| vec_key_ops.iter().map(|o| Some((*o).into())).collect()),
      alg,
      x5u: self.x5u.as_ref().map(|v| v.as_str().to_string()),
      x5c: self.x5c.clone(),
      x5t: self.x5t.clone(),
      key_params: params,
    })
  }
}
