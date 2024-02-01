use aries_askar::{crypto::alg::EcCurves, kms::KeyAlg};

use crate::errors::error::{AriesVcxCoreError, AriesVcxCoreErrorKind, VcxCoreResult};

pub enum SigType {
    EdDSA,
    ES256,
    ES256K,
    ES384,
}

impl From<SigType> for &str {
    fn from(value: SigType) -> Self {
        match value {
            SigType::EdDSA => "eddsa",
            SigType::ES256 => "es256",
            SigType::ES256K => "es256k",
            SigType::ES384 => "es384",
        }
    }
}

impl SigType {
    pub fn try_from_key_alg(key_alg: KeyAlg) -> VcxCoreResult<Self> {
        match key_alg {
            KeyAlg::Ed25519 => Ok(SigType::EdDSA),
            KeyAlg::EcCurve(item) => match item {
                EcCurves::Secp256r1 => Ok(SigType::ES256),
                EcCurves::Secp256k1 => Ok(SigType::ES256K),
                EcCurves::Secp384r1 => Ok(SigType::ES384),
            },
            _ => Err(AriesVcxCoreError::from_msg(
                AriesVcxCoreErrorKind::InvalidInput,
                "this key does not support signing",
            )),
        }
    }
}
