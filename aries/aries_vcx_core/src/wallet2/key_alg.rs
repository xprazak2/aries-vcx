use aries_askar::kms::KeyAlg as AskarKeyAlg;

use aries_askar::crypto::alg::AesTypes as AskarAesTypes;
use aries_askar::crypto::alg::BlsCurves as AskarBlsCurves;
use aries_askar::crypto::alg::Chacha20Types as AskarChacha20Types;
use aries_askar::crypto::alg::EcCurves as AskarEcCurves;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
pub enum KeyAlg {
    /// AES
    Aes(AesTypes),
    /// BLS12-381
    Bls12_381(BlsCurves),
    /// (X)ChaCha20-Poly1305
    Chacha20(Chacha20Types),
    /// Ed25519 signing key
    Ed25519,
    /// Curve25519 elliptic curve key exchange key
    X25519,
    /// Elliptic Curve key for signing or key exchange
    EcCurve(EcCurves),
}

impl From<KeyAlg> for AskarKeyAlg {
    fn from(value: KeyAlg) -> Self {
        match value {
            KeyAlg::Aes(aes_type) => Self::Aes(aes_type.into()),
            KeyAlg::Bls12_381(bls_type) => Self::Bls12_381(bls_type.into()),
            KeyAlg::Chacha20(chacha_type) => Self::Chacha20(chacha_type.into()),
            KeyAlg::Ed25519 => Self::Ed25519,
            KeyAlg::X25519 => Self::X25519,
            KeyAlg::EcCurve(ec_type) => Self::EcCurve(ec_type.into()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
pub enum AesTypes {
    /// 128-bit AES-GCM
    A128Gcm,
    /// 256-bit AES-GCM
    A256Gcm,
    /// 128-bit AES-CBC with HMAC-256
    A128CbcHs256,
    /// 256-bit AES-CBC with HMAC-512
    A256CbcHs512,
    /// 128-bit AES Key Wrap
    A128Kw,
    /// 256-bit AES Key Wrap
    A256Kw,
}

impl From<AesTypes> for AskarAesTypes {
    fn from(value: AesTypes) -> Self {
        match value {
            AesTypes::A128Gcm => Self::A128Gcm,
            AesTypes::A256Gcm => Self::A256Gcm,
            AesTypes::A128CbcHs256 => Self::A128CbcHs256,
            AesTypes::A256CbcHs512 => Self::A256CbcHs512,
            AesTypes::A128Kw => Self::A128Kw,
            AesTypes::A256Kw => Self::A256Kw,
        }
    }
}

/// Supported public key types for Bls12_381
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
pub enum BlsCurves {
    /// G1 curve
    G1,
    /// G2 curve
    G2,
    /// G1 + G2 curves
    G1G2,
}

impl From<BlsCurves> for AskarBlsCurves {
    fn from(value: BlsCurves) -> Self {
        match value {
            BlsCurves::G1 => Self::G1,
            BlsCurves::G2 => Self::G2,
            BlsCurves::G1G2 => Self::G1G2,
        }
    }
}

/// Supported algorithms for (X)ChaCha20-Poly1305
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
pub enum Chacha20Types {
    /// ChaCha20-Poly1305
    C20P,
    /// XChaCha20-Poly1305
    XC20P,
}

impl From<Chacha20Types> for AskarChacha20Types {
    fn from(value: Chacha20Types) -> Self {
        match value {
            Chacha20Types::C20P => Self::C20P,
            Chacha20Types::XC20P => Self::XC20P,
        }
    }
}

/// Supported curves for ECC operations
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
pub enum EcCurves {
    /// NIST P-256 curve
    Secp256r1,
    /// Koblitz 256 curve
    Secp256k1,
    /// NIST P-384 curve
    Secp384r1,
}

impl From<EcCurves> for AskarEcCurves {
    fn from(value: EcCurves) -> Self {
        match value {
            EcCurves::Secp256r1 => Self::Secp256r1,
            EcCurves::Secp256k1 => Self::Secp256k1,
            EcCurves::Secp384r1 => Self::Secp384r1,
        }
    }
}
