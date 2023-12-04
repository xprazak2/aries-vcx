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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

/// Supported public key types for Bls12_381
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BlsCurves {
    /// G1 curve
    G1,
    /// G2 curve
    G2,
    /// G1 + G2 curves
    G1G2,
}

/// Supported algorithms for (X)ChaCha20-Poly1305
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Chacha20Types {
    /// ChaCha20-Poly1305
    C20P,
    /// XChaCha20-Poly1305
    XC20P,
}

/// Supported curves for ECC operations
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EcCurves {
    /// NIST P-256 curve
    Secp256r1,
    /// Koblitz 256 curve
    Secp256k1,
    /// NIST P-384 curve
    Secp384r1,
}
