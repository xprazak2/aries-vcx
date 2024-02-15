use serde::{Deserialize, Serialize};

use super::{encryption_method::EncryptionMethod, key_derivation_method::KeyDerivationMethod};

#[derive(Debug, Serialize, Deserialize)]
pub struct Header {
    // Method of encryption for encrypted stream
    pub encryption_method: EncryptionMethod,
    // Export time in seconds from UNIX Epoch
    pub time: u64,
    // Version of header
    pub version: u32,
}

impl Header {
    pub fn to_key_derivation_method(&self) -> KeyDerivationMethod {
        match self.encryption_method {
            EncryptionMethod::ChaCha20Poly1305IETF { .. } => KeyDerivationMethod::ARGON2I_MOD,
            EncryptionMethod::ChaCha20Poly1305IETFInteractive { .. } => {
                KeyDerivationMethod::ARGON2I_INT
            }
            EncryptionMethod::ChaCha20Poly1305IETFRaw { .. } => KeyDerivationMethod::RAW,
        }
    }
}
