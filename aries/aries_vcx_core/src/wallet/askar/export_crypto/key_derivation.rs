use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::{
    aead::{chacha20poly1305::Key, chacha20poly1305_ietf},
    pwhash::Salt,
};

use crate::errors::error::{AriesVcxCoreError, AriesVcxCoreErrorKind, VcxCoreResult};

use super::{
    chacha20poly1305ietf,
    encryption_method::{EncryptionMethod, CHUNK_SIZE},
    key_derivation_method::KeyDerivationMethod,
    pwhash,
};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum Metadata {
    MetadataArgon(MetadataArgon),
    MetadataRaw(MetadataRaw),
}

// impl Metadata {
//     pub fn get_keys(&self) -> &Vec<u8> {
//         match *self {
//             Metadata::MetadataArgon(ref metadata) => &metadata.keys,
//             Metadata::MetadataRaw(ref metadata) => &metadata.keys,
//         }
//     }
// }

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MetadataArgon {
    pub keys: Vec<u8>,
    pub master_key_salt: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MetadataRaw {
    pub keys: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum KeyDerivationData {
    Raw(String),
    Argon2iMod(String, Salt),
    Argon2iInt(String, Salt),
}

// pub fn master_key_salt_from_slice(slice: &[u8]) -> VcxCoreResult<Salt> {
//     Salt::from_slice(slice).ok_or_else(|| {
//         AriesVcxCoreError::from_msg(
//             crate::errors::error::AriesVcxCoreErrorKind::InvalidInput,
//             "Invalid master key salt",
//         )
//     })

//     // Ok(salt)
// }

impl KeyDerivationData {
    pub fn from_passphrase_with_new_salt(
        passphrase: &str,
        derivation_method: &KeyDerivationMethod,
    ) -> Self {
        let salt = pwhash::gen_salt();
        let passphrase = passphrase.to_owned();
        match *derivation_method {
            KeyDerivationMethod::ARGON2I_INT => KeyDerivationData::Argon2iInt(passphrase, salt),
            KeyDerivationMethod::ARGON2I_MOD => KeyDerivationData::Argon2iMod(passphrase, salt),
            KeyDerivationMethod::RAW => KeyDerivationData::Raw(passphrase),
        }
    }

    pub fn encryption_method(&self, nonce: chacha20poly1305_ietf::Nonce) -> EncryptionMethod {
        match self {
            KeyDerivationData::Argon2iMod(_, salt) => EncryptionMethod::ChaCha20Poly1305IETF {
                salt: salt[..].to_vec(),
                nonce: nonce[..].to_vec(),
                chunk_size: CHUNK_SIZE,
            },
            KeyDerivationData::Argon2iInt(_, salt) => {
                EncryptionMethod::ChaCha20Poly1305IETFInteractive {
                    salt: salt[..].to_vec(),
                    nonce: nonce[..].to_vec(),
                    chunk_size: CHUNK_SIZE,
                }
            }
            KeyDerivationData::Raw(_) => EncryptionMethod::ChaCha20Poly1305IETFRaw {
                nonce: nonce[..].to_vec(),
                chunk_size: CHUNK_SIZE,
            },
        }
    }

    // pub(super) fn from_passphrase_and_metadata(
    //     passphrase: &str,
    //     metadata: &Metadata,
    //     derivation_method: &KeyDerivationMethod,
    // ) -> VcxCoreResult<Self> {
    //     let passphrase = passphrase.to_owned();

    //     let data = match (derivation_method, metadata) {
    //         (KeyDerivationMethod::RAW, &Metadata::MetadataRaw(_)) => {
    //             KeyDerivationData::Raw(passphrase)
    //         }
    //         (KeyDerivationMethod::ARGON2I_INT, Metadata::MetadataArgon(metadata)) => {
    //             let master_key_salt = master_key_salt_from_slice(&metadata.master_key_salt)?;
    //             KeyDerivationData::Argon2iInt(passphrase, master_key_salt)
    //         }
    //         (KeyDerivationMethod::ARGON2I_MOD, Metadata::MetadataArgon(metadata)) => {
    //             let master_key_salt = master_key_salt_from_slice(&metadata.master_key_salt)?;
    //             KeyDerivationData::Argon2iMod(passphrase, master_key_salt)
    //         }
    //         _ => {
    //             return Err(AriesVcxCoreError::from_msg(
    //                 AriesVcxCoreErrorKind::InvalidInput,
    //                 "Invalid combination of KeyDerivationMethod and Metadata",
    //             ))
    //         }
    //     };

    //     Ok(data)
    // }

    pub fn calc_master_key(&self) -> VcxCoreResult<chacha20poly1305_ietf::Key> {
        match self {
            KeyDerivationData::Raw(passphrase) => _raw_master_key(passphrase),
            KeyDerivationData::Argon2iInt(passphrase, salt) => {
                _derive_master_key(passphrase, salt, &KeyDerivationMethod::ARGON2I_INT)
            }
            KeyDerivationData::Argon2iMod(passphrase, salt) => {
                _derive_master_key(passphrase, salt, &KeyDerivationMethod::ARGON2I_MOD)
            }
        }
    }
}

fn _derive_master_key(
    passphrase: &str,
    salt: &Salt,
    key_derivation_method: &KeyDerivationMethod,
) -> VcxCoreResult<chacha20poly1305_ietf::Key> {
    let key = chacha20poly1305ietf::derive_key(passphrase, salt, key_derivation_method)?;
    Ok(key)
}

fn _raw_master_key(passphrase: &str) -> VcxCoreResult<chacha20poly1305_ietf::Key> {
    let bytes = bs58::decode(passphrase)
        .into_vec()
        .map_err(|err| AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::InvalidInput, err))?;

    chacha20poly1305_ietf::Key::from_slice(&bytes).ok_or_else(|| {
        AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::InvalidInput, "Invalid master key")
    })
}
