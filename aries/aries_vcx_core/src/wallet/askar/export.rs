use std::{
    fs,
    io::{BufWriter, Write},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use indy_api_types::domain::wallet::KeyDerivationMethod;
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::aead::chacha20poly1305_ietf;
use vdrtools::indy_wallet::KeyDerivationData;

use byteorder::{LittleEndian, WriteBytesExt};
// use byteorder::LittleEndian;

use crate::errors::error::VcxCoreResult;

const CHUNK_SIZE: usize = 1024;

#[derive(Debug, Serialize, Deserialize)]
pub enum EncryptionMethod {
    // **ChaCha20-Poly1305-IETF** cypher in blocks per chunk_size bytes
    ChaCha20Poly1305IETF {
        // pwhash_argon2i13::Salt as bytes. Random salt used for deriving of key from passphrase
        salt: Vec<u8>,
        // chacha20poly1305_ietf::Nonce as bytes. Random start nonce. We increment nonce for each
        // chunk to be sure in export file consistency
        nonce: Vec<u8>,
        // size of encrypted chunk
        chunk_size: usize,
    },
    // **ChaCha20-Poly1305-IETF interactive key derivation** cypher in blocks per chunk_size bytes
    ChaCha20Poly1305IETFInteractive {
        // pwhash_argon2i13::Salt as bytes. Random salt used for deriving of key from passphrase
        salt: Vec<u8>,
        // chacha20poly1305_ietf::Nonce as bytes. Random start nonce. We increment nonce for each
        // chunk to be sure in export file consistency
        nonce: Vec<u8>,
        // size of encrypted chunk
        chunk_size: usize,
    },
    // **ChaCha20-Poly1305-IETF raw key** cypher in blocks per chunk_size bytes
    ChaCha20Poly1305IETFRaw {
        // chacha20poly1305_ietf::Nonce as bytes. Random start nonce. We increment nonce for each
        // chunk to be sure in export file consistency
        nonce: Vec<u8>,
        // size of encrypted chunk
        chunk_size: usize,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Header {
    // Method of encryption for encrypted stream
    pub encryption_method: EncryptionMethod,
    // Export time in seconds from UNIX Epoch
    pub time: u64,
    // Version of header
    pub version: u32,
}

pub async fn export(path: &str, key: &str, kdf_method: KeyDerivationMethod) -> VcxCoreResult<()> {
    // indy dep
    let key_data = KeyDerivationData::from_passphrase_with_new_salt(&key, &kdf_method);

    let master_key = key_data.calc_master_key()?;

    let path = PathBuf::from(&path);

    if let Some(parent_path) = path.parent() {
        fs::DirBuilder::new().recursive(true).create(parent_path)?;
    }

    let mut export_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path.clone())?;

    // indy dep
    let nonce = chacha20poly1305_ietf::gen_nonce();

    let encryption_method = match key_data {
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
    };

    let version = 0;
    let header = Header {
        encryption_method,
        time: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        version,
    };
    let header = rmp_serde::to_vec(&header)?;
    let mut writer = BufWriter::new(export_file);
    export_file.write_u32::<LittleEndian>(header.len() as u32)?;
    export_file.write_all(&header)?;

    let mut export_file =
        chacha20poly1305_ietf::Writer::new(export_file, master_key, nonce, CHUNK_SIZE);

    export_file.write_all(&hash(&header)?)?;

    let mut records = wallet.get_all().await?;

    Ok(())
}
