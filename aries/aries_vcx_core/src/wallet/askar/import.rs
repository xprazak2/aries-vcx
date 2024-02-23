use std::{
    fs,
    io::{BufReader, Read},
};

use aries_askar::entry::EntryTag as AskarEntryTag;
use async_trait::async_trait;
use byteorder::{LittleEndian, ReadBytesExt};
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::{aead::chacha20poly1305_ietf, auth::hmacsha256, pwhash::Salt};
use zeroize::Zeroize;

use super::{
    export_crypto::{
        chacha20poly1305ietf,
        encryption_method::EncryptionMethod,
        header::Header,
        key_derivation::KeyDerivationData,
        key_derivation_method::{self, KeyDerivationMethod},
    },
    AskarWallet, AskarWalletConfig, KeyValue,
};
use crate::{
    errors::error::{AriesVcxCoreError, AriesVcxCoreErrorKind, VcxCoreResult},
    wallet::{
        base_wallet::{
            record::Record, record_wallet::RecordWallet, CoreWallet, ImportWallet, ManageWallet,
        },
        constants::INDY_KEY,
    },
};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum Metadata {
    MetadataArgon(MetadataArgon),
    MetadataRaw(MetadataRaw),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MetadataArgon {
    pub keys: Vec<u8>,
    pub master_key_salt: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MetadataRaw {
    pub keys: Vec<u8>,
}

// pub fn gen_nonce_and_encrypt(
//     data: &[u8],
//     key: &chacha20poly1305_ietf::Key,
// ) -> (Vec<u8>, chacha20poly1305_ietf::Nonce) {
//     let nonce = chacha20poly1305_ietf::gen_nonce();

//     let encrypted_data = chacha20poly1305_ietf::seal(data, None, &nonce, &key);

//     (encrypted_data, nonce)
// }

// fn encrypt_as_not_searchable(data: &[u8], key: &chacha20poly1305_ietf::Key) -> Vec<u8> {
//     let (ct, nonce) = gen_nonce_and_encrypt(data, key);

//     let mut result: Vec<u8> = Default::default();
//     result.extend_from_slice(&nonce[..]);
//     result.extend_from_slice(&ct);
//     result
// }

// #[derive(Serialize, Deserialize)]
// pub struct Keys {
//     pub type_key: chacha20poly1305_ietf::Key,
//     pub name_key: chacha20poly1305_ietf::Key,
//     pub value_key: chacha20poly1305_ietf::Key,
//     pub item_hmac_key: hmacsha256::Key,
//     pub tag_name_key: chacha20poly1305_ietf::Key,
//     pub tag_value_key: chacha20poly1305_ietf::Key,
//     pub tags_hmac_key: hmacsha256::Key,
// }

// #[allow(clippy::new_without_default)]
// impl Keys {
//     pub fn new() -> Keys {
//         Keys {
//             type_key: chacha20poly1305_ietf::gen_key(),
//             name_key: chacha20poly1305_ietf::gen_key(),
//             value_key: chacha20poly1305_ietf::gen_key(),
//             item_hmac_key: hmacsha256::gen_key(),
//             tag_name_key: chacha20poly1305_ietf::gen_key(),
//             tag_value_key: chacha20poly1305_ietf::gen_key(),
//             tags_hmac_key: hmacsha256::gen_key(),
//         }
//     }

//     pub fn serialize_encrypted(
//         &self,
//         master_key: &chacha20poly1305_ietf::Key,
//     ) -> VcxCoreResult<Vec<u8>> {
//         let mut serialized = rmp_serde::to_vec(self)?;

//         let encrypted = encrypt_as_not_searchable(&serialized, master_key);

//         serialized.zeroize();
//         Ok(encrypted)
//     }

// pub fn deserialize_encrypted(
//     bytes: &[u8],
//     master_key: &chacha20poly1305_ietf::Key,
// ) -> IndyResult<Keys> {
//     let mut decrypted = decrypt_merged(bytes, master_key)?;

//     let keys: Keys = rmp_serde::from_slice(&decrypted)
//         .to_indy(IndyErrorKind::InvalidState, "Invalid bytes for Key")?;

//     decrypted.zeroize();
//     Ok(keys)
// }
// }

#[derive(Debug)]
pub struct AskarImportConfig<'a> {
    wallet_config: AskarWalletConfig<'a>,
    exported_file_path: String,
    key: String,
    kdf_method: KeyDerivationMethod,
}

impl<'a> AskarImportConfig<'a> {
    pub fn new(
        wallet_config: &AskarWalletConfig<'a>,
        path: &str,
        key: &str,
        kdf_method: KeyDerivationMethod,
    ) -> Self {
        Self {
            wallet_config: wallet_config.clone(),
            exported_file_path: path.into(),
            key: key.into(),
            kdf_method,
        }
    }
}

#[async_trait]
impl<'a> ImportWallet for AskarImportConfig<'static> {
    async fn import_wallet(&self) -> VcxCoreResult<Box<dyn ManageWallet>> {
        println!("wallet config: {:?}", self.wallet_config);

        let wallet = self.wallet_config.create_wallet().await?;

        import(
            &self.exported_file_path,
            &self.key,
            &self.kdf_method,
            wallet,
        )
        .await?;

        Ok(Box::new(self.wallet_config.clone()))
    }
}

async fn import<'a>(
    path: &str,
    key: &str,
    kdf_method: &KeyDerivationMethod,
    wallet: CoreWallet,
) -> VcxCoreResult<()> {
    let exported_file = fs::OpenOptions::new().read(true).open(&path)?;
    println!("preparing file to import");
    let (reader, import_key_derivation_data, nonce, chunk_size, header_bytes) =
        prepare_file_to_import(exported_file, &key)?;

    // let key_data = KeyDerivationData::from_passphrase_with_new_salt(
    //     &credentials.key,
    //     &credentials.key_derivation_method,
    // );

    let key_data = KeyDerivationData::from_passphrase_with_new_salt(&key, &kdf_method);

    let import_key = import_key_derivation_data.calc_master_key()?;
    // let master_key = key_data.calc_master_key()?;

    // let keys = Keys::new();

    // let encrypted_keys = keys.serialize_encrypted(&master_key)?;

    // let metadata = match key_data {
    //     KeyDerivationData::Raw(_) => Metadata::MetadataRaw(MetadataRaw {
    //         keys: encrypted_keys,
    //     }),
    //     KeyDerivationData::Argon2iInt(_, salt) | KeyDerivationData::Argon2iMod(_, salt) => {
    //         Metadata::MetadataArgon(MetadataArgon {
    //             keys: encrypted_keys,
    //             master_key_salt: salt[..].to_vec(),
    //         })
    //     }
    // };

    println!("trying to open a wallet");

    // let wallet = AskarWallet::open(&wallet_config).await?;

    println!("opened wallet");

    let mut reader = chacha20poly1305ietf::Reader::new(reader, import_key, nonce, chunk_size);

    read_header(&mut reader)?;

    // let mut header_hash = vec![0u8; HASHBYTES];
    // reader.read_exact(&mut header_hash).map_err(_map_io_err)?;

    // if hash(&header_bytes)? != header_hash {
    //     return Err(err_msg(
    //         IndyErrorKind::InvalidStructure,
    //         "Invalid header hash",
    //     ));
    // }

    loop {
        let record_len = reader.read_u32::<LittleEndian>()? as usize;

        if record_len == 0 {
            break;
        }

        let mut record = vec![0u8; record_len];
        reader.read_exact(&mut record)?;

        let record: Record = rmp_serde::from_slice(&record)?;

        match record.category() {
            INDY_KEY => {
                let key_value: KeyValue = serde_json::from_str(record.value())?;
                let askar_tags: Vec<AskarEntryTag> = record.tags().clone().into();

                wallet
                    .create_key(record.name(), &key_value, Some(askar_tags.as_ref()))
                    .await?;
            }
            _ => wallet.add_record(record).await?,
        }
    }

    // let metadata_json = serde_json::to_vec(&metadata)?;

    // let (storage_type, storage_config, storage_credentials) =
    //         get_config_and_cred_for_storage(config, credentials)?;

    Ok(())
}

// #[allow(clippy::type_complexity)]
fn prepare_file_to_import<T>(
    reader: T,
    passphrase: &str,
) -> VcxCoreResult<(
    BufReader<T>,
    KeyDerivationData,
    chacha20poly1305_ietf::Nonce,
    usize,
    Header,
)>
where
    T: Read + 'static,
{
    // Reads plain
    let mut reader = BufReader::new(reader);

    // let header_len = reader.read_u32::<LittleEndian>().map_err(_map_io_err)? as usize;
    // let header_len = reader.read_u32::<LittleEndian>()? as usize;

    // if header_len == 0 {
    //     return Err(AriesVcxCoreError::from_msg(
    //         AriesVcxCoreErrorKind::InvalidStructure,
    //         "Unexpected header length",
    //     ));
    // }

    // let mut header_bytes = vec![0u8; header_len];
    // reader.read_exact(&mut header_bytes)?;

    // let header: Header = rmp_serde::from_slice(&header_bytes)?;

    // if header.version != 0 {
    //     return Err(AriesVcxCoreError::from_msg(
    //         AriesVcxCoreErrorKind::InvalidStructure,
    //         "Unsupported version",
    //     ));
    // }

    let header = read_header(&mut reader)?;

    // let key_derivation_method = match header.encryption_method {
    //     EncryptionMethod::ChaCha20Poly1305IETF { .. } => KeyDerivationMethod::ARGON2I_MOD,
    //     EncryptionMethod::ChaCha20Poly1305IETFInteractive { .. } => {
    //         KeyDerivationMethod::ARGON2I_INT
    //     }
    //     EncryptionMethod::ChaCha20Poly1305IETFRaw { .. } => KeyDerivationMethod::RAW,
    // };

    // let key_derivation_method = header.to_key_derivation_method();

    let (import_key_derivation_data, nonce, chunk_size) =
        read_encrypted_header(&header, passphrase)?;

    Ok((
        reader,
        import_key_derivation_data,
        nonce,
        chunk_size,
        header,
    ))
}

fn nonce_from_slice(nonce: &Vec<u8>) -> VcxCoreResult<chacha20poly1305_ietf::Nonce> {
    chacha20poly1305_ietf::Nonce::from_slice(nonce).ok_or_else(|| {
        AriesVcxCoreError::from_msg(
            AriesVcxCoreErrorKind::ParsingError,
            "unexpected nonce length",
        )
    })
}

fn salt_from_slice(salt: &Vec<u8>) -> VcxCoreResult<Salt> {
    Salt::from_slice(salt).ok_or_else(|| {
        AriesVcxCoreError::from_msg(
            AriesVcxCoreErrorKind::ParsingError,
            "unexpected salt length",
        )
    })
}

fn read_encrypted_header(
    header: &Header,
    passphrase: &str,
) -> VcxCoreResult<(KeyDerivationData, chacha20poly1305_ietf::Nonce, usize)> {
    let key_derivation_method = header.to_key_derivation_method();

    match &header.encryption_method {
        EncryptionMethod::ChaCha20Poly1305IETF {
            salt,
            nonce,
            chunk_size,
        }
        | EncryptionMethod::ChaCha20Poly1305IETFInteractive {
            salt,
            nonce,
            chunk_size,
        } => {
            let salt = salt_from_slice(&salt)?;
            let nonce = nonce_from_slice(&nonce)?;
            let passphrase = passphrase.to_owned();

            let key_data = match key_derivation_method {
                KeyDerivationMethod::ARGON2I_INT => KeyDerivationData::Argon2iInt(passphrase, salt),
                KeyDerivationMethod::ARGON2I_MOD => KeyDerivationData::Argon2iMod(passphrase, salt),
                _ => unimplemented!("FIXME"),
            };

            Ok((key_data, nonce, *chunk_size))
        }
        EncryptionMethod::ChaCha20Poly1305IETFRaw { nonce, chunk_size } => {
            let nonce = nonce_from_slice(nonce)?;
            let key_data = KeyDerivationData::Raw(passphrase.to_owned());
            Ok((key_data, nonce, *chunk_size))
        }
    }
}

fn read_header(reader: &mut impl Read) -> VcxCoreResult<Header> {
    let header_len = reader.read_u32::<LittleEndian>()? as usize;

    if header_len == 0 {
        return Err(AriesVcxCoreError::from_msg(
            AriesVcxCoreErrorKind::InvalidInput,
            "Unexpected header length",
        ));
    }

    let mut header_bytes = vec![0u8; header_len];
    reader.read_exact(&mut header_bytes)?;

    let header: Header = rmp_serde::from_slice(&header_bytes)?;

    if header.version != 0 {
        return Err(AriesVcxCoreError::from_msg(
            AriesVcxCoreErrorKind::InvalidInput,
            "Unsupported version",
        ));
    }

    return Ok(header);
}
