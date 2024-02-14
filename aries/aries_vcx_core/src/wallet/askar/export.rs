use std::{
    fs::{self, File},
    io::{BufWriter, Write},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::aead::chacha20poly1305_ietf;

use byteorder::{LittleEndian, WriteBytesExt};

use crate::{
    errors::error::VcxCoreResult,
    wallet::base_wallet::{record::AllRecords, BaseWallet},
};

use super::export_crypto::{
    chacha20poly1305ietf,
    encryption_method::{self, EncryptionMethod, CHUNK_SIZE},
    hash::hash,
    header::Header,
    key_derivation::KeyDerivationData,
    key_derivation_method::KeyDerivationMethod,
};

fn create_export_file(path: &str) -> VcxCoreResult<File> {
    let path = PathBuf::from(&path);

    if let Some(parent_path) = path.parent() {
        fs::DirBuilder::new().recursive(true).create(parent_path)?;
    }

    let export_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path.clone())?;

    Ok(export_file)
}

fn create_header(encryption_method: EncryptionMethod) -> Header {
    Header {
        encryption_method,
        time: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        version: 0,
    }
}

pub async fn export(
    path: &str,
    key: &str,
    kdf_method: KeyDerivationMethod,
    all_records: &mut Box<dyn AllRecords + Send>,
) -> VcxCoreResult<()> {
    let key_data = KeyDerivationData::from_passphrase_with_new_salt(&key, &kdf_method);
    let master_key = key_data.calc_master_key()?;

    // let path = PathBuf::from(&path);

    // if let Some(parent_path) = path.parent() {
    //     fs::DirBuilder::new().recursive(true).create(parent_path)?;
    // }

    // let export_file = fs::OpenOptions::new()
    //     .write(true)
    //     .create_new(true)
    //     .open(path.clone())?;

    let nonce = chacha20poly1305_ietf::gen_nonce();

    let encryption_method = key_data.encryption_method(nonce);

    // let version = 0;
    // let header = Header {
    //     encryption_method,
    //     time: SystemTime::now()
    //         .duration_since(UNIX_EPOCH)
    //         .unwrap()
    //         .as_secs(),
    //     version,
    // };

    let header = create_header(encryption_method);
    let header = rmp_serde::to_vec(&header)?;

    let export_file = create_export_file(path)?;

    let mut writer = BufWriter::new(export_file);
    writer.write_u32::<LittleEndian>(header.len() as u32)?;
    writer.write_all(&header)?;

    let mut writer = chacha20poly1305ietf::Writer::new(writer, master_key, nonce, CHUNK_SIZE);

    writer.write_all(&hash(&header)?)?;

    while let Some(partial_record) = all_records.next().await? {
        let rmp_record = rmp_serde::to_vec(&partial_record.try_into_record()?)?;

        writer.write_u32::<LittleEndian>(rmp_record.len() as u32)?;
        writer.write_all(&rmp_record)?;
    }

    writer.write_u32::<LittleEndian>(0)?; // END message
    writer.flush()?;

    Ok(())
}
