use std::{
    fs,
    io::{BufReader, Read},
};

use byteorder::{LittleEndian, ReadBytesExt};
use sodiumoxide::crypto::{aead::chacha20poly1305::Nonce, pwhash::Salt};

use crate::errors::error::{AriesVcxCoreError, AriesVcxCoreErrorKind, VcxCoreResult};

use super::export_crypto::{
    encryption_method::EncryptionMethod,
    header::Header,
    key_derivation::KeyDerivationData,
    key_derivation_method::{self, KeyDerivationMethod},
};

pub async fn import(path: &str, key: &str, kdf_method: KeyDerivationMethod) -> VcxCoreResult<()> {
    let exported_file = fs::OpenOptions::new().read(true).open(&path)?;

    let (reader, import_key_derivation_data, nonce, chunk_size, header_bytes) =
        preparse_file_to_import(exported_file, &key)?;

    // let key_data = KeyDerivationData::from_passphrase_with_new_salt(
    //     &credentials.key,
    //     &credentials.key_derivation_method,
    // );

    Ok(())
}

// #[allow(clippy::type_complexity)]
fn preparse_file_to_import<T>(
    reader: T,
    passphrase: &str,
) -> VcxCoreResult<(
    BufReader<T>,
    KeyDerivationData,
    chacha20poly1305_ietf::Nonce,
    usize,
    Vec<u8>,
)>
where
    T: Read,
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

    let key_derivation_method = header.to_key_derivation_method();

    let (import_key_derivation_data, nonce, chunk_size) =
        read_encrypted_header(header, passphrase)?;

    Ok((
        reader,
        import_key_derivation_data,
        nonce,
        chunk_size,
        header_bytes,
    ))
}

fn read_encrypted_header(
    header: Header,
    passphrase: &str,
) -> VcxCoreResult<(KeyDerivationData, Nonce, usize)> {
    match header.encryption_method {
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
            let salt = Salt::from_slice(&salt)?;
            let nonce = Nonce::from_slice(&nonce)?;
            let passphrase = passphrase.to_owned();

            let key_data = match key_derivation_method {
                KeyDerivationMethod::ARGON2I_INT => KeyDerivationData::Argon2iInt(passphrase, salt),
                KeyDerivationMethod::ARGON2I_MOD => KeyDerivationData::Argon2iMod(passphrase, salt),
                _ => unimplemented!("FIXME"), //FIXME
            };

            Ok((key_data, nonce, chunk_size))
        }
        EncryptionMethod::ChaCha20Poly1305IETFRaw { nonce, chunk_size } => {
            let nonce = Nonce::from_slice(&nonce)?;

            let key_data = KeyDerivationData::Raw(passphrase.to_owned());

            Ok((key_data, nonce, chunk_size))
        }
    }
}

fn read_header(reader: &mut BufReader<dyn Read>) -> VcxCoreResult<Header> {
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
