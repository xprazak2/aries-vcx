use aries_askar::kms::{KeyAlg, LocalKey};

use crate::errors::error::VcxCoreResult;

pub fn local_key_to_bs58_name(local_key: &LocalKey) -> VcxCoreResult<String> {
    let res = local_key_to_bs58_public_key(local_key)?;
    Ok(res[0..16].to_string())
}

pub fn local_key_to_bs58_public_key(local_key: &LocalKey) -> VcxCoreResult<String> {
    Ok(bs58::encode(local_key.to_public_bytes()?).into_string())
}

pub fn local_key_to_private_key_bytes(local_key: &LocalKey) -> VcxCoreResult<Vec<u8>> {
    Ok(local_key.to_secret_bytes()?.to_vec())
}

pub fn local_key_to_public_key_bytes(local_key: &LocalKey) -> VcxCoreResult<Vec<u8>> {
    Ok(local_key.to_public_bytes()?.to_vec())
}

pub fn ed25519_to_x25519_pair(local_key: &LocalKey) -> VcxCoreResult<(Vec<u8>, Vec<u8>)> {
    let key = local_key.convert_key(KeyAlg::X25519)?;
    let private_bytes = local_key_to_private_key_bytes(&key)?;
    let public_bytes = local_key_to_public_key_bytes(&key)?;
    Ok((private_bytes, public_bytes))
}

pub fn ed25519_to_x25519_public(local_key: &LocalKey) -> VcxCoreResult<Vec<u8>> {
    let key = local_key.convert_key(KeyAlg::X25519)?;
    let public_bytes = local_key_to_public_key_bytes(&key)?;
    Ok(public_bytes)
}

pub fn ed25519_to_x25519_private(local_key: &LocalKey) -> VcxCoreResult<Vec<u8>> {
    let key = local_key.convert_key(KeyAlg::X25519)?;
    let private_bytes = local_key_to_private_key_bytes(&key)?;
    Ok(private_bytes)
}
