use public_key::Key;
use rand::{distributions::Alphanumeric, Rng};
use serde::Deserialize;

use crate::errors::error::{AriesVcxCoreError, AriesVcxCoreErrorKind, VcxCoreResult};

pub fn bytes_to_string(vec: Vec<u8>) -> VcxCoreResult<String> {
    String::from_utf8(vec)
        .map_err(|err| AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::InvalidInput, err))
}

pub fn bs58_to_bytes(key: &str) -> VcxCoreResult<Vec<u8>> {
    bs58::decode(key)
        .into_vec()
        .map_err(|err| AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::WalletError, err))
}

pub fn bytes_to_bs58(bytes: &[u8]) -> String {
    bs58::encode(bytes).into_string()
}

pub fn from_json_str<T: for<'a> Deserialize<'a>>(json: &str) -> VcxCoreResult<T> {
    serde_json::from_str::<T>(json)
        .map_err(|err| AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::InvalidJson, err))
}

pub fn random_seed() -> String {
    rand::thread_rng()
        .sample_iter(Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

pub fn seed_from_opt(maybe_seed: Option<&str>) -> String {
    match maybe_seed {
        Some(val) => val.into(),
        None => random_seed(),
    }
}

pub fn key_from_base58(value: &str) -> VcxCoreResult<Key> {
    Ok(Key::from_base58(value, public_key::KeyType::Ed25519)?)
}

pub fn key_from_bytes(value: Vec<u8>) -> VcxCoreResult<Key> {
    Ok(Key::new(value, public_key::KeyType::Ed25519)?)
}

pub fn did_from_key(key: Key) -> String {
    key.base58()[0..16].to_string()
}