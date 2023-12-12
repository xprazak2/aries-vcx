use base64::{engine::general_purpose, Engine};

use crate::errors::error::{AriesVcxCoreError, AriesVcxCoreErrorKind, VcxCoreResult};

pub fn encode_urlsafe(content: &[u8]) -> String {
    general_purpose::URL_SAFE.encode(content)
}

pub fn bytes_to_string(vec: Vec<u8>) -> VcxCoreResult<String> {
    Ok(String::from_utf8(vec)
        .map_err(|err| AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::InvalidInput, err))?)
}

pub fn bs58_to_bytes(key: &str) -> VcxCoreResult<Vec<u8>> {
    Ok(bs58::decode(key)
        .into_vec()
        .map_err(|err| AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::WalletUnexpected, err))?)
}
