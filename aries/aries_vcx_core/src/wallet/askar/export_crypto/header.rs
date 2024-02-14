use serde::{Deserialize, Serialize};

use super::encryption_method::EncryptionMethod;

#[derive(Debug, Serialize, Deserialize)]
pub struct Header {
    // Method of encryption for encrypted stream
    pub encryption_method: EncryptionMethod,
    // Export time in seconds from UNIX Epoch
    pub time: u64,
    // Version of header
    pub version: u32,
}
