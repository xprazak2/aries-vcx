use serde::{Deserialize, Serialize};

pub const CHUNK_SIZE: usize = 1024;

#[derive(Debug, Serialize, Deserialize)]
pub enum EncryptionMethod {
    // **ChaCha20-Poly1305-IETF** cypher in blocks per chunk_size bytes
    ChaCha20Poly1305IETF {
        // Salt as bytes. Random salt used for deriving of key from passphrase
        salt: Vec<u8>,
        // Nonce as bytes. Random start nonce. We increment nonce for each
        // chunk to be sure in export file consistency
        nonce: Vec<u8>,
        // size of encrypted chunk
        chunk_size: usize,
    },
    // **ChaCha20-Poly1305-IETF interactive key derivation** cypher in blocks per chunk_size bytes
    ChaCha20Poly1305IETFInteractive {
        // Salt as bytes. Random salt used for deriving of key from passphrase
        salt: Vec<u8>,
        // Nonce as bytes. Random start nonce. We increment nonce for each
        // chunk to be sure in export file consistency
        nonce: Vec<u8>,
        // size of encrypted chunk
        chunk_size: usize,
    },
    // **ChaCha20-Poly1305-IETF raw key** cypher in blocks per chunk_size bytes
    ChaCha20Poly1305IETFRaw {
        // Nonce as bytes. Random start nonce. We increment nonce for each
        // chunk to be sure in export file consistency
        nonce: Vec<u8>,
        // size of encrypted chunk
        chunk_size: usize,
    },
}
