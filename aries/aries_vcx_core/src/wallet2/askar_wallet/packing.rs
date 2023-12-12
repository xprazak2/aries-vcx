use aries_askar::kms::LocalKey;
use serde::{Deserialize, Serialize};

use crate::{
    errors::error::{AriesVcxCoreError, AriesVcxCoreErrorKind, VcxCoreResult},
    wallet2::{
        crypto_box::{CryptoBox, SodiumCryptoBox},
        utils::{bs58_to_bytes, bytes_to_string, encode_urlsafe},
        Key,
    },
};

pub const PROTECTED_HEADER_ENC: &str = "xchacha20poly1305_ietf";
pub const PROTECTED_HEADER_TYP: &str = "JWM/1.0";

#[derive(Serialize, Deserialize)]
pub struct Jwe {
    pub protected: String,
    pub iv: String,
    pub ciphertext: String,
    pub tag: String,
}

#[derive(Serialize, Deserialize)]
pub enum JweAlg {
    Authcrypt,
    Anoncrypt,
}

#[derive(Serialize, Deserialize)]
pub struct ProtectedData {
    pub enc: String,
    pub typ: String,
    pub alg: JweAlg,
    pub recipients: Vec<Recipient>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct Recipient {
    pub encrypted_key: String,
    pub header: Header,
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct Header {
    pub kid: String,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iv: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender: Option<String>,
}

pub struct Packing {
    pub crypto_box: Box<dyn CryptoBox + Send>,
}

impl Packing {
    pub fn new() -> Self {
        Self {
            crypto_box: Box::new(SodiumCryptoBox {}),
        }
    }

    pub fn pack_all(
        &self,
        base64_protected: &str,
        ciphertext: &str,
        iv: &str,
        tag: &str,
    ) -> VcxCoreResult<Vec<u8>> {
        let jwe = Jwe {
            protected: base64_protected.to_string(),
            iv: iv.to_string(),
            ciphertext: ciphertext.to_string(),
            tag: tag.to_string(),
        };

        serde_json::to_vec(&jwe).map_err(|err| {
            AriesVcxCoreError::from_msg(
                AriesVcxCoreErrorKind::EncodeError,
                format!("Failed to serialize JWE {}", err),
            )
        })
    }

    fn local_key_to_private_key_bytes(&self, local_key: &LocalKey) -> VcxCoreResult<Vec<u8>> {
        Ok(local_key.to_secret_bytes()?.to_vec())
    }

    fn local_key_to_public_key_bytes(&self, local_key: &LocalKey) -> VcxCoreResult<Vec<u8>> {
        Ok(local_key.to_public_bytes()?.to_vec())
    }

    pub fn pack_authcrypt(
        &self,
        enc_key: &LocalKey,
        recipient_keys: Vec<Key>,
        sender_local_key: LocalKey,
    ) -> VcxCoreResult<String> {
        let encrypted_recipients =
            self.pack_authcrypt_recipients(enc_key, recipient_keys, sender_local_key)?;

        Ok(self.encode_protected_data(encrypted_recipients, JweAlg::Authcrypt)?)
    }

    fn pack_authcrypt_recipients(
        &self,
        enc_key: &LocalKey,
        recipient_keys: Vec<Key>,
        sender_local_key: LocalKey,
    ) -> VcxCoreResult<Vec<Recipient>> {
        let my_secret_bytes = self.local_key_to_private_key_bytes(&sender_local_key)?;
        let my_public_bytes = self.local_key_to_public_key_bytes(&sender_local_key)?;

        let enc_key_secret = self.local_key_to_private_key_bytes(enc_key)?;

        let mut encrypted_recipients = Vec::with_capacity(recipient_keys.len());

        for recipient_key in recipient_keys {
            let recipient_pubkey = bs58_to_bytes(&recipient_key.pubkey_bs58)?;

            let (enc_cek, nonce) = self.crypto_box.box_encrypt(
                &my_secret_bytes,
                &recipient_pubkey,
                &enc_key_secret,
            )?;

            let enc_sender = self
                .crypto_box
                .sealedbox_encrypt(&recipient_pubkey, &my_public_bytes)?;

            encrypted_recipients.push(Recipient {
                encrypted_key: encode_urlsafe(&enc_cek),
                header: Header {
                    kid: bytes_to_string(recipient_pubkey)?,
                    sender: Some(encode_urlsafe(&enc_sender)),
                    iv: Some(encode_urlsafe(&nonce)),
                },
            });
        }

        Ok(encrypted_recipients)
    }

    pub fn pack_anoncrypt(
        &self,
        enc_key: &LocalKey,
        recipient_keys: Vec<Key>,
    ) -> VcxCoreResult<String> {
        let encrypted_recipients = self.pack_anoncrypt_recipients(enc_key, recipient_keys)?;

        Ok(self.encode_protected_data(encrypted_recipients, JweAlg::Anoncrypt)?)
    }

    fn pack_anoncrypt_recipients(
        &self,
        enc_key: &LocalKey,
        recipient_keys: Vec<Key>,
    ) -> VcxCoreResult<Vec<Recipient>> {
        let mut encrypted_recipients = Vec::with_capacity(recipient_keys.len());

        let enc_key_secret = self.local_key_to_private_key_bytes(enc_key)?;

        for recipient_key in recipient_keys {
            let recipient_pubkey = bs58_to_bytes(&recipient_key.pubkey_bs58)?;

            let enc_cek = self
                .crypto_box
                .sealedbox_encrypt(&recipient_pubkey, &enc_key_secret)?;

            encrypted_recipients.push(Recipient {
                encrypted_key: encode_urlsafe(&enc_cek),
                header: Header {
                    kid: bytes_to_string(recipient_pubkey)?,
                    sender: None,
                    iv: None,
                },
            });
        }

        Ok(encrypted_recipients)
    }

    fn encode_protected_data(
        &self,
        encrypted_recipients: Vec<Recipient>,
        jwe_alg: JweAlg,
    ) -> VcxCoreResult<String> {
        let protected_data = ProtectedData {
            enc: PROTECTED_HEADER_ENC.into(),
            typ: PROTECTED_HEADER_TYP.into(),
            alg: jwe_alg,
            recipients: encrypted_recipients,
        };
        let protected_encoded = serde_json::to_string(&protected_data).map_err(|err| {
            AriesVcxCoreError::from_msg(
                AriesVcxCoreErrorKind::EncodeError,
                format!("Failed to serialize protected field {}", err),
            )
        })?;
        Ok(encode_urlsafe(protected_encoded.as_bytes()))
    }
}
