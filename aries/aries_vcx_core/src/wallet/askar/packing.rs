use aries_askar::{
    kms::{KeyAlg, KeyEntry, LocalKey, ToDecrypt},
    Session,
};

use aries_askar::crypto::alg::Chacha20Types;
use public_key::Key;
use serde::{de::Unexpected, Deserialize, Serialize};

use crate::{
    errors::error::{AriesVcxCoreError, AriesVcxCoreErrorKind, VcxCoreResult},
    wallet::structs_io::UnpackMessageOutput,
    wallet::{
        askar::crypto_box::{CryptoBox, SodiumCryptoBox},
        utils::{
            bs58_to_bytes, bytes_to_bs58, bytes_to_string, decode_urlsafe, encode_urlsafe,
            from_json_str,
        },
    },
};

use super::askar_utils::{
    ed25519_to_x25519_pair, ed25519_to_x25519_private, ed25519_to_x25519_public,
    local_key_to_private_key_bytes, local_key_to_public_key_bytes,
};
use aries_askar::kms::KeyAlg::Ed25519;

pub const PROTECTED_HEADER_ENC: &str = "xchacha20poly1305_ietf";
pub const PROTECTED_HEADER_TYP: &str = "JWM/1.0";

#[derive(Debug)]
pub enum ProtectedHeaderEnc {
    XChaCha20Poly1305,
}

impl Serialize for ProtectedHeaderEnc {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(match self {
            Self::XChaCha20Poly1305 => PROTECTED_HEADER_ENC,
        })
    }
}

impl<'de> Deserialize<'de> for ProtectedHeaderEnc {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;

        match value.as_str() {
            PROTECTED_HEADER_ENC => Ok(Self::XChaCha20Poly1305),
            _ => Err(serde::de::Error::invalid_value(
                Unexpected::Str(value.as_str()),
                &PROTECTED_HEADER_ENC,
            )),
        }
    }
}

#[derive(Debug)]
pub enum ProtectedHeaderTyp {
    Jwm,
}

impl Serialize for ProtectedHeaderTyp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(match self {
            Self::Jwm => PROTECTED_HEADER_TYP,
        })
    }
}

impl<'de> Deserialize<'de> for ProtectedHeaderTyp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;

        match value.as_str() {
            PROTECTED_HEADER_TYP => Ok(Self::Jwm),
            _ => Err(serde::de::Error::invalid_value(
                Unexpected::Str(value.as_str()),
                &PROTECTED_HEADER_TYP,
            )),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(transparent)]
pub struct Base64String(String);

impl Base64String {
    pub fn from_bytes(content: &[u8]) -> Self {
        Self(encode_urlsafe(content))
    }

    pub fn decode(&self) -> VcxCoreResult<Vec<u8>> {
        decode_urlsafe(&self.0)
    }

    pub fn decode_to_string(&self) -> VcxCoreResult<String> {
        bytes_to_string(self.decode()?)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().into()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Jwe {
    pub protected: Base64String,
    pub iv: Base64String,
    pub ciphertext: Base64String,
    pub tag: Base64String,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum JweAlg {
    Authcrypt,
    Anoncrypt,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ProtectedData {
    pub enc: ProtectedHeaderEnc,
    pub typ: ProtectedHeaderTyp,
    pub alg: JweAlg,
    pub recipients: Vec<Recipient>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum Recipient {
    Authcrypt(AuthcryptRecipient),
    Anoncrypt(AnoncryptRecipient),
}

impl Recipient {
    pub fn new_authcrypt(
        encrypted_key: Base64String,
        kid: &str,
        iv: Base64String,
        sender: Base64String,
    ) -> Self {
        Self::Authcrypt(AuthcryptRecipient {
            encrypted_key: encrypted_key,
            header: AuthcryptHeader {
                kid: kid.into(),
                iv: iv,
                sender: sender,
            },
        })
    }

    pub fn new_anoncrypt(encrypted_key: Base64String, kid: &str) -> Self {
        Self::Anoncrypt(AnoncryptRecipient {
            encrypted_key: encrypted_key,
            header: AnoncryptHeader { kid: kid.into() },
        })
    }

    pub fn unwrap_kid(&self) -> &str {
        match self {
            Self::Anoncrypt(inner) => &inner.header.kid,
            Self::Authcrypt(inner) => &inner.header.kid,
        }
    }

    pub fn key_name(&self) -> &str {
        &self.unwrap_kid()[0..16]
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthcryptRecipient {
    pub encrypted_key: Base64String,
    pub header: AuthcryptHeader,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AnoncryptRecipient {
    pub encrypted_key: Base64String,
    pub header: AnoncryptHeader,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthcryptHeader {
    pub kid: String,
    pub iv: Base64String,
    pub sender: Base64String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AnoncryptHeader {
    pub kid: String,
}

pub struct Packing {
    crypto_box: Box<dyn CryptoBox + Send + Sync>,
}

impl Packing {
    pub fn new() -> Self {
        Self {
            crypto_box: Box::new(SodiumCryptoBox::new()),
        }
    }

    pub async fn unpack(
        &self,
        jwe: Jwe,
        session: &mut Session,
    ) -> VcxCoreResult<UnpackMessageOutput> {
        let protected_data_str = &jwe.protected.decode_to_string()?;
        // let protected_data_str = bytes_to_string(protected_data_vec)?;
        let protected_data = from_json_str(&protected_data_str)?;

        let (recipient, key_entry) = self.find_recipient_key(&protected_data, session).await?;
        let local_key = key_entry.load_local_key()?;

        let (enc_key, sender_verkey) = self.unpack_recipient(recipient, &local_key)?;

        let nonce = &jwe.iv.decode()?;
        let ciphertext = &jwe.ciphertext.decode()?;
        let tag = &jwe.tag.decode()?;

        let to_decrypt = ToDecrypt::from((ciphertext.as_ref(), tag.as_ref()));

        let msg = enc_key.aead_decrypt(to_decrypt, &nonce, &jwe.protected.as_bytes())?;

        let unpacked = UnpackMessageOutput {
            message: bytes_to_string(msg.to_vec())?,
            recipient_verkey: recipient.unwrap_kid().to_owned(),
            sender_verkey,
        };

        Ok(unpacked)
    }

    fn unpack_recipient(
        &self,
        recipient: &Recipient,
        local_key: &LocalKey,
    ) -> VcxCoreResult<(LocalKey, Option<String>)> {
        let res = match recipient {
            Recipient::Authcrypt(auth_recipient) => {
                self.unpack_authcrypt(&local_key, auth_recipient)
            }
            Recipient::Anoncrypt(anon_recipient) => {
                self.unpack_anoncrypt(&local_key, anon_recipient)
            }
        }?;

        Ok(res)
    }

    fn unpack_authcrypt(
        &self,
        local_key: &LocalKey,
        recipient: &AuthcryptRecipient,
    ) -> VcxCoreResult<(LocalKey, Option<String>)> {
        let encrypted_key = &recipient.encrypted_key.decode()?;
        let iv = &recipient.header.iv.decode()?;

        let sender_vk_enc = &recipient.header.sender.decode()?;

        let (private_bytes, public_bytes) = ed25519_to_x25519_pair(local_key)?;

        let sender_vk_vec =
            self.crypto_box
                .sealedbox_decrypt(&private_bytes, &public_bytes, &sender_vk_enc)?;

        let sender_vk = bytes_to_string(sender_vk_vec)?;

        let sender_vk_local_key =
            LocalKey::from_public_bytes(Ed25519, &bs58_to_bytes(&sender_vk)?)?;

        let sender_vk_public_bytes = ed25519_to_x25519_public(&sender_vk_local_key)?;

        let cek_vec = self.crypto_box.box_decrypt(
            &private_bytes,
            &sender_vk_public_bytes,
            &encrypted_key,
            &iv,
        )?;

        let enc_key = LocalKey::from_secret_bytes(KeyAlg::Chacha20(Chacha20Types::C20P), &cek_vec)?;

        Ok((enc_key, Some(sender_vk)))
    }

    fn unpack_anoncrypt(
        &self,
        local_key: &LocalKey,
        recipient: &AnoncryptRecipient,
    ) -> VcxCoreResult<(LocalKey, Option<String>)> {
        let encrypted_key = &recipient.encrypted_key.decode()?;

        let (private_bytes, public_bytes) = ed25519_to_x25519_pair(local_key)?;

        let cek_vec =
            self.crypto_box
                .sealedbox_decrypt(&private_bytes, &public_bytes, &encrypted_key)?;
        let enc_key = LocalKey::from_secret_bytes(KeyAlg::Chacha20(Chacha20Types::C20P), &cek_vec)?;

        Ok((enc_key, None))
    }

    async fn find_recipient_key<'a>(
        &self,
        protected_data: &'a ProtectedData,
        session: &mut Session,
    ) -> VcxCoreResult<(&'a Recipient, KeyEntry)> {
        for recipient in protected_data.recipients.iter() {
            if let Some(key_entry) = session.fetch_key(&recipient.key_name(), false).await? {
                return Ok((recipient, key_entry));
            };
        }

        Err(AriesVcxCoreError::from_msg(
            AriesVcxCoreErrorKind::WalletRecordNotFound,
            "recipient key not found in wallet",
        ))
    }

    pub fn pack_all(
        &self,
        base64_data: Base64String,
        enc_key: LocalKey,
        msg: &[u8],
    ) -> VcxCoreResult<Vec<u8>> {
        let nonce = enc_key.aead_random_nonce()?;
        let enc = enc_key.aead_encrypt(msg, &nonce, &base64_data.as_bytes())?;

        let jwe = Jwe {
            protected: base64_data,
            iv: Base64String::from_bytes(enc.nonce()),
            ciphertext: Base64String::from_bytes(enc.ciphertext()),
            tag: Base64String::from_bytes(enc.tag()),
        };

        serde_json::to_vec(&jwe).map_err(|err| {
            AriesVcxCoreError::from_msg(
                AriesVcxCoreErrorKind::EncodeError,
                format!("Failed to serialize JWE {}", err),
            )
        })
    }

    pub fn pack_authcrypt(
        &self,
        enc_key: &LocalKey,
        recipient_keys: Vec<Key>,
        sender_local_key: LocalKey,
    ) -> VcxCoreResult<Base64String> {
        self.check_supported_key_alg(&sender_local_key)?;

        let encrypted_recipients =
            self.pack_authcrypt_recipients(enc_key, recipient_keys, sender_local_key)?;

        Ok(self.encode_protected_data(encrypted_recipients, JweAlg::Authcrypt)?)
    }

    fn check_supported_key_alg(&self, key: &LocalKey) -> VcxCoreResult<()> {
        let supported_algs = vec![Ed25519];

        if !supported_algs.contains(&key.algorithm()) {
            let msg = format!(
                "Unsupported key algorithm, expected one of: {}",
                supported_algs
                    .into_iter()
                    .map(|alg| alg.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            return Err(AriesVcxCoreError::from_msg(
                AriesVcxCoreErrorKind::InvalidOption,
                msg,
            ));
        }
        Ok(())
    }

    fn pack_authcrypt_recipients(
        &self,
        enc_key: &LocalKey,
        recipient_keys: Vec<Key>,
        sender_local_key: LocalKey,
    ) -> VcxCoreResult<Vec<Recipient>> {
        let my_original_public_bytes = local_key_to_public_key_bytes(&sender_local_key)?;
        let my_secret_bytes = ed25519_to_x25519_private(&sender_local_key)?;

        let enc_key_secret = local_key_to_private_key_bytes(enc_key)?;

        let mut encrypted_recipients = Vec::with_capacity(recipient_keys.len());

        for recipient_key in recipient_keys {
            // could it be &recipient_key.key()
            let recipient_pubkey = bs58_to_bytes(&recipient_key.base58())?;
            let recipient_local_key = LocalKey::from_public_bytes(Ed25519, &recipient_pubkey)?;
            let recipient_public_bytes = ed25519_to_x25519_public(&recipient_local_key)?;

            let (enc_cek, nonce) = self.crypto_box.box_encrypt(
                &my_secret_bytes,
                &recipient_public_bytes,
                &enc_key_secret,
            )?;

            let enc_sender = self.crypto_box.sealedbox_encrypt(
                &recipient_public_bytes,
                bytes_to_bs58(&my_original_public_bytes).as_bytes(),
            )?;

            let kid = bytes_to_bs58(&recipient_pubkey);
            // ?could previous line be:
            // let kid = recipient_key.base58();
            let sender = Base64String::from_bytes(&enc_sender);
            let iv = Base64String::from_bytes(&nonce);

            encrypted_recipients.push(Recipient::new_authcrypt(
                Base64String::from_bytes(&enc_cek),
                &kid,
                iv,
                sender,
            ));
        }

        Ok(encrypted_recipients)
    }

    pub fn pack_anoncrypt(
        &self,
        enc_key: &LocalKey,
        recipient_keys: Vec<Key>,
    ) -> VcxCoreResult<Base64String> {
        let encrypted_recipients = self.pack_anoncrypt_recipients(enc_key, recipient_keys)?;

        Ok(self.encode_protected_data(encrypted_recipients, JweAlg::Anoncrypt)?)
    }

    fn pack_anoncrypt_recipients(
        &self,
        enc_key: &LocalKey,
        recipient_keys: Vec<Key>,
    ) -> VcxCoreResult<Vec<Recipient>> {
        let mut encrypted_recipients = Vec::with_capacity(recipient_keys.len());

        let enc_key_secret = local_key_to_private_key_bytes(enc_key)?;

        for recipient_key in recipient_keys {
            let recipient_pubkey = bs58_to_bytes(&recipient_key.base58())?;
            let recipient_local_key = LocalKey::from_public_bytes(Ed25519, &recipient_pubkey)?;
            let recipient_public_bytes = ed25519_to_x25519_public(&recipient_local_key)?;

            let enc_cek = self
                .crypto_box
                .sealedbox_encrypt(&recipient_public_bytes, &enc_key_secret)?;

            let kid = bytes_to_bs58(&recipient_pubkey);

            encrypted_recipients.push(Recipient::new_anoncrypt(
                Base64String::from_bytes(&enc_cek),
                &kid,
            ));
        }

        Ok(encrypted_recipients)
    }

    fn encode_protected_data(
        &self,
        encrypted_recipients: Vec<Recipient>,
        jwe_alg: JweAlg,
    ) -> VcxCoreResult<Base64String> {
        let protected_data = ProtectedData {
            enc: ProtectedHeaderEnc::XChaCha20Poly1305,
            typ: ProtectedHeaderTyp::Jwm,
            alg: jwe_alg,
            recipients: encrypted_recipients,
        };

        let protected_encoded = serde_json::to_string(&protected_data).map_err(|err| {
            AriesVcxCoreError::from_msg(
                AriesVcxCoreErrorKind::EncodeError,
                format!("Failed to serialize protected field {}", err),
            )
        })?;

        Ok(Base64String::from_bytes(protected_encoded.as_bytes()))
    }
}
