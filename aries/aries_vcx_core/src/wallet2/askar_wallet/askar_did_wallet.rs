use aries_askar::{
    crypto::alg::{Chacha20Types, EcCurves},
    kms::{KeyAlg, LocalKey},
};
use async_trait::async_trait;

use super::{packing::Packing, AskarWallet, RngMethod};
use crate::{
    errors::error::{AriesVcxCoreError, AriesVcxCoreErrorKind, VcxCoreResult},
    wallet2::{DidData, DidWallet, Key, UnpackedMessage},
};

pub enum SigType {
    EdDSA,
    ES256,
    ES256K,
    ES384,
}

impl From<SigType> for &str {
    fn from(value: SigType) -> Self {
        match value {
            SigType::EdDSA => "eddsa",
            SigType::ES256 => "es256",
            SigType::ES256K => "es256k",
            SigType::ES384 => "es384",
        }
    }
}

impl TryFrom<KeyAlg> for SigType {
    type Error = AriesVcxCoreError;

    fn try_from(value: KeyAlg) -> Result<Self, Self::Error> {
        match value {
            KeyAlg::Ed25519 => Ok(SigType::EdDSA),
            KeyAlg::EcCurve(item) => match item {
                EcCurves::Secp256r1 => Ok(SigType::ES256),
                EcCurves::Secp256k1 => Ok(SigType::ES256K),
                EcCurves::Secp384r1 => Ok(SigType::ES384),
            },
            _ => Err(AriesVcxCoreError::from_msg(
                AriesVcxCoreErrorKind::InvalidInput,
                "this key does not support signing",
            )),
        }
    }
}

#[async_trait]
impl DidWallet for AskarWallet {
    async fn create_and_store_my_did(
        &self,
        seed: Option<&str>,
        _did_method_name: Option<&str>,
    ) -> VcxCoreResult<DidData> {
        let mut tx = self.backend.transaction(self.profile.clone()).await?;

        let fix_seed = match seed {
            Some(val) => val,
            None => "",
        };

        let (did, local_key) = self
            .insert_key(
                &mut tx,
                KeyAlg::Ed25519,
                fix_seed.as_bytes(),
                RngMethod::RandomDet,
            )
            .await?;

        let verkey = self.local_key_to_bs58_pubkey(&local_key)?;

        self.insert_did(&mut tx, &did, &did, &verkey, None).await?;

        tx.commit().await?;

        Ok(DidData { did, verkey })
    }

    async fn did_key(&self, did: &str) -> VcxCoreResult<String> {
        let mut session = self.backend.session(self.profile.clone()).await?;

        let data = self.find_did(&mut session, did).await?;

        if let Some(_) = data {
            let local_key = self.fetch_local_key(&mut session, did).await?;
            let verkey = self.local_key_to_bs58_pubkey(&local_key)?;

            return Ok(verkey);
        }

        Err(AriesVcxCoreError::from_msg(
            AriesVcxCoreErrorKind::WalletRecordNotFound,
            "did not found",
        ))
    }

    async fn replace_did_key_start(&self, did: &str, seed: Option<&str>) -> VcxCoreResult<String> {
        let mut tx = self.backend.transaction(self.profile.clone()).await?;

        let data = self.find_did(&mut tx, did).await?;

        let fix_seed = match seed {
            Some(val) => val,
            None => "",
        };

        if let Some(did_data) = data {
            let key_name = &did_data.verkey[0..16];

            let (new_key_name, local_key) = self
                .insert_key(
                    &mut tx,
                    KeyAlg::Ed25519,
                    fix_seed.as_bytes(),
                    RngMethod::RandomDet,
                )
                .await?;

            let verkey = self.local_key_to_bs58_pubkey(&local_key)?;

            self.insert_did(&mut tx, &new_key_name, &did, &verkey, None)
                .await?;

            tx.remove(key_name, did).await?;
            tx.remove_key(key_name).await?;
            tx.commit().await?;
            return Ok(verkey);
        }

        Err(AriesVcxCoreError::from_msg(
            AriesVcxCoreErrorKind::InvalidDid,
            "did not found",
        ))
    }

    async fn replace_did_key_apply(&self, did: &str) -> VcxCoreResult<()> {
        Ok(())
    }

    async fn sign(&self, key_name: &str, msg: &[u8]) -> VcxCoreResult<Vec<u8>> {
        let mut session = self.backend.session(self.profile.clone()).await?;
        let res = session.fetch_key(key_name, false).await?;

        if let Some(key) = res {
            let local_key = key.load_local_key()?;
            let key_alg: SigType = local_key.algorithm().try_into()?;
            let res = local_key.sign_message(msg, Some(key_alg.into()))?;
            return Ok(res);
        }

        Err(AriesVcxCoreError::from_msg(
            AriesVcxCoreErrorKind::WalletUnexpected,
            "key not found",
        ))
    }

    async fn verify(&self, key_name: &str, msg: &[u8], signature: &[u8]) -> VcxCoreResult<bool> {
        let mut session = self.backend.session(self.profile.clone()).await?;

        if let Some(key) = session.fetch_key(key_name, false).await? {
            let local_key = key.load_local_key()?;
            let key_alg: SigType = local_key.algorithm().try_into()?;
            let res = local_key.verify_signature(msg, signature, Some(key_alg.into()))?;
            return Ok(res);
        }

        Ok(false)
    }

    async fn pack_message(
        &self,
        sender_vk: Option<String>,
        recipient_keys: Vec<Key>,
        msg: &[u8],
    ) -> VcxCoreResult<Vec<u8>> {
        if recipient_keys.is_empty() {
            return Err(AriesVcxCoreError::from_msg(
                AriesVcxCoreErrorKind::InvalidInput,
                "recipient keys should not be empty",
            ));
        }

        let enc_key = LocalKey::generate(KeyAlg::Chacha20(Chacha20Types::C20P), true)?;
        let packing = Packing::new();

        let base64_data = if let Some(sender_verkey_name) = sender_vk {
            let mut session = self.backend.session(self.profile.clone()).await?;

            let my_key = self
                .fetch_local_key(&mut session, &sender_verkey_name)
                .await?;
            packing.pack_authcrypt(&enc_key, recipient_keys, my_key)?
        } else {
            packing.pack_anoncrypt(&enc_key, recipient_keys)?
        };

        Ok(packing.pack_all(&base64_data, enc_key, msg)?)
    }

    async fn unpack_message(&self, msg: &[u8]) -> VcxCoreResult<UnpackedMessage> {
        let msg_jwe = serde_json::from_slice(msg)?;

        let packing = Packing::new();

        let mut session = self.backend.session(self.profile.clone()).await?;

        Ok(packing.unpack(msg_jwe, &mut session).await?)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        errors::error::AriesVcxCoreErrorKind,
        wallet2::{
            askar_wallet::{
                askar_utils::local_key_to_public_key_bytes, test_helper::create_test_wallet,
            },
            utils::bytes_to_bs58,
        },
    };

    #[tokio::test]
    async fn test_askar_should_sign_and_verify() {
        let wallet = create_test_wallet().await;

        let first_data = wallet
            .create_and_store_my_did("foo".into(), None)
            .await
            .unwrap();

        let second_data = wallet
            .create_and_store_my_did("bar".into(), None)
            .await
            .unwrap();

        let msg = "sign this message";
        let sig = wallet
            .sign(&first_data.verkey, msg.as_bytes())
            .await
            .unwrap();

        assert!(wallet
            .verify(&first_data.verkey, msg.as_bytes(), &sig)
            .await
            .unwrap());
        assert!(!wallet
            .verify(&second_data.verkey, msg.as_bytes(), &sig)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_askar_should_replace_did_key() {
        let wallet = create_test_wallet().await;

        let first_data = wallet
            .create_and_store_my_did("foo".into(), None)
            .await
            .unwrap();

        let res = wallet
            .replace_did_key(&first_data.did, "goo")
            .await
            .unwrap();

        let new_data = wallet.did_key(&first_data.did).await.unwrap();

        assert_eq!(res, new_data);
    }

    #[tokio::test]
    async fn test_askar_should_pack_and_unpack_authcrypt() {
        let wallet = create_test_wallet().await;

        let mut session = wallet
            .backend
            .session(wallet.profile.clone())
            .await
            .unwrap();

        let key_name = "sender_key";
        let sender_key = LocalKey::generate(KeyAlg::Ed25519, true).unwrap();
        session
            .insert_key(key_name, &sender_key, None, None, None)
            .await
            .unwrap();

        let msg = "send me";

        let recipient_key = LocalKey::generate(KeyAlg::Ed25519, true).unwrap();

        // Kid is base58 pubkey, we need to use it as a name in askar to be able to retrieve the
        // key. Somewhat awkward. Also does not align with `create_and_store_my_did` which
        // generates keys with names using only first 16 bytes of (pub)key
        let kid = bytes_to_bs58(&local_key_to_public_key_bytes(&recipient_key).unwrap());
        session
            .insert_key(&kid, &recipient_key, None, None, None)
            .await
            .unwrap();

        let rec_key = Key { pubkey_bs58: kid };

        let packed = wallet
            .pack_message(Some(key_name.into()), vec![rec_key], msg.as_bytes())
            .await
            .unwrap();

        let unpacked = wallet.unpack_message(&packed).await.unwrap();

        assert_eq!(msg, unpacked.message);
    }

    #[tokio::test]
    async fn test_askar_should_pack_and_unpack_anoncrypt() {
        let wallet = create_test_wallet().await;

        let mut session = wallet
            .backend
            .session(wallet.profile.clone())
            .await
            .unwrap();

        let msg = "send me";

        let recipient_key = LocalKey::generate(KeyAlg::Ed25519, true).unwrap();

        // Kid is base58 pubkey, we need to use it as a name in askar to be able to retrieve the
        // key. Somewhat awkward. Also does not align with `create_and_store_my_did` which
        // generates keys with names using only first 16 bytes of (pub)key
        let kid = bytes_to_bs58(&local_key_to_public_key_bytes(&recipient_key).unwrap());
        session
            .insert_key(&kid, &recipient_key, None, None, None)
            .await
            .unwrap();

        let rec_key = Key { pubkey_bs58: kid };

        let packed = wallet
            .pack_message(None, vec![rec_key], msg.as_bytes())
            .await
            .unwrap();

        let unpacked = wallet.unpack_message(&packed).await.unwrap();

        assert_eq!(msg, unpacked.message);
    }
}
