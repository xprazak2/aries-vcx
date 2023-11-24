use aries_askar::{
    crypto::alg::{Chacha20Types, EcCurves},
    kms::{KeyAlg, LocalKey},
};
use async_trait::async_trait;

use super::{packing::Packing, AskarWallet, RngMethod};
use crate::{
    errors::error::{AriesVcxCoreError, AriesVcxCoreErrorKind, VcxCoreResult},
    wallet2::{utils::seed_from_opt, DidData, DidWallet, Key, UnpackedMessage},
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

        let (did, local_key) = self
            .insert_key(
                &mut tx,
                KeyAlg::Ed25519,
                seed_from_opt(seed).as_bytes(),
                RngMethod::RandomDet,
            )
            .await?;

        let verkey = self.local_key_to_bs58_pubkey(&local_key)?;

        self.insert_did(
            &mut tx,
            &did,
            AskarWallet::CURRENT_DID_CATEGORY,
            &verkey,
            None,
        )
        .await?;

        tx.commit().await?;

        Ok(DidData { did, verkey })
    }

    async fn did_key(&self, did: &str) -> VcxCoreResult<String> {
        let mut session = self.backend.session(self.profile.clone()).await?;
        let data = self.find_current_did(&mut session, did).await?;

        if let Some(did_data) = data {
            return Ok(did_data.verkey);
        }

        Err(AriesVcxCoreError::from_msg(
            AriesVcxCoreErrorKind::WalletRecordNotFound,
            "did not found",
        ))
    }

    async fn replace_did_key_start(&self, did: &str, seed: Option<&str>) -> VcxCoreResult<String> {
        let mut tx = self.backend.transaction(self.profile.clone()).await?;

        let data = self.find_current_did(&mut tx, did).await?;

        if let Some(_) = data {
            let (new_key_name, local_key) = self
                .insert_key(
                    &mut tx,
                    KeyAlg::Ed25519,
                    seed_from_opt(seed).as_bytes(),
                    RngMethod::RandomDet,
                )
                .await?;

            let verkey = self.local_key_to_bs58_pubkey(&local_key)?;

            self.insert_did(&mut tx, did, AskarWallet::TMP_DID_CATEGORY, &verkey, None)
                .await?;

            tx.commit().await?;

            return Ok(new_key_name);
        }

        Err(AriesVcxCoreError::from_msg(
            AriesVcxCoreErrorKind::WalletRecordNotFound,
            format!("did not found in wallet: {}", did),
        ))
    }

    async fn replace_did_key_apply(&self, did: &str) -> VcxCoreResult<()> {
        let mut tx = self.backend.transaction(self.profile.clone()).await?;

        let tmp_record = self
            .find_did(&mut tx, did, AskarWallet::TMP_DID_CATEGORY)
            .await?;

        if let Some(did_data) = tmp_record {
            tx.remove(AskarWallet::TMP_DID_CATEGORY, did).await?;
            tx.remove_key(&did_data.verkey[0..16]).await?;
            self.update_did(
                &mut tx,
                did,
                AskarWallet::CURRENT_DID_CATEGORY,
                &did_data.verkey,
                None,
            )
            .await?;
            tx.commit().await?;
            return Ok(());
        } else {
            return Err(AriesVcxCoreError::from_msg(
                AriesVcxCoreErrorKind::WalletRecordNotFound,
                "temporary did key not found in wallet",
            ));
        }
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
    use crate::wallet2::{
        askar_wallet::{
            askar_utils::local_key_to_public_key_bytes, test_helper::create_test_wallet,
        },
        utils::bytes_to_bs58,
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

        let new_key_name = wallet
            .replace_did_key_start(&first_data.did, Some("goo"))
            .await
            .unwrap();

        wallet.replace_did_key_apply(&first_data.did).await.unwrap();

        let new_verkey = wallet.did_key(&first_data.did).await.unwrap();

        assert_eq!(new_key_name, new_verkey[0..16]);
    }

    #[tokio::test]
    async fn test_askar_should_replace_did_key_repeatedly() {
        let wallet = create_test_wallet().await;

        let first_data = wallet
            .create_and_store_my_did("foo".into(), None)
            .await
            .unwrap();

        let new_key_name = wallet
            .replace_did_key_start(&first_data.did, Some("goo"))
            .await
            .unwrap();

        wallet.replace_did_key_apply(&first_data.did).await.unwrap();

        let new_verkey = wallet.did_key(&first_data.did).await.unwrap();

        assert_eq!(new_key_name, new_verkey[0..16]);

        let second_new_key_name = wallet
            .replace_did_key_start(&first_data.did, Some("koo"))
            .await
            .unwrap();

        wallet.replace_did_key_apply(&first_data.did).await.unwrap();

        let second_new_verkey = wallet.did_key(&first_data.did).await.unwrap();

        assert_eq!(second_new_key_name, second_new_verkey[0..16]);
    }

    #[tokio::test]
    async fn test_askar_should_replace_did_key_interleaved() {
        let wallet = create_test_wallet().await;

        let first_data = wallet
            .create_and_store_my_did("foo".into(), None)
            .await
            .unwrap();

        let second_data = wallet
            .create_and_store_my_did("boo".into(), None)
            .await
            .unwrap();

        let first_new_key_name = wallet
            .replace_did_key_start(&first_data.did, Some("goo"))
            .await
            .unwrap();

        let second_new_key_name = wallet
            .replace_did_key_start(&second_data.did, Some("moo"))
            .await
            .unwrap();

        wallet
            .replace_did_key_apply(&second_data.did)
            .await
            .unwrap();
        wallet.replace_did_key_apply(&first_data.did).await.unwrap();

        let first_new_verkey = wallet.did_key(&first_data.did).await.unwrap();
        let second_new_verkey = wallet.did_key(&second_data.did).await.unwrap();

        assert_eq!(first_new_key_name, first_new_verkey[0..16]);
        assert_eq!(second_new_key_name, second_new_verkey[0..16]);
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
