use aries_askar::{
    crypto::alg::Chacha20Types,
    kms::{KeyAlg, LocalKey},
};
use async_trait::async_trait;
use public_key::Key;

use super::{
    askar_utils::local_key_to_bs58_public_key, packing::Packing, rng_method::RngMethod,
    sig_type::SigType, AskarWallet,
};
use crate::{
    errors::error::{AriesVcxCoreError, AriesVcxCoreErrorKind, VcxCoreResult},
    wallet::{
        base_wallet::{did_data::DidData, DidWallet},
        constants::{DID_CATEGORY, TMP_DID_CATEGORY},
        structs_io::UnpackMessageOutput,
        utils::{did_from_key, key_from_base58, seed_from_opt},
    },
};

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

        let verkey = local_key_to_bs58_public_key(&local_key)?;

        self.insert_did(&mut tx, &did, DID_CATEGORY, &verkey, None)
            .await?;

        tx.commit().await?;

        Ok(DidData::new(&did, key_from_base58(&verkey)?))
    }

    async fn key_for_did(&self, did: &str) -> VcxCoreResult<Key> {
        let mut session = self.backend.session(self.profile.clone()).await?;
        let data = self.find_current_did(&mut session, did).await?;

        if let Some(did_data) = data {
            return Ok(did_data.verkey().to_owned());
        }

        Err(AriesVcxCoreError::from_msg(
            AriesVcxCoreErrorKind::WalletRecordNotFound,
            format!("did not found in wallet: {}", did),
        ))
    }

    async fn replace_did_key_start(&self, did: &str, seed: Option<&str>) -> VcxCoreResult<Key> {
        let mut tx = self.backend.transaction(self.profile.clone()).await?;

        let data = self.find_current_did(&mut tx, did).await?;

        if data.is_some() {
            let (new_key_name, local_key) = self
                .insert_key(
                    &mut tx,
                    KeyAlg::Ed25519,
                    seed_from_opt(seed).as_bytes(),
                    RngMethod::RandomDet,
                )
                .await?;

            let verkey = local_key_to_bs58_public_key(&local_key)?;

            self.insert_did(&mut tx, did, TMP_DID_CATEGORY, &verkey, None)
                .await?;

            tx.commit().await?;

            return key_from_base58(&new_key_name);
        }

        Err(AriesVcxCoreError::from_msg(
            AriesVcxCoreErrorKind::WalletRecordNotFound,
            format!("did not found in wallet: {}", did),
        ))
    }

    async fn replace_did_key_apply(&self, did: &str) -> VcxCoreResult<()> {
        let mut tx = self.backend.transaction(self.profile.clone()).await?;

        let tmp_record = self.find_did(&mut tx, did, TMP_DID_CATEGORY).await?;

        if let Some(did_data) = tmp_record {
            let verkey_did = did_data.did_from_verkey();
            tx.remove(TMP_DID_CATEGORY, did).await?;
            tx.remove_key(&verkey_did).await?;
            self.update_did(&mut tx, did, DID_CATEGORY, &verkey_did, None)
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

    async fn sign(&self, key: &Key, msg: &[u8]) -> VcxCoreResult<Vec<u8>> {
        let mut session = self.backend.session(self.profile.clone()).await?;
        let res = session
            .fetch_key(&did_from_key(key.to_owned()), false)
            .await?;

        if let Some(key) = res {
            let local_key = key.load_local_key()?;
            let key_alg = SigType::try_from_key_alg(local_key.algorithm())?;
            return Ok(local_key.sign_message(msg, Some(key_alg.into()))?);
        }

        Err(AriesVcxCoreError::from_msg(
            AriesVcxCoreErrorKind::WalletError,
            "key not found",
        ))
    }

    async fn verify(&self, key: &Key, msg: &[u8], signature: &[u8]) -> VcxCoreResult<bool> {
        let mut session = self.backend.session(self.profile.clone()).await?;

        if let Some(key) = session
            .fetch_key(&did_from_key(key.to_owned()), false)
            .await?
        {
            let local_key = key.load_local_key()?;
            let key_alg = SigType::try_from_key_alg(local_key.algorithm())?;
            return Ok(local_key.verify_signature(msg, signature, Some(key_alg.into()))?);
        }

        Ok(false)
    }

    async fn pack_message(
        &self,
        sender_vk: Option<Key>,
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

        let base64_data = if let Some(sender_verkey) = sender_vk {
            let mut session = self.backend.session(self.profile.clone()).await?;

            let my_key = self
                .fetch_local_key(&mut session, &did_from_key(sender_verkey))
                .await?;
            packing.pack_authcrypt(&enc_key, recipient_keys, my_key)?
        } else {
            packing.pack_anoncrypt(&enc_key, recipient_keys)?
        };

        Ok(packing.pack_all(base64_data, enc_key, msg)?)
    }

    async fn unpack_message(&self, msg: &[u8]) -> VcxCoreResult<UnpackMessageOutput> {
        let msg_jwe = serde_json::from_slice(msg)?;

        let packing = Packing::new();

        let mut session = self.backend.session(self.profile.clone()).await?;

        Ok(packing.unpack(msg_jwe, &mut session).await?)
    }
}