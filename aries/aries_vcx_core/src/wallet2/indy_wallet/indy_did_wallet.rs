use async_trait::async_trait;
use vdrtools::{DidMethod, DidValue, KeyInfo, Locator, MyDidInfo};

use crate::{
    errors::error::{AriesVcxCoreError, AriesVcxCoreErrorKind, VcxCoreResult},
    wallet::{indy::IndySdkWallet, structs_io::UnpackMessageOutput},
    wallet2::{DidData, DidWallet, Key, UnpackedMessage},
};

#[async_trait]
impl DidWallet for IndySdkWallet {
    async fn create_and_store_my_did(
        &self,
        seed: Option<&str>,
        did_method_name: Option<&str>,
    ) -> VcxCoreResult<DidData> {
        let res = Locator::instance()
            .did_controller
            .create_and_store_my_did(
                self.wallet_handle,
                MyDidInfo {
                    method_name: did_method_name.map(|m| DidMethod(m.into())),
                    seed: seed.map(Into::into),
                    ..MyDidInfo::default()
                },
            )
            .await?;

        Ok(DidData {
            did: res.0,
            verkey: res.1,
        })
    }

    async fn did_key(&self, did: &str) -> VcxCoreResult<String> {
        Locator::instance()
            .did_controller
            .key_for_local_did(self.wallet_handle, DidValue(did.into()))
            .await
            .map_err(From::from)
    }

    async fn replace_did_key_start(&self, did: &str, seed: Option<&str>) -> VcxCoreResult<String> {
        let key_info = KeyInfo {
            seed: seed.map(Into::into),
            ..Default::default()
        };

        let key = Locator::instance()
            .did_controller
            .replace_keys_start(self.wallet_handle, key_info, DidValue(did.into()))
            .await?;

        Ok(key)
    }

    async fn replace_did_key_apply(&self, did: &str) -> VcxCoreResult<()> {
        Ok(Locator::instance()
            .did_controller
            .replace_keys_apply(self.wallet_handle, DidValue(did.into()))
            .await?)
    }

    async fn sign(&self, key: &str, msg: &[u8]) -> VcxCoreResult<Vec<u8>> {
        Locator::instance()
            .crypto_controller
            .crypto_sign(self.wallet_handle, key, msg)
            .await
            .map_err(From::from)
    }

    async fn verify(&self, key: &str, msg: &[u8], signature: &[u8]) -> VcxCoreResult<bool> {
        Locator::instance()
            .crypto_controller
            .crypto_verify(key, msg, signature)
            .await
            .map_err(From::from)
    }

    async fn pack_message(
        &self,
        sender_vk: Option<String>,
        receiver_keys: Vec<Key>,
        msg: &[u8],
    ) -> VcxCoreResult<Vec<u8>> {
        let receiver_keys_str = receiver_keys
            .into_iter()
            .map(|key| key.pubkey_bs58)
            .collect();

        Ok(Locator::instance()
            .crypto_controller
            .pack_msg(msg.into(), receiver_keys_str, sender_vk, self.wallet_handle)
            .await?)
    }

    async fn unpack_message(&self, msg: &[u8]) -> VcxCoreResult<UnpackedMessage> {
        let unpacked_bytes = Locator::instance()
            .crypto_controller
            .unpack_msg(serde_json::from_slice(msg)?, self.wallet_handle)
            .await?;

        let res: UnpackMessageOutput =
            serde_json::from_slice(&unpacked_bytes[..]).map_err(|err| {
                AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::ParsingError, err.to_string())
            })?;

        Ok(res.into())
    }
}

#[cfg(test)]
mod tests {

    use rand::{distributions::Alphanumeric, Rng};
    use test_utils::devsetup::create_indy_test_wallet_handle;

    use crate::{
        wallet::indy::IndySdkWallet,
        wallet2::{indy_wallet::test_helper::create_test_wallet, DidWallet, Key, SigType},
    };

    #[tokio::test]
    #[ignore]
    async fn test_indy_should_sign_and_verify() {
        let wallet = IndySdkWallet::new(create_indy_test_wallet_handle().await);

        let seed: String = rand::thread_rng()
            .sample_iter(Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        let did_data = DidWallet::create_and_store_my_did(&wallet, Some(&seed), None)
            .await
            .unwrap();

        let msg = "sign this".as_bytes();
        let sig = DidWallet::sign(&wallet, &did_data.verkey, msg)
            .await
            .unwrap();

        let res = DidWallet::verify(&wallet, &did_data.verkey, msg, &sig)
            .await
            .unwrap();
        assert!(res);
    }

    #[tokio::test]
    #[ignore]
    async fn test_indy_should_rotate_keys() {
        let wallet = IndySdkWallet::new(create_indy_test_wallet_handle().await);

        let seed: String = rand::thread_rng()
            .sample_iter(Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        let did_data = DidWallet::create_and_store_my_did(&wallet, Some(&seed), None)
            .await
            .unwrap();

        let key = wallet.did_key(&did_data.did).await.unwrap();

        assert_eq!(did_data.verkey, key);

        let new_seed: String = rand::thread_rng()
            .sample_iter(Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        let res = wallet
            .replace_did_key_start(&did_data.did, Some(&new_seed))
            .await
            .unwrap();

        wallet.replace_did_key_apply(&did_data.did).await.unwrap();

        let new_key = wallet.did_key(&did_data.did).await.unwrap();
        assert_eq!(res, new_key);
    }

    #[tokio::test]
    #[ignore]
    async fn test_indy_should_pack_and_unpack() {
        let wallet = IndySdkWallet::new(create_indy_test_wallet_handle().await);

        let sender_data = DidWallet::create_and_store_my_did(&wallet, None, None)
            .await
            .unwrap();

        let receiver_data = DidWallet::create_and_store_my_did(&wallet, None, None)
            .await
            .unwrap();

        let receiver_key = Key {
            pubkey_bs58: receiver_data.verkey,
        };
        let msg = "pack me";

        let packed = wallet
            .pack_message(Some(sender_data.verkey), vec![receiver_key], msg.as_bytes())
            .await
            .unwrap();

        let unpacked = wallet.unpack_message(&packed).await.unwrap();

        assert_eq!(msg, unpacked.message);
    }
}
