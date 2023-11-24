use async_trait::async_trait;
use vdrtools::{DidMethod, DidValue, KeyInfo, Locator, MyDidInfo};

use crate::{
    errors::error::{AriesVcxCoreError, VcxCoreResult},
    wallet2::{DidData, DidWallet},
};

#[async_trait]
impl DidWallet for crate::wallet::indy::IndySdkWallet {
    async fn create_and_store_my_did(
        &self,
        seed: &str,
        method_name: Option<&str>,
    ) -> VcxCoreResult<DidData> {
        let res = Locator::instance()
            .did_controller
            .create_and_store_my_did(
                self.wallet_handle,
                MyDidInfo {
                    method_name: method_name.map(|m| DidMethod(m.into())),
                    seed: Some(seed.into()),
                    ..MyDidInfo::default()
                },
            )
            .await
            .map_err::<AriesVcxCoreError, _>(From::from)?;

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

    async fn replace_did_key(&self, did: &str, seed: &str) -> VcxCoreResult<String> {
        let key_info = KeyInfo {
            seed: Some(seed.into()),
            ..Default::default()
        };

        let key = Locator::instance()
            .did_controller
            .replace_keys_start(self.wallet_handle, key_info, DidValue(did.into()))
            .await?;

        Locator::instance()
            .did_controller
            .replace_keys_apply(self.wallet_handle, DidValue(did.into()))
            .await?;

        Ok(key)
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
}

#[cfg(test)]
mod tests {
    use rand::{distributions::Alphanumeric, Rng};
    use test_utils::devsetup::create_indy_test_wallet_handle;

    use crate::{wallet::indy::IndySdkWallet, wallet2::DidWallet};

    #[tokio::test]
    #[ignore]
    async fn test_indy_should_sign_and_verify() {
        let wallet = IndySdkWallet::new(create_indy_test_wallet_handle().await);

        let seed: String = rand::thread_rng()
            .sample_iter(Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        let did_data = DidWallet::create_and_store_my_did(&wallet, &seed, None)
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

        let did_data = DidWallet::create_and_store_my_did(&wallet, &seed, None)
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
            .replace_did_key(&did_data.did, &new_seed)
            .await
            .unwrap();

        let new_key = wallet.did_key(&did_data.did).await.unwrap();
        assert_eq!(res, new_key);
    }
}
