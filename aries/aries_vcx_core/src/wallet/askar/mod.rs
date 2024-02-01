use aries_askar::{
    entry::EntryTag,
    kms::{KeyAlg, KeyEntry, LocalKey},
    PassKey, Session, Store, StoreKeyMethod,
};

use crate::errors::error::{AriesVcxCoreError, AriesVcxCoreErrorKind, VcxCoreResult};

use self::{askar_utils::local_key_to_bs58_name, rng_method::RngMethod};

use super::{
    base_wallet::{did_data::DidData, BaseWallet},
    utils::key_from_base58,
};

pub mod askar_did_wallet;
pub mod askar_record_wallet;
mod askar_tags;
pub mod askar_utils;
mod crypto_box;
pub mod entry;
pub mod packing;
mod rng_method;
mod sig_type;

#[derive(Debug)]
pub struct AskarWallet {
    backend: Store,
    profile: Option<String>,
}

impl BaseWallet for AskarWallet {}

impl AskarWallet {
    const CURRENT_DID_CATEGORY: &str = "did";
    const TMP_DID_CATEGORY: &str = "tmp";

    pub async fn create(
        db_url: &str,
        key_method: StoreKeyMethod,
        pass_key: PassKey<'_>,
        recreate: bool,
        profile: Option<String>,
    ) -> Result<Self, AriesVcxCoreError> {
        let backend =
            Store::provision(db_url, key_method, pass_key, profile.clone(), recreate).await?;

        Ok(Self { backend, profile })
    }

    pub async fn open(
        db_url: &str,
        key_method: Option<StoreKeyMethod>,
        pass_key: PassKey<'_>,
        profile: Option<String>,
    ) -> Result<Self, AriesVcxCoreError> {
        let backend = Store::open(db_url, key_method, pass_key, profile.clone()).await?;

        Ok(Self { backend, profile })
    }

    async fn fetch_local_key(
        &self,
        session: &mut Session,
        key_name: &str,
    ) -> VcxCoreResult<LocalKey> {
        let key_entry = self.fetch_key_entry(session, &key_name).await?;

        Ok(key_entry.load_local_key()?)
    }

    async fn fetch_key_entry(
        &self,
        session: &mut Session,
        key_name: &str,
    ) -> Result<KeyEntry, AriesVcxCoreError> {
        session.fetch_key(key_name, false).await?.ok_or_else(|| {
            AriesVcxCoreError::from_msg(
                AriesVcxCoreErrorKind::WalletRecordNotFound,
                format!("no key with name '{}' found in wallet", key_name),
            )
        })
    }

    async fn insert_key(
        &self,
        session: &mut Session,
        alg: KeyAlg,
        seed: &[u8],
        rng_method: RngMethod,
    ) -> Result<(String, LocalKey), AriesVcxCoreError> {
        let key = LocalKey::from_seed(alg, seed, rng_method.into())?;

        let key_name = local_key_to_bs58_name(&key)?;

        session
            .insert_key(&key_name, &key, None, None, None)
            .await?;

        Ok((key_name, key))
    }

    async fn find_did(
        &self,
        session: &mut Session,
        did: &str,
        category: &str,
    ) -> VcxCoreResult<Option<DidData>> {
        let maybe_entry = session.fetch(category, did, false).await?;

        if let Some(entry) = maybe_entry {
            if let Some(val) = entry.value.as_opt_str() {
                let res: DidData = serde_json::from_str(val)?;
                return Ok(Some(res));
            }
        }

        Ok(None)
    }

    async fn find_current_did(
        &self,
        session: &mut Session,
        did: &str,
    ) -> VcxCoreResult<Option<DidData>> {
        self.find_did(session, did, AskarWallet::CURRENT_DID_CATEGORY)
            .await
    }

    async fn insert_did(
        &self,
        session: &mut Session,
        did: &str,
        category: &str,
        verkey: &str,
        tags: Option<&[EntryTag]>,
    ) -> VcxCoreResult<()> {
        if let Some(_) = session.fetch(&did, category, false).await? {
            return Err(AriesVcxCoreError::from_msg(
                AriesVcxCoreErrorKind::DuplicationDid,
                "did with given verkey already exists",
            ));
        }

        let did_data = DidData::new(did.into(), key_from_base58(verkey)?);

        let did_data = serde_json::to_string(&did_data)?;

        let res = session
            .insert(category, did, did_data.as_bytes(), tags, None)
            .await?;

        Ok(res)
    }

    async fn update_did(
        &self,
        session: &mut Session,
        did: &str,
        category: &str,
        verkey: &str,
        tags: Option<&[EntryTag]>,
    ) -> VcxCoreResult<()> {
        let did_data = DidData::new(did, key_from_base58(verkey)?);

        let did_data = serde_json::to_string(&did_data)?;
        session
            .replace(category, did, did_data.as_bytes(), tags, None)
            .await?;

        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use crate::wallet::base_wallet::BaseWallet;

    pub async fn dev_setup_askar_wallet() -> Box<dyn BaseWallet> {
        use aries_askar::StoreKeyMethod;
        use uuid::Uuid;

        use crate::wallet::askar::AskarWallet;

        Box::new(
            AskarWallet::create(
                "sqlite://:memory:",
                StoreKeyMethod::Unprotected,
                None.into(),
                true,
                Some(Uuid::new_v4().to_string()),
            )
            .await
            .unwrap(),
        )
    }
}
