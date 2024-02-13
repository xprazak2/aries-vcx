use std::{mem, ops::Deref};

use aries_askar::{
    entry::EntryTag,
    kms::{KeyAlg, KeyEntry, LocalKey},
    PassKey, Session, Store, StoreKeyMethod,
};
use indy_api_types::domain::wallet::default_key_derivation_method;
use serde::{Deserialize, Serialize};

use self::{
    askar_utils::{
        key_from_base58, local_key_to_bs58_name, local_key_to_bs58_private_key,
        local_key_to_bs58_public_key, value_from_entry,
    },
    rng_method::RngMethod,
};
use super::{
    base_wallet::{
        did_data::DidData,
        record::{AllRecords, PartialRecord, Record},
        BaseWallet,
    },
    constants::{DID_CATEGORY, INDY_KEY},
    utils::did_from_key,
};
use crate::errors::error::{AriesVcxCoreError, AriesVcxCoreErrorKind, VcxCoreResult};

use crate::wallet::askar::export::export;
use async_trait::async_trait;

mod askar_did_wallet;
mod askar_record_wallet;
mod askar_tags;
pub mod askar_utils;
mod chacha20poly1305ietf;
mod crypto_box;
mod entry;
mod export;
mod packing;
mod packing_types;
mod rng_method;
mod sig_type;

#[derive(Debug)]
pub struct BackendStore(Option<Store>);

impl BackendStore {
    async fn session(&self, profile: Option<String>) -> VcxCoreResult<Session> {
        match &self.0 {
            Some(backend) => Ok(backend.session(profile).await?),
            None => Err(AriesVcxCoreError::from_msg(
                AriesVcxCoreErrorKind::WalletAccessFailed,
                "wallet is closed",
            )),
        }
    }

    async fn transaction(&self, profile: Option<String>) -> VcxCoreResult<Session> {
        match &self.0 {
            Some(backend) => Ok(backend.transaction(profile).await?),
            None => Err(AriesVcxCoreError::from_msg(
                AriesVcxCoreErrorKind::WalletAccessFailed,
                "wallet is closed",
            )),
        }
    }

    async fn close(self) -> VcxCoreResult<()> {
        match self.0 {
            Some(backend) => Ok(backend.close().await?),
            None => Err(AriesVcxCoreError::from_msg(
                AriesVcxCoreErrorKind::WalletAccessFailed,
                "wallet is closed",
            )),
        }
    }

    fn opened(backend: Store) -> Self {
        Self(Some(backend))
    }

    fn closed() -> Self {
        Self(None)
    }
}

#[derive(Debug)]
pub struct AskarWallet {
    backend: BackendStore,
    profile: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct KeyValue {
    verkey: String,
    signkey: String,
}

impl KeyValue {
    pub fn new(signkey: String, verkey: String) -> Self {
        Self { signkey, verkey }
    }
}

pub struct AllAskarRecords {
    iterator: std::vec::IntoIter<PartialRecord>,
    total_count: Option<usize>,
}

#[async_trait]
impl AllRecords for AllAskarRecords {
    fn total_count(&self) -> VcxCoreResult<Option<usize>> {
        Ok(self.total_count)
    }

    async fn next(&mut self) -> VcxCoreResult<Option<PartialRecord>> {
        Ok(self.iterator.next())
    }
}

#[async_trait]
impl BaseWallet for AskarWallet {
    async fn export_wallet(&self, path: &str, backup_key: &str) -> VcxCoreResult<()> {
        export::export(path, backup_key, default_key_derivation_method()).await?;
        Ok(())
    }

    async fn close_wallet(&mut self) -> VcxCoreResult<()> {
        let orig = mem::replace(&mut self.backend, BackendStore::closed());
        orig.close().await
    }

    async fn all(&self) -> VcxCoreResult<Box<dyn AllRecords + Send>> {
        let mut session = self.backend.session(self.profile.clone()).await?;

        let recs = session.fetch_all(None, None, None, false).await?;

        let mut recs = recs
            .into_iter()
            .map(PartialRecord::from_askar_entry)
            .collect::<Result<Vec<_>, _>>()?;

        let keys = session
            .fetch_all_keys(None, None, None, None, false)
            .await?;

        let mut local_keys = keys
            .into_iter()
            .map(PartialRecord::from_askar_key_entry)
            .collect::<Result<Vec<_>, _>>()?;

        recs.append(&mut local_keys);

        let total_count = recs.len();

        Ok(Box::new(AllAskarRecords {
            iterator: recs.into_iter(),
            total_count: Some(total_count),
        }))
    }
}

impl AskarWallet {
    pub async fn create(
        db_url: &str,
        key_method: StoreKeyMethod,
        pass_key: PassKey<'_>,
        recreate: bool,
        profile: Option<String>,
    ) -> Result<Self, AriesVcxCoreError> {
        let backend =
            Store::provision(db_url, key_method, pass_key, profile.clone(), recreate).await?;

        Ok(Self {
            backend: BackendStore(Some(backend)),
            profile,
        })
    }

    pub async fn open(
        db_url: &str,
        key_method: Option<StoreKeyMethod>,
        pass_key: PassKey<'_>,
        profile: Option<String>,
    ) -> Result<Self, AriesVcxCoreError> {
        Ok(Self {
            backend: BackendStore(Some(
                Store::open(db_url, key_method, pass_key, profile.clone()).await?,
            )),
            profile,
        })
    }

    async fn fetch_local_key(
        &self,
        session: &mut Session,
        key_name: &str,
    ) -> VcxCoreResult<LocalKey> {
        Ok(self
            .fetch_key_entry(session, key_name)
            .await?
            .load_local_key()?)
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
        if let Some(entry) = session.fetch(category, did, false).await? {
            if let Some(val) = entry.value.as_opt_str() {
                return Ok(Some(serde_json::from_str(val)?));
            }
        }

        Ok(None)
    }

    async fn find_current_did(
        &self,
        session: &mut Session,
        did: &str,
    ) -> VcxCoreResult<Option<DidData>> {
        self.find_did(session, did, DID_CATEGORY).await
    }

    async fn insert_did(
        &self,
        session: &mut Session,
        did: &str,
        category: &str,
        verkey: &str,
        tags: Option<&[EntryTag]>,
    ) -> VcxCoreResult<()> {
        if (session.fetch(did, category, false).await?).is_some() {
            Err(AriesVcxCoreError::from_msg(
                AriesVcxCoreErrorKind::DuplicationDid,
                "did with given verkey already exists",
            ))
        } else {
            Ok(session
                .insert(
                    category,
                    did,
                    serde_json::to_string(&DidData::new(did, key_from_base58(verkey)?))?.as_bytes(),
                    tags,
                    None,
                )
                .await?)
        }
    }

    async fn update_did(
        &self,
        session: &mut Session,
        did: &str,
        category: &str,
        verkey: &str,
        tags: Option<&[EntryTag]>,
    ) -> VcxCoreResult<()> {
        session
            .replace(
                category,
                did,
                serde_json::to_string(&DidData::new(did, key_from_base58(verkey)?))?.as_bytes(),
                tags,
                None,
            )
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
