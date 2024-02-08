use aries_askar::{
    entry::EntryTag,
    kms::{KeyAlg, KeyEntry, LocalKey},
    PassKey, Session, Store, StoreKeyMethod,
};
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

use async_trait::async_trait;

mod askar_did_wallet;
mod askar_record_wallet;
mod askar_tags;
pub mod askar_utils;
mod crypto_box;
mod entry;
mod packing;
mod packing_types;
mod rng_method;
mod sig_type;

#[derive(Debug)]
pub struct AskarWallet {
    backend: Store,
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

// struct KeyRecord {
//     name: String,
//     category: String,
//     value: KeyValue,
//     tags: EntryTags
// }

// enum WalletRecord {
//     Record(Record),
//     Key(KeyRecord)
// }

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
        Ok(())
    }

    async fn close_wallet(&self) -> VcxCoreResult<()> {
        Ok(())
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
            // .map(|key_entry| {
            //     let local_key = key_entry.load_local_key()?;
            //     let name = key_entry.name();
            //     let tags = key_entry.tags_as_slice();
            //     // check for private key length!!!!
            //     let value = KeyValue {
            //         signkey: local_key_to_bs58_private_key(&local_key)?,
            //         verkey: local_key_to_bs58_public_key(&local_key)?,
            //     };
            //     let value = serde_json::to_string(&value)?;
            //     Ok(PartialRecord::builder()
            //         .name(name.into())
            //         .category(Some(INDY_KEY.into()))
            //         .value(Some(value))
            //         .tags(Some(tags.to_vec().into()))
            //         .build())
            // })
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

        Ok(Self { backend, profile })
    }

    pub async fn open(
        db_url: &str,
        key_method: Option<StoreKeyMethod>,
        pass_key: PassKey<'_>,
        profile: Option<String>,
    ) -> Result<Self, AriesVcxCoreError> {
        Ok(Self {
            backend: Store::open(db_url, key_method, pass_key, profile.clone()).await?,
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
