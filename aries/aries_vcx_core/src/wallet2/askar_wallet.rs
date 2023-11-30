use aries_askar::{
    entry::{Entry, EntryTag, TagFilter},
    kms::{KeyAlg, KeyEntry, LocalKey, SecretBytes},
    PassKey, Session, Store, StoreKeyMethod,
};
use async_trait::async_trait;
use futures::stream::BoxStream;
use serde::{Deserialize, Serialize};

use crate::errors::error::{AriesVcxCoreError, AriesVcxCoreErrorKind, VcxCoreResult};

use super::{DidWallet, RecordWallet, SigType, Wallet};

#[derive(Clone)]
pub enum RngMethod {
    Bls,
    RandomDet,
}

impl From<RngMethod> for Option<&str> {
    fn from(value: RngMethod) -> Self {
        match value {
            RngMethod::RandomDet => None,
            RngMethod::Bls => Some("bls_keygen"),
        }
    }
}

pub struct DidEntry {
    category: String,
    name: String,
    value: DidData,
    tags: Vec<EntryTag>,
}

#[derive(Debug)]
pub struct AskarWallet {
    pub backend: Store,
    profile: Option<String>,
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
        let backend = Store::open(db_url, key_method, pass_key, profile.clone()).await?;

        Ok(Self { backend, profile })
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

    async fn rotate_key(&self, did: &str, new_key_name: &str) -> VcxCoreResult<()> {
        let mut session = self.backend.session(self.profile.clone()).await?;

        let entries = session.fetch_all(Some(&did), None, None, false).await?;

        let mut data: Option<DidEntry> = None;
        for entry in entries.iter() {
            if let Some(val) = entry.value.as_opt_str() {

                let res: DidData = serde_json::from_str(val)?;
                if res.current {
                    data = Some(DidEntry { category: entry.category.clone(), name: entry.name.clone(), value: res, tags: entry.tags.clone() });
                }
            }
        }

        if let Some(mut did_entry) = data {
            // insert new did
            let key_entry = self.fetch_key_entry(&mut session, &new_key_name).await?;

            let local_key = key_entry.load_local_key()?;
            let verkey = bs58::encode(local_key.to_public_bytes()?).into_string();

            if let Some(_) = session.fetch(&did, &new_key_name, false).await? {
                return  Err(AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::DuplicationDid, "did with given verkey already exists"));
            }

            let did_data = DidData{ did: did.to_string(), verkey, current: true};
            let did_data = serde_json::to_string(&did_data)?;

            let res = session
            .insert(
                &did,
                &new_key_name,
                did_data.as_bytes(),
                Some(&did_entry.tags),
                None
            )
            .await?;

            // insert new did end

            did_entry.value.current = false;
            let did_entry_data = serde_json::to_string(&did_entry.value)?;

            let rs = session.replace(&did_entry.category, &did_entry.name, did_entry_data.as_bytes(), Some(&did_entry.tags), None).await?;

            // Ok(did)
        }

        Ok(())
    }

}

#[derive(Default, Clone)]
pub struct Record {
    pub category: String,
    pub name: String,
    pub value: SecretBytes,
    pub tags: Option<Vec<EntryTag>>,
    pub expiry_ms: Option<i64>,
}

impl Record {
    pub fn set_name(mut self, new_name: &str) -> Self{
        self.name = new_name.to_owned();
        self
    }

    pub fn set_category(mut self, new_category: &str) -> Self{
        self.category = new_category.to_owned();
        self
    }

    pub fn set_value(mut self, new_value: &SecretBytes) -> Self {
        self.value = new_value.to_owned();
        self
    }

    pub fn set_tags(mut self, new_tags: Vec<EntryTag>) -> Self {
        self.tags = Some(new_tags);
        self
    }

    pub fn set_expiry_ms(mut self, new_expiry_ms: i64) -> Self {
        self.expiry_ms = Some(new_expiry_ms);
        self
    }
}

#[derive(Default)]
pub struct RecordId {
    name: String,
    category: String,
    for_update: bool,
}

impl RecordId {
    pub fn set_name(mut self, new_name: &str) -> Self {
        self.name = new_name.to_string();
        self
    }

    pub fn set_category(mut self, new_category: &str) -> Self {
        self.category = new_category.to_string();
        self
    }

    pub fn set_for_update(mut self, new_for_update: bool) -> Self {
        self.for_update = new_for_update;
        self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DidData {
    did: String,
    verkey: String,
    current: bool
}

#[derive(Clone)]
pub struct DidAttrs {
    key_name: String,
    // category: String,
    tags: Option<Vec<EntryTag>>,
    // expiry_ms: Option<i64>,
}

pub struct FindDidKeyAttrs {
    did: String,
    tags: Option<TagFilter>
}

#[derive(Clone)]
pub struct KeyAttrs {
    name: String,
    alg: KeyAlg,
    seed: String,
    rng_method: RngMethod,
    metadata: Option<String>,
    tags: Option<Vec<EntryTag>>,
    expiry_ms: Option<i64>,
}

#[async_trait]
impl Wallet for AskarWallet {}

#[async_trait]
impl DidWallet for AskarWallet {
    type DidAttrs = DidAttrs;
    type CreatedDid = String;
    type DidKey = Option<KeyEntry>;
    type KeyAttrs = KeyAttrs;
    type FindDidKeyAttrs = FindDidKeyAttrs;

    async fn create_key(&self, key_attrs: Self::KeyAttrs) -> Result<(), AriesVcxCoreError> {
        let mut session = self.backend.session(self.profile.clone()).await?;

        let key = LocalKey::from_seed(
            key_attrs.alg,
            key_attrs.seed.as_bytes(),
            key_attrs.rng_method.into(),
        )?;
        Ok(session
            .insert_key(
                &key_attrs.name,
                &key,
                key_attrs.metadata.as_deref(),
                key_attrs.tags.as_deref(),
                key_attrs.expiry_ms,
            )
            .await?)
    }

    // async fn insert_did(&self, session: &mut Session, key_name: &str, did: &str, ) -> VcxCoreResult<Self::CreatedDid> {

    // }

    async fn create_did(&self, attrs: Self::DidAttrs) -> VcxCoreResult<Self::CreatedDid> {
        let mut session = self.backend.session(self.profile.clone()).await?;

        let key_entry = self.fetch_key_entry(&mut session, &attrs.key_name).await?;

        let local_key = key_entry.load_local_key()?;

        let verkey = bs58::encode(local_key.to_public_bytes()?).into_string();

        let did = verkey[0..16].to_string();

        if let Some(_) = session.fetch(&did, &attrs.key_name, false).await? {
            return  Err(AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::DuplicationDid, "did with given verkey already exists"));
        }

        let did_data = DidData{ did: did.clone(), verkey, current: true};
        let did_data = serde_json::to_string(&did_data)?;

        let res = session
        .insert(
            &did,
            &attrs.key_name,
            did_data.as_bytes(),
            attrs.tags.as_deref(),
            None,
        )
        .await?;

        Ok(did)
    }

    async fn did_key(&self, attrs: Self::FindDidKeyAttrs) -> VcxCoreResult<Self::DidKey> {
        let mut session = self.backend.session(self.profile.clone()).await?;

        let entries = session.fetch_all(Some(&attrs.did), attrs.tags, None, false).await?;

        let mut data: Option<DidEntry> = None;
        for entry in entries.iter() {
            if let Some(val) = entry.value.as_opt_str() {

                let res: DidData = serde_json::from_str(val)?;
                if res.current {
                    data = Some(DidEntry { category: entry.category.clone(), name: entry.name.clone(), value: res, tags: entry.tags.clone() });
                }
            }
        }

        if let Some(entry) = data {
            let key_entry = self.fetch_key_entry(&mut session, &entry.name).await?;
            return Ok(Some(key_entry));
        }

        Ok(None)
    }

    async fn replace_did_key(&self, did: &str, new_key_name: &str) -> VcxCoreResult<Self::DidKey> {
        let mut session = self.backend.session(self.profile.clone()).await?;

        let dids = session.fetch_all(Some(&did), None, None, false).await?;

        // let found_did = dids.iter().find(|did| {
        //     let val: DidData = serde_json::from_str(did.value);
        //     return false;
        // }).collect();



        todo!("Not yet implemented");
    }

    async fn sign(
        &self,
        verkey_name: &str,
        msg: &[u8],
        sig_type: SigType,
    ) -> VcxCoreResult<Vec<u8>> {
        let mut session = self.backend.session(self.profile.clone()).await?;
        let res = session.fetch_key(verkey_name, false).await?;

        if let Some(key) = res {
            let local_key = key.load_local_key()?;
            let res = local_key.sign_message(msg, Some(sig_type.into()))?;
            return Ok(res);
        }

        Ok(vec![])
    }

    async fn verify(
        &self,
        verkey_name: &str,
        msg: &[u8],
        signature: &[u8],
        sig_type: SigType,
    ) -> VcxCoreResult<bool> {
        let mut session = self.backend.session(self.profile.clone()).await?;

        if let Some(key) = session.fetch_key(verkey_name, false).await? {
            let local_key = key.load_local_key()?;
            let res = local_key.verify_signature(msg, signature, Some(sig_type.into()))?;
            return Ok(res);
        }

        Ok(false)
    }
}

pub struct SearchFilter {
    category: Option<String>,
    tag_filter: Option<TagFilter>,
    offset: Option<i64>,
    limit: Option<i64>,
}

#[async_trait]
impl RecordWallet for AskarWallet {
    type Record = Record;
    type RecordId = RecordId;
    type FoundRecord = Entry;
    type SearchFilter = SearchFilter;

    async fn add_record(&self, record: Self::Record) -> VcxCoreResult<()> {
        let mut session = self.backend.session(self.profile.clone()).await?;

        Ok(session
            .insert(
                &record.category,
                &record.name,
                &record.value,
                record.tags.as_deref(),
                record.expiry_ms,
            )
            .await?)
    }

    async fn get_record(&self, id: &Self::RecordId) -> VcxCoreResult<Self::FoundRecord> {
        let mut session = self.backend.session(self.profile.clone()).await?;

        session
            .fetch(&id.category, &id.name, id.for_update)
            .await?
            .ok_or_else(|| {
                AriesVcxCoreError::from_msg(
                    AriesVcxCoreErrorKind::WalletRecordNotFound,
                    "not found",
                )
            })
    }

    async fn update_record(&self, record: Self::Record) -> VcxCoreResult<()> {
        let mut session = self.backend.session(self.profile.clone()).await?;
        Ok(session.replace(&record.category, &record.name, &record.value, record.tags.as_deref(), record.expiry_ms).await?)
    }

    async fn delete_record(&self, id: &Self::RecordId) -> VcxCoreResult<()> {
        let mut session = self.backend.session(self.profile.clone()).await?;
        Ok(session.remove(&id.category, &id.name).await?)
    }

    async fn search_record(
        &self,
        filter: Self::SearchFilter,
    ) -> VcxCoreResult<BoxStream<VcxCoreResult<Self::FoundRecord>>> {
        let mut res = self
            .backend
            .scan(
                self.profile.clone(),
                filter.category,
                filter.tag_filter,
                filter.offset,
                filter.limit,
            )
            .await?;
        let mut all: Vec<VcxCoreResult<Self::FoundRecord>> = vec![];
        let rs = res
            .fetch_next()
            .await
            .map_err(|err| AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::IOError, err))?;
        if let Some(found) = rs {
            all = found.into_iter().map(|entry| Ok(entry)).collect();
        }
        Ok(Box::pin(futures::stream::iter(all)))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use futures::StreamExt;
    use uuid::Uuid;

    use crate::wallet2::askar_wallet::AskarWallet;

    async fn create_test_wallet() -> AskarWallet {
        AskarWallet::create(
            "sqlite://:memory:",
            StoreKeyMethod::Unprotected,
            None.into(),
            true,
            Some(Uuid::new_v4().to_string()),
            )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn test_askar_should_delete_record() {
        let wallet = create_test_wallet().await;

        let name1 = "delete-me-1".to_string();
        let category1 = "my".to_string();
        let value1 = "ff".to_string();

        let record1 = Record::default()
            .set_name(&name1)
            .set_category(&category1)
            .set_value(&value1.into());

        wallet.add_record(record1).await.unwrap();

        let name2 = "do-not-delete-me".to_string();
        let category2 = "my".to_string();
        let value2 = "gg".to_string();

        let record2 = Record::default()
            .set_name(&name2)
            .set_category(&category2)
            .set_value(&value2.into());

        wallet.add_record(record2).await.unwrap();

        let record1_id = RecordId::default().set_name(&name1).set_category(&category1);
        wallet.delete_record(&record1_id).await.unwrap();
        let err = wallet.get_record(&record1_id).await.unwrap_err();
        assert_eq!(AriesVcxCoreErrorKind::WalletRecordNotFound, err.kind());

        let record2_id = RecordId::default().set_name(&name2).set_category(&category2);
        wallet.get_record(&record2_id).await.unwrap();
    }

    #[tokio::test]
    async fn test_askar_should_get_record() {
        let wallet = create_test_wallet().await;

        let name1 = "foobar".to_string();
        let category1 = "my".to_string();
        let value1 = "ff".to_string();

        let record1 = Record::default()
            .set_name(&name1)
            .set_category(&category1)
            .set_value(&value1.clone().into());

        wallet.add_record(record1).await.unwrap();

        let name2 = "foofar".to_string();
        let category2 = "your".to_string();
        let value2 = "gg".to_string();

        let record2 = Record::default()
            .set_name(&name2)
            .set_category(&category2)
            .set_value(&value2.clone().into());

        wallet.add_record(record2).await.unwrap();

        let record1_id = RecordId::default().set_name(&name1).set_category(&category1);
        let found1 = wallet.get_record(&record1_id).await.unwrap();
        assert_eq!(value1, secret_bytes_to_string(&found1.value));

        let record3_id = RecordId::default().set_name(&name1).set_category(&category2);
        let err1 = wallet.get_record(&record3_id).await.unwrap_err();

        assert_eq!(AriesVcxCoreErrorKind::WalletRecordNotFound, err1.kind())
    }

    #[tokio::test]
    async fn test_askar_should_update_record() {
        let wallet = create_test_wallet().await;

        let name = "test-name".to_string();
        let category = "test-category".to_string();
        let value = "test-value".to_string();

        let record = Record::default()
            .set_name(&name)
            .set_category(&category)
            .set_value(&value.clone().into());

        wallet.add_record(record.clone()).await.unwrap();

        let updated_value = "updated-test-value".to_string();
        let record = record.set_value(&updated_value.clone().into());

        wallet.update_record(record.clone()).await.unwrap();

        let record_id = RecordId::default().set_name(&name).set_category(&category);
        let found = wallet.get_record(&record_id).await.unwrap();
        assert_eq!(updated_value, secret_bytes_to_string(&found.value));

        let other_category = "other-test-category".to_string();
        let record = record.set_category(&other_category);
        let err = wallet.update_record(record.clone()).await.unwrap_err();

        assert_eq!(AriesVcxCoreErrorKind::WalletRecordNotFound, err.kind());
    }

    fn secret_bytes_to_string(sb: &SecretBytes) -> String {
        std::str::from_utf8(&sb.to_vec()).unwrap().to_string()
    }

    #[tokio::test]
    async fn test_askar_should_find_records() {
        let wallet = create_test_wallet().await;

        let record1 = Record {
            category: "my".into(),
            name: "foofar".into(),
            tags: None,
            value: "ff".into(),
            expiry_ms: None,
        };
        wallet.add_record(record1).await.unwrap();

        let record2 = Record {
            category: "my".into(),
            name: "foobar".into(),
            tags: None,
            value: "fb".into(),
            expiry_ms: None,
        };
        wallet.add_record(record2).await.unwrap();

        let record3 = Record {
            category: "your".into(),
            name: "football".into(),
            tags: None,
            value: "fbl".into(),
            expiry_ms: None,
        };
        wallet.add_record(record3).await.unwrap();

        let filter = SearchFilter{ category: Some("my".into()), offset: None, tag_filter: None, limit: None};

        let mut res = wallet.search_record(filter).await.unwrap();

        let mut all = vec![];
        while let Some(item) = res.next().await {
            all.push(item.unwrap());
        }
        assert_eq!(2, all.len());
    }

    #[tokio::test]
    async fn test_askar_should_rotate_key() {
        let wallet = create_test_wallet().await;

        let first_key_name = "first".to_string();
        let first_key_attrs = KeyAttrs{
            name: first_key_name.clone(),
            alg: KeyAlg::Ed25519,
            seed: "foo".into(),
            rng_method: RngMethod::RandomDet,
            metadata: None,
            tags: None,
            expiry_ms: None
        };
        let first_key = wallet.create_key(first_key_attrs).await.unwrap();

        let second_key_name = "second".to_string();
        let second_key_attrs = KeyAttrs{
            name: second_key_name.clone(),
            alg: KeyAlg::Ed25519,
            seed: "bar".into(),
            rng_method: RngMethod::RandomDet,
            metadata: None,
            tags: None,
            expiry_ms: None
        };
        let second_key = wallet.create_key(second_key_attrs).await.unwrap();

        let did_attrs = DidAttrs {
            key_name: first_key_name,
            tags: None,
        };
        let did = wallet.create_did(did_attrs.clone()).await.unwrap();
        let rot = wallet.rotate_key(&did, &second_key_name).await.unwrap();

        let third_key_name = "third".to_string();
        let third_key_attrs = KeyAttrs{
            name: third_key_name.clone(),
            alg: KeyAlg::Ed25519,
            seed: "baz".into(),
            rng_method: RngMethod::RandomDet,
            metadata: None,
            tags: None,
            expiry_ms: None
        };
        let third_key = wallet.create_key(third_key_attrs).await.unwrap();

        let rot = wallet.rotate_key(&did, &third_key_name).await.unwrap();

        let did_key_attrs = FindDidKeyAttrs {did: did.clone(), tags: None};
        let res = wallet.did_key(did_key_attrs).await.unwrap().unwrap();
        assert_eq!(third_key_name, res.name());
    }


    #[tokio::test]
    async fn test_askar_should_not_create_key_repeatedly() {
        let wallet = create_test_wallet().await;

        let first_key_name = "first".to_string();
        let first_key_attrs = KeyAttrs{
            name: first_key_name.clone(),
            alg: KeyAlg::Ed25519,
            seed: "foo".into(),
            rng_method: RngMethod::RandomDet,
            metadata: None,
            tags: None,
            expiry_ms: None
        };
        let first_key = wallet.create_key(first_key_attrs.clone()).await.unwrap();
        let create_err = wallet.create_key(first_key_attrs).await.unwrap_err();

        assert_eq!(AriesVcxCoreErrorKind::DuplicationWalletRecord, create_err.kind());
    }
}
