use std::collections::HashMap;

use aries_askar::entry::{Entry, EntryKind, TagFilter};
use async_trait::async_trait;
use derive_builder::Builder;
#[cfg(feature = "vdrtools_wallet")]
use indy_api_types::domain::wallet::Record as IndyRecord;
use public_key::Key;
use serde::{Deserialize, Serialize};

use self::{entry_tag::EntryTags, utils::did_from_key};

use crate::{
    errors::error::{AriesVcxCoreError, AriesVcxCoreErrorKind, VcxCoreResult},
    wallet::structs_io::UnpackMessageOutput,
};

#[cfg(feature = "vdrtools_wallet")]
pub mod indy_wallet;

#[cfg(feature = "askar_wallet")]
pub mod askar_wallet;

pub mod crypto_box;
pub mod entry_tag;
pub mod utils;

#[derive(Clone, Default)]
pub enum RngMethod {
    #[default]
    RandomDet,
    Bls,
}

impl From<RngMethod> for Option<&str> {
    fn from(value: RngMethod) -> Self {
        match value {
            RngMethod::RandomDet => None,
            RngMethod::Bls => Some("bls_keygen"),
        }
    }
}

#[derive(Debug, Default, Clone, Builder)]
pub struct Record {
    category: String,
    name: String,
    value: String,
    #[builder(default)]
    tags: EntryTags,
}

#[cfg(feature = "vdrtools_wallet")]
impl From<IndyRecord> for Record {
    fn from(ir: IndyRecord) -> Self {
        Self {
            name: ir.id,
            category: ir.type_,
            value: ir.value,
            tags: ir.tags.into(),
        }
    }
}

#[cfg(feature = "vdrtools_wallet")]
impl From<Record> for IndyRecord {
    fn from(record: Record) -> Self {
        let tags = record
            .tags
            .into_iter()
            .fold(HashMap::new(), |mut memo, item| {
                let (key, value) = item.into();
                memo.insert(key, value);
                memo
            });
        Self {
            id: record.name,
            type_: record.category,
            value: record.value,
            tags,
        }
    }
}

#[cfg(feature = "askar_wallet")]
impl TryFrom<Entry> for Record {
    type Error = AriesVcxCoreError;

    fn try_from(entry: Entry) -> Result<Self, Self::Error> {
        let string_value = std::str::from_utf8(&entry.value)
            .map_err(|err| AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::WalletError, err))?;

        Ok(Self {
            category: entry.category,
            name: entry.name,
            value: string_value.into(),
            tags: entry.tags.into_iter().map(From::from).collect(),
        })
    }
}

#[cfg(feature = "askar_wallet")]
impl From<Record> for Entry {
    fn from(record: Record) -> Self {
        Self {
            category: record.category,
            name: record.name,
            value: record.value.into(),
            kind: EntryKind::Item,
            tags: record.tags.into_iter().map(From::from).collect(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DidData {
    did: String,
    verkey: Key,
}

impl DidData {
    pub fn did_from_verkey(&self) -> String {
        did_from_key(self.verkey.clone())
    }
}

pub enum SearchFilter {
    TagFilter(TagFilter),
    JsonFilter(String),
}

#[async_trait]
pub trait BaseWallet2: RecordWallet + DidWallet {}

#[async_trait]
pub trait DidWallet {
    async fn create_and_store_my_did(
        &self,
        seed: Option<&str>,
        method_name: Option<&str>,
    ) -> VcxCoreResult<DidData>;

    async fn did_key(&self, name: &str) -> VcxCoreResult<Key>;

    async fn replace_did_key_start(&self, did: &str, seed: Option<&str>) -> VcxCoreResult<Key>;

    async fn replace_did_key_apply(&self, did: &str) -> VcxCoreResult<()>;

    async fn sign(&self, key: &Key, msg: &[u8]) -> VcxCoreResult<Vec<u8>>;

    async fn verify(&self, key: &Key, msg: &[u8], signature: &[u8]) -> VcxCoreResult<bool>;

    async fn pack_message(
        &self,
        sender_vk: Option<Key>,
        receiver_keys: Vec<Key>,
        msg: &[u8],
    ) -> VcxCoreResult<Vec<u8>>;

    async fn unpack_message(&self, msg: &[u8]) -> VcxCoreResult<UnpackMessageOutput>;
}

#[async_trait]
pub trait RecordWallet {
    async fn add_record(&self, record: Record) -> VcxCoreResult<()>;

    async fn get_record(&self, name: &str, category: &str) -> VcxCoreResult<Record>;

    async fn update_record_tags(
        &self,
        name: &str,
        category: &str,
        new_tags: EntryTags,
    ) -> VcxCoreResult<()>;

    async fn update_record_value(
        &self,
        name: &str,
        category: &str,
        new_value: &str,
    ) -> VcxCoreResult<()>;

    async fn delete_record(&self, name: &str, category: &str) -> VcxCoreResult<()>;

    async fn search_record(
        &self,
        category: &str,
        search_filter: Option<SearchFilter>,
    ) -> VcxCoreResult<Vec<Record>>;
}

#[cfg(test)]
mod tests {
    use super::BaseWallet2;
    use crate::{
        errors::error::AriesVcxCoreErrorKind,
        wallet2::{
            entry_tag::{EntryTag, EntryTags},
            utils::random_seed,
            DidWallet, RecordBuilder, RecordWallet,
        },
    };

    async fn build_test_wallet() -> Box<dyn BaseWallet2> {
        #[cfg(feature = "vdrtools_wallet")]
        return dev_setup_indy_wallet().await;

        #[cfg(feature = "askar_wallet")]
        return dev_setup_askar_wallet().await;
    }

    #[cfg(feature = "vdrtools_wallet")]
    async fn dev_setup_indy_wallet() -> Box<dyn BaseWallet2> {
        use crate::{
            global::settings::{DEFAULT_WALLET_KEY, WALLET_KDF_RAW},
            wallet::indy::{wallet::create_and_open_wallet, IndySdkWallet, WalletConfig},
        };

        let config_wallet = WalletConfig {
            wallet_name: format!("wallet_{}", uuid::Uuid::new_v4()),
            wallet_key: DEFAULT_WALLET_KEY.into(),
            wallet_key_derivation: WALLET_KDF_RAW.into(),
            wallet_type: None,
            storage_config: None,
            storage_credentials: None,
            rekey: None,
            rekey_derivation_method: None,
        };
        let wallet_handle = create_and_open_wallet(&config_wallet).await.unwrap();

        Box::new(IndySdkWallet::new(wallet_handle))
    }

    #[cfg(feature = "askar_wallet")]
    async fn dev_setup_askar_wallet() -> Box<dyn BaseWallet2> {
        use aries_askar::StoreKeyMethod;
        use uuid::Uuid;

        use super::askar_wallet::AskarWallet;

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

    #[tokio::test]
    async fn did_wallet_should_sign_and_verify() {
        let wallet = build_test_wallet().await;

        let did_data = wallet
            .create_and_store_my_did(Some(&random_seed()), None)
            .await
            .unwrap();

        let msg = "sign this".as_bytes();
        let sig = wallet.sign(&did_data.verkey, msg).await.unwrap();

        let res = wallet.verify(&did_data.verkey, msg, &sig).await.unwrap();
        assert!(res);
    }

    #[tokio::test]
    async fn did_wallet_should_rotate_keys() {
        let wallet = build_test_wallet().await;

        let did_data = wallet
            .create_and_store_my_did(Some(&random_seed()), None)
            .await
            .unwrap();

        let key = wallet.did_key(&did_data.did).await.unwrap();

        assert_eq!(did_data.verkey, key);

        let res = wallet
            .replace_did_key_start(&did_data.did, Some(&random_seed()))
            .await
            .unwrap();

        wallet.replace_did_key_apply(&did_data.did).await.unwrap();

        let new_key = wallet.did_key(&did_data.did).await.unwrap();
        assert_eq!(res, new_key);
    }

    #[tokio::test]
    async fn did_wallet_should_pack_and_unpack() {
        let wallet = build_test_wallet().await;

        let sender_data = wallet.create_and_store_my_did(None, None).await.unwrap();

        let receiver_data = wallet.create_and_store_my_did(None, None).await.unwrap();

        let msg = "pack me";

        let packed = wallet
            .pack_message(
                Some(sender_data.verkey),
                vec![receiver_data.verkey],
                msg.as_bytes(),
            )
            .await
            .unwrap();

        let unpacked = wallet.unpack_message(&packed).await.unwrap();

        assert_eq!(msg, unpacked.message);
    }

    #[tokio::test]
    async fn record_wallet_should_create_record() {
        let wallet = build_test_wallet().await;

        let name = "foo";
        let category = "my";
        let value = "bar";

        let record1 = RecordBuilder::default()
            .name(name.into())
            .category(category.into())
            .value(value.into())
            .build()
            .unwrap();
        let record2 = RecordBuilder::default()
            .name("baz".into())
            .category(category.into())
            .value("box".into())
            .build()
            .unwrap();

        wallet.add_record(record1).await.unwrap();
        wallet.add_record(record2).await.unwrap();

        let res = wallet.get_record(name, category).await.unwrap();

        assert_eq!(value, res.value);
    }

    #[tokio::test]
    async fn record_wallet_should_delete_record() {
        let wallet = build_test_wallet().await;

        let name = "foo";
        let category = "my";
        let value = "bar";

        let record = RecordBuilder::default()
            .name(name.into())
            .category(category.into())
            .value(value.into())
            .build()
            .unwrap();

        wallet.add_record(record).await.unwrap();

        let res = wallet.get_record(name, category).await.unwrap();

        assert_eq!(value, res.value);

        wallet.delete_record(name, category).await.unwrap();

        let err = wallet.get_record(name, category).await.unwrap_err();
        assert_eq!(AriesVcxCoreErrorKind::WalletRecordNotFound, err.kind());
    }

    #[tokio::test]
    async fn record_wallet_should_search_for_records() {
        let wallet = build_test_wallet().await;

        let name1 = "foo";
        let name2 = "foa";
        let name3 = "fob";
        let category1 = "my";
        let category2 = "your";
        let value = "xxx";

        let mut record_builder = RecordBuilder::default();
        record_builder
            .name(name1.into())
            .category(category1.into())
            .value(value.into());

        let record1 = record_builder.build().unwrap();
        wallet.add_record(record1).await.unwrap();

        let record2 = record_builder.name(name2.into()).build().unwrap();
        wallet.add_record(record2).await.unwrap();

        let record3 = record_builder
            .name(name3.into())
            .category(category2.into())
            .build()
            .unwrap();
        wallet.add_record(record3).await.unwrap();

        let res = wallet.search_record(category1, None).await.unwrap();

        assert_eq!(2, res.len());
    }

    #[tokio::test]
    async fn record_wallet_should_update_record() {
        let wallet = build_test_wallet().await;

        let name = "foo";
        let category = "my";
        let value1 = "xxx";
        let value2 = "yyy";
        let tags1: EntryTags = vec![EntryTag::Plaintext("a".into(), "b".into())].into();
        let tags2 = EntryTags::default();

        let record = RecordBuilder::default()
            .name(name.into())
            .category(category.into())
            .tags(tags1.clone())
            .value(value1.into())
            .build()
            .unwrap();
        wallet.add_record(record.clone()).await.unwrap();

        wallet
            .update_record_value(name, category, value2)
            .await
            .unwrap();
        wallet
            .update_record_tags(name, category, tags2.clone())
            .await
            .unwrap();

        let res = wallet.get_record(name, category).await.unwrap();
        assert_eq!(value2, res.value);
        assert_eq!(tags2, res.tags);
    }

    #[tokio::test]
    async fn record_wallet_should_update_only_value() {
        let wallet = build_test_wallet().await;

        let name = "foo";
        let category = "my";
        let value1 = "xxx";
        let value2 = "yyy";
        let tags: EntryTags = vec![EntryTag::Plaintext("a".into(), "b".into())].into();

        let record = RecordBuilder::default()
            .name(name.into())
            .category(category.into())
            .tags(tags.clone())
            .value(value1.into())
            .build()
            .unwrap();
        wallet.add_record(record.clone()).await.unwrap();

        wallet
            .update_record_value(name, category, value2)
            .await
            .unwrap();

        let res = wallet.get_record(name, category).await.unwrap();
        assert_eq!(value2, res.value);
        assert_eq!(tags, res.tags);
    }

    #[tokio::test]
    async fn record_wallet_should_update_only_tags() {
        let wallet = build_test_wallet().await;

        let name = "foo";
        let category = "my";
        let value = "xxx";
        let tags1: EntryTags = vec![EntryTag::Plaintext("a".into(), "b".into())].into();
        let tags2: EntryTags = vec![EntryTag::Plaintext("c".into(), "d".into())].into();

        let record = RecordBuilder::default()
            .name(name.into())
            .category(category.into())
            .tags(tags1.clone())
            .value(value.into())
            .build()
            .unwrap();
        wallet.add_record(record.clone()).await.unwrap();

        wallet
            .update_record_tags(name, category, tags2.clone())
            .await
            .unwrap();

        let res = wallet.get_record(name, category).await.unwrap();
        assert_eq!(value, res.value);
        assert_eq!(tags2, res.tags);
    }
}
