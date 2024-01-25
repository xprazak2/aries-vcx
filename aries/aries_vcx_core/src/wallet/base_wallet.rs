#[cfg(feature = "askar_wallet")]
use aries_askar::entry::{Entry, EntryKind, TagFilter};
use async_trait::async_trait;

#[cfg(feature = "vdrtools_wallet")]
use indy_api_types::domain::wallet::Record as IndyRecord;
use public_key::Key;
use serde::{Deserialize, Serialize};
use typed_builder::TypedBuilder;

use super::{entry_tag::EntryTags, utils::did_from_key};
use crate::{
    errors::error::{AriesVcxCoreError, AriesVcxCoreErrorKind, VcxCoreResult},
    wallet::structs_io::UnpackMessageOutput,
};

#[derive(Debug, Default, Clone, TypedBuilder)]
pub struct Record {
    category: String,
    name: String,
    value: String,
    #[builder(default)]
    tags: EntryTags,
}

impl Record {
    pub fn get_value(&self) -> &str {
        &self.value
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn get_category(&self) -> &str {
        &self.category
    }

    pub fn get_tags(&self) -> &EntryTags {
        &self.tags
    }
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
        Self {
            id: record.name,
            type_: record.category,
            value: record.value,
            tags: record.tags.into(),
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
    pub fn new(did: &str, verkey: Key) -> Self {
        Self {
            did: did.into(),
            verkey,
        }
    }

    pub fn get_did(&self) -> &str {
        &self.did
    }

    pub fn get_verkey(&self) -> &Key {
        &self.verkey
    }

    pub fn did_from_verkey(&self) -> String {
        did_from_key(self.verkey.clone())
    }
}

pub enum SearchFilter {
    JsonFilter(String),
    #[cfg(feature = "askar_wallet")]
    TagFilter(TagFilter),
}

pub trait BaseWallet: RecordWallet + DidWallet + Send + Sync + std::fmt::Debug {}

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
    use rand::{distributions::Alphanumeric, Rng};

    use super::BaseWallet;
    use crate::{
        errors::error::AriesVcxCoreErrorKind,
        wallet::{
            base_wallet::{Record, RecordBuilder},
            entry_tag::{EntryTag, EntryTags},
            utils::did_from_key,
        },
    };

    fn random_seed() -> String {
        rand::thread_rng()
            .sample_iter(Alphanumeric)
            .take(32)
            .map(char::from)
            .collect()
    }

    async fn build_test_wallet() -> Box<dyn BaseWallet> {
        #[cfg(feature = "vdrtools_wallet")]
        return dev_setup_indy_wallet().await;

        #[cfg(feature = "askar_wallet")]
        return dev_setup_askar_wallet().await;
    }

    #[cfg(feature = "vdrtools_wallet")]
    async fn dev_setup_indy_wallet() -> Box<dyn BaseWallet> {
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
    async fn dev_setup_askar_wallet() -> Box<dyn BaseWallet> {
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
    async fn did_wallet_should_replace_did_key_repeatedly() {
        let wallet = build_test_wallet().await;

        let first_data = wallet
            .create_and_store_my_did("foo".into(), None)
            .await
            .unwrap();

        let new_key = wallet
            .replace_did_key_start(&first_data.get_did(), Some("goo"))
            .await
            .unwrap();

        wallet
            .replace_did_key_apply(&first_data.get_did())
            .await
            .unwrap();

        let new_verkey = wallet.did_key(&first_data.get_did()).await.unwrap();

        assert_eq!(did_from_key(new_key), did_from_key(new_verkey));

        let second_new_key = wallet
            .replace_did_key_start(&first_data.get_did(), Some("koo"))
            .await
            .unwrap();

        wallet
            .replace_did_key_apply(&first_data.get_did())
            .await
            .unwrap();

        let second_new_verkey = wallet.did_key(&first_data.get_did()).await.unwrap();

        assert_eq!(
            did_from_key(second_new_key),
            did_from_key(second_new_verkey)
        );
    }

    #[tokio::test]
    async fn did_wallet_should_replace_did_key_interleaved() {
        let wallet = build_test_wallet().await;

        let first_data = wallet
            .create_and_store_my_did("foo".into(), None)
            .await
            .unwrap();

        let second_data = wallet
            .create_and_store_my_did("boo".into(), None)
            .await
            .unwrap();

        let first_new_key = wallet
            .replace_did_key_start(&first_data.get_did(), Some("goo"))
            .await
            .unwrap();

        let second_new_key = wallet
            .replace_did_key_start(&second_data.get_did(), Some("moo"))
            .await
            .unwrap();

        wallet
            .replace_did_key_apply(&second_data.get_did())
            .await
            .unwrap();
        wallet
            .replace_did_key_apply(&first_data.get_did())
            .await
            .unwrap();

        let first_new_verkey = wallet.did_key(&first_data.get_did()).await.unwrap();
        let second_new_verkey = wallet.did_key(&second_data.get_did()).await.unwrap();

        assert_eq!(did_from_key(first_new_key), did_from_key(first_new_verkey));
        assert_eq!(
            did_from_key(second_new_key),
            did_from_key(second_new_verkey)
        );
    }

    #[tokio::test]
    async fn did_wallet_should_pack_and_unpack_authcrypt() {
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
    async fn did_wallet_should_pack_and_unpack_anoncrypt() {
        let wallet = build_test_wallet().await;

        let receiver_data = wallet.create_and_store_my_did(None, None).await.unwrap();

        let msg = "pack me";

        let packed = wallet
            .pack_message(None, vec![receiver_data.verkey], msg.as_bytes())
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

        let record1 = Record::builder()
            .name(name.into())
            .category(category.into())
            .value(value.into())
            .build();
        let record2 = Record::builder()
            .name("baz".into())
            .category(category.into())
            .value("box".into())
            .build();

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

        let record = Record::builder()
            .name(name.into())
            .category(category.into())
            .value(value.into())
            .build();

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

        let record1 = Record::builder()
            .name(name1.into())
            .category(category1.into())
            .value(value.into())
            .build();

        wallet.add_record(record1).await.unwrap();

        let record2 = Record::builder()
            .name(name2.into())
            .category(category1.into())
            .value(value.into())
            .build();
        wallet.add_record(record2).await.unwrap();

        let record3 = Record::builder()
            .name(name3.into())
            .category(category2.into())
            .value(value.into())
            .build();

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

        let record = Record::builder()
            .name(name.into())
            .category(category.into())
            .tags(tags1.clone())
            .value(value1.into())
            .build();
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

        let record = Record::builder()
            .name(name.into())
            .category(category.into())
            .tags(tags.clone())
            .value(value1.into())
            .build();
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

        let record = Record::builder()
            .name(name.into())
            .category(category.into())
            .tags(tags1.clone())
            .value(value.into())
            .build();
        wallet.add_record(record.clone()).await.unwrap();

        wallet
            .update_record_tags(name, category, tags2.clone())
            .await
            .unwrap();

        let res = wallet.get_record(name, category).await.unwrap();
        assert_eq!(value, res.value);
        assert_eq!(tags2, res.tags);
    }

    async fn pack_and_unpack_anoncrypt(
        sender: Box<dyn BaseWallet>,
        recipient: Box<dyn BaseWallet>,
    ) {
        let did_data = recipient.create_and_store_my_did(None, None).await.unwrap();

        let msg = "send me";

        let rec_key = did_data.get_verkey().to_owned();

        let packed = sender
            .pack_message(None, vec![rec_key], msg.as_bytes())
            .await
            .unwrap();

        let unpacked = recipient.unpack_message(&packed).await.unwrap();

        assert_eq!(msg, unpacked.message);
    }

    async fn pack_and_unpack_authcrypt(
        sender: Box<dyn BaseWallet>,
        recipient: Box<dyn BaseWallet>,
    ) {
        let sender_did_data = sender.create_and_store_my_did(None, None).await.unwrap();
        let recipient_did_data = recipient.create_and_store_my_did(None, None).await.unwrap();

        let msg = "send me";

        let rec_key = recipient_did_data.get_verkey().to_owned();

        let packed = sender
            .pack_message(
                Some(sender_did_data.get_verkey().to_owned()),
                vec![rec_key],
                msg.as_bytes(),
            )
            .await
            .unwrap();

        let unpacked = recipient.unpack_message(&packed).await.unwrap();

        assert_eq!(msg, unpacked.message);
    }

    #[tokio::test]
    async fn test_askar_should_pack_and_indy_should_unpack_anoncrypt() {
        let askar_wallet = dev_setup_askar_wallet().await;
        let indy_wallet = dev_setup_indy_wallet().await;

        pack_and_unpack_anoncrypt(askar_wallet, indy_wallet).await;
    }

    #[tokio::test]
    async fn test_indy_should_pack_and_askar_should_unpack_anoncrypt() {
        let askar_wallet = dev_setup_askar_wallet().await;
        let indy_wallet = dev_setup_indy_wallet().await;

        pack_and_unpack_anoncrypt(indy_wallet, askar_wallet).await;
    }

    #[tokio::test]
    async fn test_askar_should_pack_and_indy_should_unpack_authcrypt() {
        let askar_wallet = dev_setup_askar_wallet().await;
        let indy_wallet = dev_setup_indy_wallet().await;

        pack_and_unpack_authcrypt(askar_wallet, indy_wallet).await;
    }

    #[tokio::test]
    async fn test_indy_should_pack_and_askar_should_unpack_authcrypt() {
        let askar_wallet = dev_setup_askar_wallet().await;
        let indy_wallet = dev_setup_indy_wallet().await;

        pack_and_unpack_authcrypt(indy_wallet, askar_wallet).await;
    }
}
