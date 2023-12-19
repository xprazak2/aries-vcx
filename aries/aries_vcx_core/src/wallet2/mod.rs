use std::collections::HashMap;

use async_trait::async_trait;
use derive_builder::Builder;
#[cfg(feature = "vdrtools_wallet")]
use indy_api_types::domain::wallet::Record as IndyRecord;
use serde::{Deserialize, Serialize};

use crate::{errors::error::VcxCoreResult, wallet::structs_io::UnpackMessageOutput};

#[cfg(feature = "vdrtools_wallet")]
pub mod indy_wallet;

pub struct Key {
    pub pubkey_bs58: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum EntryTag {
    Encrypted(String, String),
    Plaintext(String, String),
}

#[derive(Default)]
pub struct EntryTags {
    inner: Vec<EntryTag>,
}

impl EntryTags {
    pub fn add(&mut self, tag: EntryTag) {
        self.inner.push(tag)
    }
}

impl From<Vec<EntryTag>> for EntryTags {
    fn from(value: Vec<EntryTag>) -> Self {
        value.into_iter().fold(Self::default(), |mut memo, item| {
            memo.add(item);
            memo
        })
    }
}

impl From<EntryTags> for Vec<EntryTag> {
    fn from(value: EntryTags) -> Self {
        value.inner
    }
}

impl From<EntryTags> for HashMap<String, String> {
    fn from(value: EntryTags) -> Self {
        let tags: Vec<EntryTag> = value.into();
        tags.into_iter().fold(Self::new(), |mut memo, item| {
            let (key, value) = item.into();
            memo.insert(key, value);
            memo
        })
    }
}

impl From<HashMap<String, String>> for EntryTags {
    fn from(value: HashMap<String, String>) -> Self {
        Self {
            inner: value
                .into_iter()
                .map(|(key, value)| (key, value))
                .map(From::from)
                .collect(),
        }
    }
}

#[derive(Debug, Default, Clone, Builder)]
pub struct Record {
    pub category: String,
    pub name: String,
    pub value: String,
    #[builder(default = "vec![]")]
    pub tags: Vec<EntryTag>,
}

#[derive(Debug, Default, Clone, Builder)]
pub struct RecordUpdate {
    pub category: String,
    pub name: String,
    #[builder(default)]
    pub value: Option<String>,
    #[builder(default)]
    pub tags: Option<Vec<EntryTag>>,
}

#[cfg(feature = "vdrtools_wallet")]
impl From<IndyRecord> for Record {
    fn from(ir: IndyRecord) -> Self {
        let tags = ir
            .tags
            .into_iter()
            .map(|(key, value)| EntryTag::Plaintext(key, value))
            .collect();
        Self {
            name: ir.id,
            category: ir.type_,
            value: ir.value,
            tags,
        }
    }
}

impl From<(String, String)> for EntryTag {
    fn from(value: (String, String)) -> Self {
        if value.0.starts_with('~') {
            EntryTag::Plaintext(value.0, value.1)
        } else {
            EntryTag::Encrypted(value.0, value.1)
        }
    }
}

impl From<EntryTag> for (String, String) {
    fn from(value: EntryTag) -> Self {
        match value {
            EntryTag::Encrypted(key, val) => (key, val),
            EntryTag::Plaintext(key, val) => (key, val),
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnpackedMessage {
    pub message: String,
    pub recipient_verkey: String,
    pub sender_verkey: Option<String>,
}

#[cfg(feature = "vdrtools_wallet")]
impl From<UnpackMessageOutput> for UnpackedMessage {
    fn from(value: UnpackMessageOutput) -> Self {
        Self {
            message: value.message,
            recipient_verkey: value.recipient_verkey,
            sender_verkey: value.sender_verkey,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DidData {
    pub did: String,
    pub verkey: String,
}

pub enum SearchFilter {
    JsonFilter(String),
}

pub trait BaseWallet2: RecordWallet + DidWallet + Send + Sync + std::fmt::Debug {}

#[async_trait]
pub trait DidWallet {
    async fn create_and_store_my_did(
        &self,
        seed: Option<&str>,
        method_name: Option<&str>,
    ) -> VcxCoreResult<DidData>;

    async fn did_key(&self, name: &str) -> VcxCoreResult<String>;

    async fn replace_did_key_start(&self, did: &str, seed: Option<&str>) -> VcxCoreResult<String>;

    async fn replace_did_key_apply(&self, did: &str) -> VcxCoreResult<()>;

    async fn sign(&self, key: &str, msg: &[u8]) -> VcxCoreResult<Vec<u8>>;

    async fn verify(&self, key: &str, msg: &[u8], signature: &[u8]) -> VcxCoreResult<bool>;

    async fn pack_message(
        &self,
        sender_vk: Option<String>,
        receiver_keys: Vec<Key>,
        msg: &[u8],
    ) -> VcxCoreResult<Vec<u8>>;

    async fn unpack_message(&self, msg: &[u8]) -> VcxCoreResult<UnpackedMessage>;
}

#[async_trait]
pub trait RecordWallet {
    async fn add_record(&self, record: Record) -> VcxCoreResult<()>;

    async fn get_record(&self, name: &str, category: &str) -> VcxCoreResult<Record>;

    async fn update_record(&self, record: RecordUpdate) -> VcxCoreResult<()>;

    async fn delete_record(&self, name: &str, category: &str) -> VcxCoreResult<()>;

    async fn search_record(
        &self,
        category: &str,
        search_filter: Option<SearchFilter>,
    ) -> VcxCoreResult<Vec<Record>>;
}
