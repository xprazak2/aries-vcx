use std::collections::HashMap;

use aries_askar::entry::{Entry, EntryKind, TagFilter};
use async_trait::async_trait;
use derive_builder::Builder;
#[cfg(feature = "vdrtools_wallet")]
use indy_api_types::domain::wallet::Record as IndyRecord;
use serde::{Deserialize, Serialize};

use self::entry_tag::EntryTags;
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

pub struct Key {
    pub pubkey_bs58: String,
}

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
    pub category: String,
    pub name: String,
    pub value: String,
    #[builder(default = "EntryTags::default()")]
    pub tags: EntryTags,
}

#[derive(Debug, Default, Clone, Builder)]
#[builder(setter(strip_option))]
pub struct RecordUpdate {
    pub category: String,
    pub name: String,
    #[builder(setter(strip_option), default = "None")]
    pub value: Option<String>,
    #[builder(setter(strip_option), default = "None")]
    pub tags: Option<EntryTags>,
}

#[cfg(feature = "vdrtools_wallet")]
impl From<IndyRecord> for Record {
    fn from(ir: IndyRecord) -> Self {
        let tags = ir.tags.into_iter().map(From::from).collect();
        Self {
            name: ir.id,
            category: ir.type_,
            value: ir.value,
            tags,
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
        let string_value = std::str::from_utf8(&entry.value).map_err(|err| {
            AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::WalletUnexpected, err)
        })?;

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
    pub did: String,
    pub verkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

pub enum SearchFilter {
    TagFilter(TagFilter),
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

// #[cfg(test)]
// mod test {
//     use aries_askar::kms::{KeyAlg, LocalKey};
//     use test_utils::devsetup::create_indy_test_wallet_handle;

//     use crate::{
//         wallet::indy::IndySdkWallet,
//         wallet2::{
//             askar_wallet::{
//                 askar_utils::local_key_to_public_key_bytes, test_helper::create_test_wallet,
//                 RngMethod,
//             },
//             utils::bytes_to_bs58,
//             DidWallet, Key,
//         },
//     };

//     #[tokio::test]
//     async fn test_askar_should_pack_and_indy_should_unpack_anoncrypt() {
//         let askar_wallet = create_test_wallet().await;

//         let (key_name, recipient_key) = askar_wallet
//             .create_key(KeyAlg::Ed25519, "foo".as_bytes(), RngMethod::RandomDet)
//             .await
//             .unwrap();

//         // let mut session = askar_wallet
//         //     .backend
//         //     .session(askar_wallet.profile.clone())
//         //     .await
//         //     .unwrap();

//         let msg = "send me";

//         // let recipient_key = LocalKey::generate(KeyAlg::Ed25519, true).unwrap();

//         let kid = bytes_to_bs58(&local_key_to_public_key_bytes(&recipient_key).unwrap());
//         // session
//         //     .insert_key(&kid, &recipient_key, None, None, None)
//         //     .await
//         //     .unwrap();

//         let rec_key = Key { pubkey_bs58: kid };

//         let packed = askar_wallet
//             .pack_message(None, vec![rec_key], msg.as_bytes())
//             .await
//             .unwrap();

//         let indy_wallet = IndySdkWallet::new(create_indy_test_wallet_handle().await);

//         let unpacked = indy_wallet.unpack_message(&packed).await.unwrap();

//         assert_eq!(msg, unpacked.message);
//     }
// }
