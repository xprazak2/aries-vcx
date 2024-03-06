use aries_vcx_core::{
    errors::error::VcxCoreResult,
    wallet::{
        askar::{askar_wallet_config::AskarIndyWalletConfig, AskarWallet},
        base_wallet::{
            did_data::DidData,
            did_wallet::DidWallet,
            record::{AllRecords, Record},
            record_category::RecordCategory,
            record_wallet::RecordWallet,
            search_filter::SearchFilter,
            BaseWallet, ManageWallet,
        },
        indy::{wallet_config::IndyWalletConfig, IndySdkWallet},
        record_tags::RecordTags,
        structs_io::UnpackMessageOutput,
    },
};
use async_trait::async_trait;
use public_key::Key;

#[derive(Debug)]
pub enum GlobalWallet {
    Indy(IndySdkWallet),
    Askar(AskarWallet),
}

#[async_trait]
impl RecordWallet for GlobalWallet {
    async fn all_records(&self) -> VcxCoreResult<Box<dyn AllRecords + Send>> {
        match self {
            GlobalWallet::Indy(inner) => inner.all_records().await,
            GlobalWallet::Askar(inner) => inner.all_records().await,
        }
    }

    async fn add_record(&self, record: Record) -> VcxCoreResult<()> {
        match self {
            GlobalWallet::Indy(inner) => inner.add_record(record).await,
            GlobalWallet::Askar(inner) => inner.add_record(record).await,
        }
    }

    async fn get_record(&self, category: RecordCategory, name: &str) -> VcxCoreResult<Record> {
        match self {
            GlobalWallet::Indy(inner) => inner.get_record(category, name).await,
            GlobalWallet::Askar(inner) => inner.get_record(category, name).await,
        }
    }

    async fn update_record_tags(
        &self,
        category: RecordCategory,
        name: &str,
        new_tags: RecordTags,
    ) -> VcxCoreResult<()> {
        match self {
            GlobalWallet::Indy(inner) => inner.update_record_tags(category, name, new_tags).await,
            GlobalWallet::Askar(inner) => inner.update_record_tags(category, name, new_tags).await,
        }
    }

    async fn update_record_value(
        &self,
        category: RecordCategory,
        name: &str,
        new_value: &str,
    ) -> VcxCoreResult<()> {
        match self {
            GlobalWallet::Indy(inner) => inner.update_record_value(category, name, new_value).await,
            GlobalWallet::Askar(inner) => {
                inner.update_record_value(category, name, new_value).await
            }
        }
    }

    async fn delete_record(&self, category: RecordCategory, name: &str) -> VcxCoreResult<()> {
        match self {
            GlobalWallet::Indy(inner) => inner.delete_record(category, name).await,
            GlobalWallet::Askar(inner) => inner.delete_record(category, name).await,
        }
    }

    async fn search_record(
        &self,
        category: RecordCategory,
        search_filter: Option<SearchFilter>,
    ) -> VcxCoreResult<Vec<Record>> {
        match self {
            GlobalWallet::Indy(inner) => inner.search_record(category, search_filter).await,
            GlobalWallet::Askar(inner) => inner.search_record(category, search_filter).await,
        }
    }
}

#[async_trait]
impl DidWallet for GlobalWallet {
    async fn create_and_store_my_did(
        &self,
        seed: Option<&str>,
        kdf_method_name: Option<&str>,
    ) -> VcxCoreResult<DidData> {
        match self {
            GlobalWallet::Indy(inner) => inner.create_and_store_my_did(seed, kdf_method_name).await,
            GlobalWallet::Askar(inner) => {
                inner.create_and_store_my_did(seed, kdf_method_name).await
            }
        }
    }

    async fn key_count(&self) -> VcxCoreResult<usize> {
        match self {
            GlobalWallet::Indy(inner) => inner.key_count().await,
            GlobalWallet::Askar(inner) => inner.key_count().await,
        }
    }

    async fn key_for_did(&self, did: &str) -> VcxCoreResult<Key> {
        match self {
            GlobalWallet::Indy(inner) => inner.key_for_did(did).await,
            GlobalWallet::Askar(inner) => inner.key_for_did(did).await,
        }
    }

    async fn replace_did_key_start(&self, did: &str, seed: Option<&str>) -> VcxCoreResult<Key> {
        match self {
            GlobalWallet::Indy(inner) => inner.replace_did_key_start(did, seed).await,
            GlobalWallet::Askar(inner) => inner.replace_did_key_start(did, seed).await,
        }
    }

    async fn replace_did_key_apply(&self, did: &str) -> VcxCoreResult<()> {
        match self {
            GlobalWallet::Indy(inner) => inner.replace_did_key_apply(did).await,
            GlobalWallet::Askar(inner) => inner.replace_did_key_apply(did).await,
        }
    }

    async fn sign(&self, key: &Key, msg: &[u8]) -> VcxCoreResult<Vec<u8>> {
        match self {
            GlobalWallet::Indy(inner) => inner.sign(key, msg).await,
            GlobalWallet::Askar(inner) => inner.sign(key, msg).await,
        }
    }

    async fn verify(&self, key: &Key, msg: &[u8], signature: &[u8]) -> VcxCoreResult<bool> {
        match self {
            GlobalWallet::Indy(inner) => inner.verify(key, msg, signature).await,
            GlobalWallet::Askar(inner) => inner.verify(key, msg, signature).await,
        }
    }

    async fn pack_message(
        &self,
        sender_vk: Option<Key>,
        receiver_keys: Vec<Key>,
        msg: &[u8],
    ) -> VcxCoreResult<Vec<u8>> {
        match self {
            GlobalWallet::Indy(inner) => inner.pack_message(sender_vk, receiver_keys, msg).await,
            GlobalWallet::Askar(inner) => inner.pack_message(sender_vk, receiver_keys, msg).await,
        }
    }

    async fn unpack_message(&self, msg: &[u8]) -> VcxCoreResult<UnpackMessageOutput> {
        match self {
            GlobalWallet::Indy(inner) => inner.unpack_message(msg).await,
            GlobalWallet::Askar(inner) => inner.unpack_message(msg).await,
        }
    }
}

#[async_trait]
impl BaseWallet for GlobalWallet {
    async fn export_wallet(&self, path: &str, backup_key: &str) -> VcxCoreResult<()> {
        match self {
            GlobalWallet::Indy(inner) => inner.export_wallet(path, backup_key).await,
            GlobalWallet::Askar(inner) => inner.export_wallet(path, backup_key).await,
        }
    }

    async fn close_wallet(&self) -> VcxCoreResult<()> {
        match self {
            GlobalWallet::Indy(inner) => inner.close_wallet().await,
            GlobalWallet::Askar(inner) => inner.close_wallet().await,
        }
    }
}

pub enum GlobalIndyWalletConfig {
    Indy(IndyWalletConfig),
    Askar(AskarIndyWalletConfig),
}

impl ManageWallet for GlobalIndyWalletConfig {
    type ManagedWalletType = GlobalWallet;

    async fn create_wallet(&self) -> VcxCoreResult<Self::ManagedWalletType> {
        match self {
            GlobalIndyWalletConfig::Indy(inner) => inner.create_wallet().await,
            GlobalIndyWalletConfig::Askar(inner) => inner.create_wallet().await,
        }
    }

    async fn open_wallet(&self) -> VcxCoreResult<Self::ManagedWalletType> {
        match self {
            GlobalIndyWalletConfig::Indy(inner) => inner.open_wallet().await,
            GlobalIndyWalletConfig::Askar(inner) => inner.open_wallet().await,
        }
    }

    async fn delete_wallet(&self) -> VcxCoreResult<()> {
        match self {
            GlobalIndyWalletConfig::Indy(inner) => inner.delete_wallet().await,
            GlobalIndyWalletConfig::Askar(inner) => inner.delete_wallet().await,
        }
    }
}
