use std::sync::Arc;

use async_trait::async_trait;

use super::{record::Record, search_filter::SearchFilter, BaseWallet, CoreWallet};
use crate::{errors::error::VcxCoreResult, wallet::entry_tags::EntryTags};

#[async_trait]
pub trait RecordWallet {
    async fn add_record(&self, record: Record) -> VcxCoreResult<()>;

    async fn get_record(&self, category: &str, name: &str) -> VcxCoreResult<Record>;

    async fn update_record_tags(
        &self,
        category: &str,
        name: &str,
        new_tags: EntryTags,
    ) -> VcxCoreResult<()>;

    async fn update_record_value(
        &self,
        category: &str,
        name: &str,
        new_value: &str,
    ) -> VcxCoreResult<()>;

    async fn delete_record(&self, category: &str, name: &str) -> VcxCoreResult<()>;

    async fn search_record(
        &self,
        category: &str,
        search_filter: Option<SearchFilter>,
    ) -> VcxCoreResult<Vec<Record>>;
}

#[async_trait]
impl RecordWallet for CoreWallet {
    async fn add_record(&self, record: Record) -> VcxCoreResult<()> {
        self.read().await.add_record(record).await
    }

    async fn get_record(&self, category: &str, name: &str) -> VcxCoreResult<Record> {
        self.read().await.get_record(category, name).await
    }

    async fn update_record_tags(
        &self,
        category: &str,
        name: &str,
        new_tags: EntryTags,
    ) -> VcxCoreResult<()> {
        self.read()
            .await
            .update_record_tags(category, name, new_tags)
            .await
    }

    async fn update_record_value(
        &self,
        category: &str,
        name: &str,
        new_value: &str,
    ) -> VcxCoreResult<()> {
        self.read()
            .await
            .update_record_value(category, name, new_value)
            .await
    }

    async fn delete_record(&self, category: &str, name: &str) -> VcxCoreResult<()> {
        self.read().await.delete_record(category, name).await
    }

    async fn search_record(
        &self,
        category: &str,
        search_filter: Option<SearchFilter>,
    ) -> VcxCoreResult<Vec<Record>> {
        self.read()
            .await
            .search_record(category, search_filter)
            .await
    }
}
