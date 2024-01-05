use async_trait::async_trait;
use indy_api_types::domain::wallet::Record as IndyRecord;
use serde::Deserialize;
use serde_json::Value;
use vdrtools::Locator;

use super::{SEARCH_OPTIONS, WALLET_OPTIONS};
use crate::{
    errors::error::{AriesVcxCoreError, AriesVcxCoreErrorKind, VcxCoreResult},
    wallet::indy::IndySdkWallet,
    wallet2::{Record, RecordUpdate, RecordWallet, SearchFilter},
};

#[async_trait]
impl RecordWallet for IndySdkWallet {
    async fn add_record(&self, record: Record) -> VcxCoreResult<()> {
        let tags_map = if record.tags.is_empty() {
            None
        } else {
            Some(record.tags.into())
        };

        Ok(Locator::instance()
            .non_secret_controller
            .add_record(
                self.wallet_handle,
                record.category,
                record.name,
                record.value,
                tags_map,
            )
            .await?)
    }

    async fn get_record(&self, name: &str, category: &str) -> VcxCoreResult<Record> {
        let res = Locator::instance()
            .non_secret_controller
            .get_record(
                self.wallet_handle,
                category.into(),
                name.into(),
                WALLET_OPTIONS.into(),
            )
            .await?;

        let indy_record: IndyRecord = serde_json::from_str(&res)?;

        Ok(indy_record.into())
    }

    async fn update_record(&self, record: RecordUpdate) -> VcxCoreResult<()> {
        if let Some(tags) = record.tags {
            Locator::instance()
                .non_secret_controller
                .update_record_tags(
                    self.wallet_handle,
                    record.category.clone(),
                    record.name.clone(),
                    tags.into(),
                )
                .await?;
        }

        if let Some(value) = record.value {
            Locator::instance()
                .non_secret_controller
                .update_record_value(self.wallet_handle, record.category, record.name, value)
                .await?;
        }

        Ok(())
    }

    async fn delete_record(&self, name: &str, category: &str) -> VcxCoreResult<()> {
        Ok(Locator::instance()
            .non_secret_controller
            .delete_record(self.wallet_handle, category.into(), name.into())
            .await?)
    }

    async fn search_record(
        &self,
        category: &str,
        search_filter: Option<SearchFilter>,
    ) -> VcxCoreResult<Vec<Record>> {
        let json_filter = search_filter
            .map(|filter| match filter {
                SearchFilter::JsonFilter(inner) => Ok::<String, AriesVcxCoreError>(inner),
                SearchFilter::TagFilter(_) => Err(AriesVcxCoreError::from_msg(
                    AriesVcxCoreErrorKind::InvalidInput,
                    "filter type not supported",
                )),
            })
            .transpose()?;

        let query_json = json_filter.unwrap_or("{}".into());

        let search_handle = Locator::instance()
            .non_secret_controller
            .open_search(
                self.wallet_handle,
                category.into(),
                query_json,
                SEARCH_OPTIONS.into(),
            )
            .await?;

        let next = || async {
            let record = Locator::instance()
                .non_secret_controller
                .fetch_search_next_records(self.wallet_handle, search_handle, 1)
                .await?;

            let indy_res: Value = serde_json::from_str(&record)?;

            indy_res
                .get("records")
                .and_then(|v| v.as_array())
                .and_then(|arr| arr.first())
                .map(|item| IndyRecord::deserialize(item).map_err(AriesVcxCoreError::from))
                .transpose()
        };

        let mut records = Vec::new();
        while let Some(record) = next().await? {
            records.push(record.into());
        }

        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    // use test_utils::devsetup::create_indy_test_wallet_handle;

    // use crate::{
    //     errors::error::AriesVcxCoreErrorKind,
    //     wallet::indy::IndySdkWallet,
    //     wallet2::{
    //         entry_tag::{EntryTag, EntryTags},
    //         RecordBuilder, RecordUpdateBuilder, RecordWallet,
    //     },
    // };

    // #[tokio::test]
    // #[ignore]
    // async fn indy_wallet_should_create_record() {
    //     let wallet = IndySdkWallet::new(create_indy_test_wallet_handle().await);

    //     let name = "foo";
    //     let category = "my";
    //     let value = "bar";

    //     let record1 = RecordBuilder::default()
    //         .name(name.into())
    //         .category(category.into())
    //         .value(value.into())
    //         .build()
    //         .unwrap();
    //     let record2 = RecordBuilder::default()
    //         .name("baz".into())
    //         .category(category.into())
    //         .value("box".into())
    //         .build()
    //         .unwrap();

    //     wallet.add_record(record1).await.unwrap();
    //     wallet.add_record(record2).await.unwrap();

    //     let res = wallet.get_record(name, category).await.unwrap();

    //     assert_eq!(value, res.value);
    // }

    // #[tokio::test]
    // #[ignore]
    // async fn indy_wallet_should_delete_record() {
    //     let wallet = IndySdkWallet::new(create_indy_test_wallet_handle().await);

    //     let name = "foo";
    //     let category = "my";
    //     let value = "bar";

    //     let record = RecordBuilder::default()
    //         .name(name.into())
    //         .category(category.into())
    //         .value(value.into())
    //         .build()
    //         .unwrap();

    //     wallet.add_record(record).await.unwrap();

    //     let res = wallet.get_record(name, category).await.unwrap();

    //     assert_eq!(value, res.value);

    //     wallet.delete_record(name, category).await.unwrap();

    //     let err = wallet.get_record(name, category).await.unwrap_err();
    //     assert_eq!(AriesVcxCoreErrorKind::WalletRecordNotFound, err.kind());
    // }

    // #[tokio::test]
    // #[ignore]
    // async fn indy_wallet_should_search_for_records() {
    //     let wallet = IndySdkWallet::new(create_indy_test_wallet_handle().await);

    //     let name1 = "foo";
    //     let name2 = "foa";
    //     let name3 = "fob";
    //     let category1 = "my";
    //     let category2 = "your";
    //     let value = "xxx";

    //     let mut record_builder = RecordBuilder::default();
    //     record_builder
    //         .name(name1.into())
    //         .category(category1.into())
    //         .value(value.into());

    //     let record1 = record_builder.build().unwrap();
    //     wallet.add_record(record1).await.unwrap();

    //     let record2 = record_builder.name(name2.into()).build().unwrap();
    //     wallet.add_record(record2).await.unwrap();

    //     let record3 = record_builder
    //         .name(name3.into())
    //         .category(category2.into())
    //         .build()
    //         .unwrap();
    //     wallet.add_record(record3).await.unwrap();

    //     let res = wallet.search_record(category1, None).await.unwrap();

    //     assert_eq!(2, res.len());
    // }

    // #[tokio::test]
    // #[ignore]
    // async fn indy_wallet_should_update_record() {
    //     let wallet = IndySdkWallet::new(create_indy_test_wallet_handle().await);

    //     let name = "foo";
    //     let category = "my";
    //     let value1 = "xxx";
    //     let value2 = "yyy";
    //     let tags1 = EntryTags::from_vec(vec![EntryTag::Plaintext("a".into(), "b".into())]);
    //     let tags2 = EntryTags::default();

    //     let record = RecordBuilder::default()
    //         .name(name.into())
    //         .category(category.into())
    //         .tags(tags1.clone())
    //         .value(value1.into())
    //         .build()
    //         .unwrap();
    //     wallet.add_record(record.clone()).await.unwrap();

    //     let record_update = RecordUpdateBuilder::default()
    //         .name(record.name)
    //         .value(value2.into())
    //         .category(record.category)
    //         .tags(tags2.clone())
    //         .build()
    //         .unwrap();

    //     wallet.update_record(record_update).await.unwrap();

    //     let res = wallet.get_record(name, category).await.unwrap();
    //     assert_eq!(value2, res.value);
    //     assert_eq!(tags2, res.tags);
    // }

    // #[tokio::test]
    // #[ignore]
    // async fn indy_wallet_should_update_only_value() {
    //     let wallet = IndySdkWallet::new(create_indy_test_wallet_handle().await);

    //     let name = "foo";
    //     let category = "my";
    //     let value1 = "xxx";
    //     let value2 = "yyy";
    //     let tags = EntryTags::from_vec(vec![EntryTag::Plaintext("a".into(), "b".into())]);

    //     let record = RecordBuilder::default()
    //         .name(name.into())
    //         .category(category.into())
    //         .tags(tags.clone())
    //         .value(value1.into())
    //         .build()
    //         .unwrap();
    //     wallet.add_record(record.clone()).await.unwrap();

    //     let record_update = RecordUpdateBuilder::default()
    //         .name(record.name)
    //         .value(value2.into())
    //         .category(record.category)
    //         .build()
    //         .unwrap();

    //     wallet.update_record(record_update.clone()).await.unwrap();

    //     let res = wallet.get_record(name, category).await.unwrap();
    //     assert_eq!(value2, res.value);
    //     assert_eq!(tags, res.tags);
    // }

    // #[tokio::test]
    // #[ignore]
    // async fn indy_wallet_should_update_only_tags() {
    //     let wallet = IndySdkWallet::new(create_indy_test_wallet_handle().await);

    //     let name = "foo";
    //     let category = "my";
    //     let value = "xxx";
    //     let tags1 = EntryTags::from_vec(vec![EntryTag::Plaintext("a".into(), "b".into())]);
    //     let tags2 = EntryTags::from_vec(vec![EntryTag::Plaintext("c".into(), "d".into())]);

    //     let record = RecordBuilder::default()
    //         .name(name.into())
    //         .category(category.into())
    //         .tags(tags1.clone())
    //         .value(value.into())
    //         .build()
    //         .unwrap();
    //     wallet.add_record(record.clone()).await.unwrap();

    //     let record_update = RecordUpdateBuilder::default()
    //         .name(record.name)
    //         .category(record.category)
    //         .tags(tags2.clone())
    //         .build()
    //         .unwrap();

    //     wallet.update_record(record_update.clone()).await.unwrap();

    //     let res = wallet.get_record(name, category).await.unwrap();
    //     assert_eq!(value, res.value);
    //     assert_eq!(tags2, res.tags);
    // }
}
