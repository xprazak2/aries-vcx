use aries_askar::entry::EntryTag as AskarEntryTag;
use async_trait::async_trait;

use super::AskarWallet;
use crate::{
    errors::error::{AriesVcxCoreError, AriesVcxCoreErrorKind, VcxCoreResult},
    wallet::{
        base_wallet::{record::Record, search_filter::SearchFilter, RecordWallet},
        entry_tags::EntryTags,
    },
};

#[async_trait]
impl RecordWallet for AskarWallet {
    async fn add_record(&self, record: Record) -> VcxCoreResult<()> {
        let mut session = self.backend.session(self.profile.clone()).await?;
        let tags: Option<Vec<AskarEntryTag>> = Some(record.tags().clone().into());

        Ok(session
            .insert(
                record.category(),
                record.name(),
                record.value().as_bytes(),
                tags.as_deref(),
                None,
            )
            .await?)
    }

    async fn get_record(&self, category: &str, name: &str) -> VcxCoreResult<Record> {
        let mut session = self.backend.session(self.profile.clone()).await?;

        Ok(session
            .fetch(category, name, false)
            .await?
            .ok_or_else(|| {
                AriesVcxCoreError::from_msg(
                    AriesVcxCoreErrorKind::WalletRecordNotFound,
                    "record not found",
                )
            })
            .map(TryFrom::try_from)??)
    }

    async fn update_record_tags(
        &self,
        category: &str,
        name: &str,
        new_tags: EntryTags,
    ) -> VcxCoreResult<()> {
        let mut session = self.backend.session(self.profile.clone()).await?;

        let found = session.fetch(category, name, true).await?;

        let askar_tags: Vec<AskarEntryTag> = new_tags.into();

        match found {
            Some(record) => Ok(session
                .replace(category, name, &record.value, Some(&askar_tags), None)
                .await?),
            None => Err(AriesVcxCoreError::from_msg(
                AriesVcxCoreErrorKind::WalletRecordNotFound,
                "wallet record not found",
            )),
        }
    }

    async fn update_record_value(
        &self,
        category: &str,
        name: &str,
        new_value: &str,
    ) -> VcxCoreResult<()> {
        let mut session = self.backend.session(self.profile.clone()).await?;

        let found = session.fetch(category, name, true).await?;

        match found {
            Some(record) => Ok(session
                .replace(
                    category,
                    name,
                    new_value.as_bytes(),
                    Some(&record.tags),
                    None,
                )
                .await?),
            None => Err(AriesVcxCoreError::from_msg(
                AriesVcxCoreErrorKind::WalletRecordNotFound,
                "wallet record not found",
            )),
        }
    }

    async fn delete_record(&self, category: &str, name: &str) -> VcxCoreResult<()> {
        let mut session = self.backend.session(self.profile.clone()).await?;
        Ok(session.remove(category, name).await?)
    }

    #[allow(unreachable_patterns)]
    async fn search_record(
        &self,
        category: &str,
        search_filter: Option<SearchFilter>,
    ) -> VcxCoreResult<Vec<Record>> {
        let tag_filter = search_filter
            .map(|filter| match filter {
                SearchFilter::TagFilter(inner) => Ok(inner),
                _ => Err(AriesVcxCoreError::from_msg(
                    AriesVcxCoreErrorKind::WalletError,
                    "unsupported search filter",
                )),
            })
            .transpose()?;

        let mut session = self.backend.session(self.profile.clone()).await?;
        let res = session
            .fetch_all(Some(category), tag_filter, None, false)
            .await?;

        let rs: Vec<_> = res
            .into_iter()
            .map(TryFrom::try_from)
            .collect::<Vec<Result<Record, _>>>()
            .into_iter()
            .collect::<Result<_, _>>()?;
        Ok(rs)
    }
}
