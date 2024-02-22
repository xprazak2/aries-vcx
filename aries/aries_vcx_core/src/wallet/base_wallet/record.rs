use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use typed_builder::TypedBuilder;

use crate::{
    errors::error::{AriesVcxCoreError, AriesVcxCoreErrorKind, VcxCoreResult},
    wallet::entry_tags::EntryTags,
};

#[derive(Debug, Default, Clone, TypedBuilder, Serialize, Deserialize)]
pub struct Record {
    category: String,
    name: String,
    value: String,
    #[builder(default)]
    tags: EntryTags,
}

impl Record {
    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn category(&self) -> &str {
        &self.category
    }

    pub fn tags(&self) -> &EntryTags {
        &self.tags
    }
}

#[derive(Debug, Default, Clone, TypedBuilder)]
pub struct PartialRecord {
    category: Option<String>,
    name: String,
    value: Option<String>,
    #[builder(default)]
    tags: Option<EntryTags>,
}

impl PartialRecord {
    pub fn value(&self) -> &Option<String> {
        &self.value
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn category(&self) -> &Option<String> {
        &self.category
    }

    pub fn tags(&self) -> &Option<EntryTags> {
        &self.tags
    }

    pub fn try_into_record(self) -> VcxCoreResult<Record> {
        let unwrapped_category = match &self.category() {
            None => {
                return Err(AriesVcxCoreError::from_msg(
                    AriesVcxCoreErrorKind::InvalidInput,
                    "record is missing 'category'",
                ))
            }
            Some(category) => category.clone(),
        };
        let unwrapped_value = match &self.value() {
            None => {
                return Err(AriesVcxCoreError::from_msg(
                    AriesVcxCoreErrorKind::InvalidInput,
                    "record is missing 'category'",
                ))
            }
            Some(value) => value.clone(),
        };
        let unwrapped_tags = match &self.tags() {
            None => EntryTags::default(),
            Some(tags) => tags.clone(),
        };

        Ok(Record::builder()
            .category(unwrapped_category)
            .name(self.name().to_string())
            .value(unwrapped_value)
            .tags(unwrapped_tags)
            .build())
    }

    #[cfg(feature = "vdrtools_wallet")]
    pub fn from_wallet_record(wallet_record: vdrtools::WalletRecord) -> Self {
        use crate::wallet::indy::indy_tags::IndyTags;

        let name = wallet_record.get_id().into();
        let category = wallet_record.get_type();
        let value = wallet_record.get_value();

        let found_tags = wallet_record.get_tags();

        Self::builder()
            .name(name)
            .category(category.map(Into::into))
            .value(value.map(Into::into))
            .tags(found_tags.map(|tags| IndyTags::new(tags.clone()).into_entry_tags()))
            .build()
    }

    #[cfg(feature = "askar_wallet")]
    pub fn from_askar_entry(entry: aries_askar::entry::Entry) -> VcxCoreResult<Self> {
        use crate::wallet::askar::askar_utils::value_from_entry;

        Ok(Self::builder()
            .name(entry.name.clone())
            .category(Some(entry.category.clone()))
            .value(Some(value_from_entry(entry.clone())?))
            .tags(Some(entry.tags.into()))
            .build())
    }

    #[cfg(feature = "askar_wallet")]
    pub fn from_askar_key_entry(key_entry: aries_askar::kms::KeyEntry) -> VcxCoreResult<Self> {
        use crate::wallet::{
            askar::{
                askar_utils::{local_key_to_bs58_private_key, local_key_to_bs58_public_key},
                KeyValue,
            },
            constants::INDY_KEY,
        };

        let local_key = key_entry.load_local_key()?;
        let name = key_entry.name();
        let tags = key_entry.tags_as_slice();

        // check for private key length!!!!
        let value = KeyValue::new(
            local_key_to_bs58_private_key(&local_key)?,
            local_key_to_bs58_public_key(&local_key)?,
        );

        let value = serde_json::to_string(&value)?;

        Ok(Self::builder()
            .name(name.into())
            .category(Some(INDY_KEY.into()))
            .value(Some(value))
            .tags(Some(tags.to_vec().into()))
            .build())
    }

    #[cfg(feature = "askar_wallet")]
    pub fn try_into_askar_key_entry() -> VcxCoreResult<()> {
        Ok(())
    }
}

#[async_trait]
pub trait AllRecords {
    fn total_count(&self) -> VcxCoreResult<Option<usize>>;
    async fn next(&mut self) -> VcxCoreResult<Option<PartialRecord>>;
}
