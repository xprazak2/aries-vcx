use async_trait::async_trait;
use typed_builder::TypedBuilder;

use crate::{errors::error::VcxCoreResult, wallet::record_tags::RecordTags};

use super::record_category::RecordCategory;

#[derive(Debug, Default, Clone, TypedBuilder)]
pub struct Record {
    category: RecordCategory,
    name: String,
    value: String,
    #[builder(default)]
    tags: RecordTags,
}

impl Record {
    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn category(&self) -> &RecordCategory {
        &self.category
    }

    pub fn tags(&self) -> &RecordTags {
        &self.tags
    }
}

#[derive(Debug, Default, Clone, TypedBuilder)]
pub struct PartialRecord {
    category: Option<String>,
    name: String,
    value: Option<String>,
    #[builder(default)]
    tags: Option<RecordTags>,
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

    pub fn tags(&self) -> &Option<RecordTags> {
        &self.tags
    }

    // #[cfg(feature = "askar_wallet")]
    // pub fn from_askar_entry(entry: aries_askar::entry::Entry) -> VcxCoreResult<Self> {
    //     use crate::wallet::askar::askar_utils::value_from_entry;

    //     Ok(Self::builder()
    //         .name(entry.name.clone())
    //         .category(Some(entry.category.clone()))
    //         .value(Some(value_from_entry(entry.clone())?))
    //         .tags(Some(entry.tags.into()))
    //         .build())
    // }

    // #[cfg(feature = "askar_wallet")]
    // pub fn from_askar_key_entry(key_entry: aries_askar::kms::KeyEntry) -> VcxCoreResult<Self> {
    //     use crate::wallet::askar::KeyValue;

    //     let local_key = key_entry.load_local_key()?;
    //     let name = key_entry.name();
    //     let tags = key_entry.tags_as_slice();

    //     // check for private key length!!!!
    //     let value = KeyValue::new(
    //         local_key_to_bs58_private_key(&local_key)?,
    //         local_key_to_bs58_public_key(&local_key)?,
    //     );

    //     let value = serde_json::to_string(&value)?;

    //     Ok(Self::builder()
    //         .name(name.into())
    //         .category(Some(INDY_KEY.into()))
    //         .value(Some(value))
    //         .tags(Some(tags.to_vec().into()))
    //         .build())
    // }
}

#[async_trait]
pub trait AllRecords {
    fn total_count(&self) -> VcxCoreResult<Option<usize>>;
    async fn next(&mut self) -> VcxCoreResult<Option<PartialRecord>>;
}
