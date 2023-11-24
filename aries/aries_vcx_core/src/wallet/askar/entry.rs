use aries_askar::entry::{Entry, EntryKind};

use crate::{
    errors::error::{AriesVcxCoreError, AriesVcxCoreErrorKind},
    wallet::base_wallet::record::Record,
};

impl TryFrom<Entry> for Record {
    type Error = AriesVcxCoreError;

    fn try_from(entry: Entry) -> Result<Self, Self::Error> {
        let string_value = std::str::from_utf8(&entry.value)
            .map_err(|err| AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::WalletError, err))?;

        let tags = entry.tags.into();

        Ok(Self::builder()
            .category(entry.category)
            .name(entry.name)
            .value(string_value.into())
            .tags(tags)
            .build())
    }
}

impl From<Record> for Entry {
    fn from(record: Record) -> Self {
        Self {
            category: record.category().to_string(),
            name: record.name().to_string(),
            value: record.value().into(),
            kind: EntryKind::Item,
            tags: record.tags().clone().into_iter().map(From::from).collect(),
        }
    }
}
