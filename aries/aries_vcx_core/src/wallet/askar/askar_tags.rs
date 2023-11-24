use aries_askar::entry::EntryTag as AskarEntryTag;

use crate::wallet::entry_tags::{EntryTag, EntryTags};

impl From<AskarEntryTag> for EntryTag {
    fn from(askar_tag: AskarEntryTag) -> Self {
        match askar_tag {
            AskarEntryTag::Encrypted(key, val) => EntryTag::new(&key, &val),
            AskarEntryTag::Plaintext(key, val) => EntryTag::new(&format!("~{}", key), &val),
        }
    }
}

impl From<EntryTag> for AskarEntryTag {
    fn from(entry_tag: EntryTag) -> Self {
        if entry_tag.key().starts_with("~") {
            Self::Plaintext(
                entry_tag.key().to_string().trim_start_matches("~").into(),
                entry_tag.value().into(),
            )
        } else {
            Self::Encrypted(entry_tag.key().into(), entry_tag.value().into())
        }
    }
}

impl From<EntryTags> for Vec<AskarEntryTag> {
    fn from(tags: EntryTags) -> Self {
        let tags_vec: Vec<EntryTag> = tags.into();
        tags_vec.into_iter().map(Into::into).collect()
    }
}

impl From<Vec<AskarEntryTag>> for EntryTags {
    fn from(askar_tags: Vec<AskarEntryTag>) -> Self {
        askar_tags.into_iter().map(Into::into).collect()
    }
}
