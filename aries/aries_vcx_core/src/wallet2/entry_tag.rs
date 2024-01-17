use std::collections::HashMap;

#[cfg(feature = "askar_wallet")]
use aries_askar::entry::EntryTag as AskarEntryTag;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord)]
pub enum EntryTag {
    Encrypted(String, String),
    Plaintext(String, String),
}

#[cfg(feature = "askar_wallet")]
impl From<AskarEntryTag> for EntryTag {
    fn from(value: AskarEntryTag) -> Self {
        match value {
            AskarEntryTag::Encrypted(key, val) => Self::Encrypted(key, val),
            AskarEntryTag::Plaintext(key, val) => Self::Plaintext(key, val),
        }
    }
}

#[cfg(feature = "askar_wallet")]
impl From<EntryTag> for AskarEntryTag {
    fn from(value: EntryTag) -> Self {
        match value {
            EntryTag::Encrypted(key, val) => Self::Encrypted(key, val),
            EntryTag::Plaintext(key, val) => Self::Plaintext(key, val),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct EntryTags {
    inner: Vec<EntryTag>,
}

impl EntryTags {
    pub fn new(inner: Vec<EntryTag>) -> Self {
        Self { inner }
    }

    pub fn add(&mut self, tag: EntryTag) {
        self.inner.push(tag)
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl IntoIterator for EntryTags {
    type Item = EntryTag;

    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl FromIterator<EntryTag> for EntryTags {
    fn from_iter<T: IntoIterator<Item = EntryTag>>(iter: T) -> Self {
        let mut tags = Self::default();

        for item in iter {
            tags.add(item);
        }
        tags
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

impl From<EntryTags> for Vec<AskarEntryTag> {
    fn from(tags: EntryTags) -> Self {
        let tags_vec: Vec<EntryTag> = tags.into();
        tags_vec.into_iter().map(Into::into).collect()
    }
}
