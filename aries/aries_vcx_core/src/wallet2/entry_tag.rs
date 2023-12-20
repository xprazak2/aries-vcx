use std::collections::HashMap;

use aries_askar::entry::EntryTag as AskarEntryTag;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum EntryTag {
    Encrypted(String, String),
    Plaintext(String, String),
}

impl From<EntryTag> for (String, String) {
    fn from(value: EntryTag) -> Self {
        match value {
            EntryTag::Encrypted(key, val) => (key, val),
            EntryTag::Plaintext(key, val) => (format!("~{}", key), val),
        }
    }
}

impl From<(String, String)> for EntryTag {
    fn from(value: (String, String)) -> Self {
        if value.0.starts_with("~") {
            EntryTag::Plaintext(value.0.trim_start_matches("~").into(), value.1)
        } else {
            EntryTag::Encrypted(value.0, value.1)
        }
    }
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
    pub fn new() -> Self {
        Self { inner: vec![] }
    }

    pub fn from_vec(inner: Vec<EntryTag>) -> Self {
        Self { inner }
    }

    pub fn add(&mut self, tag: EntryTag) {
        self.inner.push(tag)
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

pub struct EntryTagsIntoIterator {
    entry_tags: Vec<EntryTag>,
}

impl Iterator for EntryTagsIntoIterator {
    type Item = EntryTag;

    fn next(&mut self) -> Option<Self::Item> {
        if self.entry_tags.len() == 0 {
            return None;
        }
        let res = self.entry_tags.remove(0);
        Some(res)
    }
}

impl IntoIterator for EntryTags {
    type Item = EntryTag;

    type IntoIter = EntryTagsIntoIterator;

    fn into_iter(self) -> Self::IntoIter {
        Self::IntoIter {
            entry_tags: self.into(),
        }
    }
}

impl FromIterator<EntryTag> for EntryTags {
    fn from_iter<T: IntoIterator<Item = EntryTag>>(iter: T) -> Self {
        let mut this = Self::new();

        for item in iter {
            this.add(item);
        }
        this
    }
}

impl From<Vec<EntryTag>> for EntryTags {
    fn from(value: Vec<EntryTag>) -> Self {
        value.into_iter().fold(Self::new(), |mut memo, item| {
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

impl From<EntryTags> for HashMap<String, String> {
    fn from(value: EntryTags) -> Self {
        let tags: Vec<EntryTag> = value.into();
        tags.into_iter().fold(Self::new(), |mut memo, item| {
            let (key, value) = item.into();

            memo.insert(key, value);
            memo
        })
    }
}

impl From<HashMap<String, String>> for EntryTags {
    fn from(value: HashMap<String, String>) -> Self {
        Self {
            inner: value
                .into_iter()
                .map(|(key, value)| (key, value))
                .map(From::from)
                .collect(),
        }
    }
}
