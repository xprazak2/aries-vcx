use serde::{ser::SerializeMap, Deserialize, Serialize};

use crate::errors::error::AriesVcxCoreError;

#[cfg(feature = "askar_wallet")]
use aries_askar::entry::EntryTag as AskarEntryTag;

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

impl Serialize for EntryTags {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.inner.len()))?;
        for tag in self.inner.iter() {
            match tag {
                EntryTag::Encrypted(key, val) | EntryTag::Plaintext(key, val) => {
                    map.serialize_entry(&key, &val)?
                }
            }
        }
        map.end()
    }
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

#[cfg(feature = "askar_wallet")]
impl From<EntryTags> for Vec<AskarEntryTag> {
    fn from(value: EntryTags) -> Self {
        let vc: Vec<EntryTag> = value.into();
        vc.into_iter().map(Into::into).collect()
    }
}

// #[cfg(feature = "vdrtools_wallet")]
// impl From<EntryTags> for HashMap<String, String> {
//     fn from(value: EntryTags) -> Self {
//         let tags: Vec<EntryTag> = value.into();
//         tags.into_iter().fold(Self::new(), |mut memo, item| {
//             let (key, value) = item.into();

impl TryFrom<EntryTags> for Option<String> {
    type Error = AriesVcxCoreError;

    fn try_from(tags: EntryTags) -> Result<Self, Self::Error> {
        if tags.is_empty() {
            Ok(None)
        } else {
            Ok(Some(serde_json::to_string(&tags)?))
        }
    }
}

#[cfg(feature = "askar_wallet")]
impl From<EntryTags> for Vec<AskarEntryTag> {
    fn from(tags: EntryTags) -> Self {
        let tags_vec: Vec<EntryTag> = tags.into();
        tags_vec.into_iter().map(Into::into).collect()
    }
}
