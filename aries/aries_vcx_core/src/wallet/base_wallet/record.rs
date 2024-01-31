use async_trait::async_trait;
use typed_builder::TypedBuilder;

use crate::{errors::error::VcxCoreResult, wallet::entry_tag::EntryTags};

use super::ToRecord;

#[derive(Debug, Default, Clone, TypedBuilder)]
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

impl ToRecord for Record {
    fn to_record(&self) -> Record {
        self.clone()
    }
}

#[async_trait]
pub trait AllRecords {
    fn total_count(&self) -> usize;
    async fn next(&self) -> VcxCoreResult<Option<Record>>;
}

pub struct AllRecordsStruct {
    inner: Box<dyn Iterator<Item = Record>>,
}

// pub struct RecordIterator {
//     inner: Box<dyn Iterator<Item = Record>>,
// }

// impl RecordIterator
// // where
// //     T: ToRecord,
// {
//     pub fn new(records: Box<dyn Iterator<Item = Record>>) -> Self {
//         Self { inner: records }
//     }

//     // pub fn total_count(&self) -> usize {
//     //     self.inner.len()
//     // }

//     // pub fn foo() {
//     //     let rs = vec![Record::builder()
//     //         .name("foo".into())
//     //         .category("bar".into())
//     //         .value("bzs".into())
//     //         .build()]
//     //     .iter();
//     // }
// }

// impl Iterator for RecordIterator
// // where
// //     T: ToRecord,
// {
//     type Item = Record;

//     fn next(&mut self) -> Option<Self::Item> {
//         self.inner.next()
//     }
// }
