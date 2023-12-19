use std::collections::HashMap;

use async_trait::async_trait;

use super::structs_io::UnpackMessageOutput;
#[cfg(feature = "vdrtools_wallet")]
use crate::WalletHandle;
use crate::{
    errors::error::{AriesVcxCoreError, AriesVcxCoreErrorKind, VcxCoreResult},
    utils::{
        async_fn_iterator::AsyncFnIterator,
        {self},
    },
    wallet::base_wallet::BaseWallet,
    wallet2::{
        BaseWallet2, DidData, DidWallet, Key, Record, RecordBuilder, RecordUpdate, RecordWallet,
        SearchFilter, UnpackedMessage,
    },
};

#[derive(Debug)]
pub struct MockWallet;

// NOTE : currently matches the expected results if did_mocks and indy_mocks are enabled
/// Implementation of [BaseAnoncreds] which responds with mock data
#[allow(unused)]
#[async_trait]
impl BaseWallet for MockWallet {
    #[cfg(feature = "vdrtools_wallet")]
    fn get_wallet_handle(&self) -> WalletHandle {
        WalletHandle(1)
    }

    async fn create_and_store_my_did(
        &self,
        seed: Option<&str>,
        method_name: Option<&str>,
    ) -> VcxCoreResult<(String, String)> {
        Ok((
            utils::constants::DID.to_string(),
            utils::constants::VERKEY.to_string(),
        ))
    }

    async fn key_for_local_did(&self, did: &str) -> VcxCoreResult<String> {
        Ok(utils::constants::VERKEY.to_string())
    }

    async fn replace_did_keys_start(&self, target_did: &str) -> VcxCoreResult<String> {
        Ok(utils::constants::VERKEY.to_string())
    }

    async fn replace_did_keys_apply(&self, target_did: &str) -> VcxCoreResult<()> {
        Ok(())
    }

    async fn add_wallet_record(
        &self,
        xtype: &str,
        id: &str,
        value: &str,
        tags: Option<HashMap<String, String>>,
    ) -> VcxCoreResult<()> {
        Ok(())
    }

    async fn get_wallet_record(
        &self,
        xtype: &str,
        id: &str,
        options: &str,
    ) -> VcxCoreResult<String> {
        Ok(r#"{"id":"123","type":"record type","value":"record value","tags":null}"#.to_string())
    }

    async fn get_wallet_record_value(&self, xtype: &str, id: &str) -> VcxCoreResult<String> {
        Ok(r#""record value""#.to_owned())
    }

    async fn delete_wallet_record(&self, xtype: &str, id: &str) -> VcxCoreResult<()> {
        Ok(())
    }

    async fn update_wallet_record_value(
        &self,
        xtype: &str,
        id: &str,
        value: &str,
    ) -> VcxCoreResult<()> {
        Ok(())
    }

    async fn add_wallet_record_tags(
        &self,
        xtype: &str,
        id: &str,
        tags: HashMap<String, String>,
    ) -> VcxCoreResult<()> {
        Ok(())
    }

    async fn update_wallet_record_tags(
        &self,
        xtype: &str,
        id: &str,
        tags: HashMap<String, String>,
    ) -> VcxCoreResult<()> {
        Ok(())
    }

    async fn delete_wallet_record_tags(
        &self,
        xtype: &str,
        id: &str,
        tag_names: &str,
    ) -> VcxCoreResult<()> {
        Ok(())
    }

    async fn iterate_wallet_records(
        &self,
        xtype: &str,
        query: &str,
        options: &str,
    ) -> VcxCoreResult<Box<dyn AsyncFnIterator<Item = VcxCoreResult<String>>>> {
        // not needed yet
        Err(AriesVcxCoreError::from_msg(
            AriesVcxCoreErrorKind::UnimplementedFeature,
            "unimplemented mock method: iterate_wallet_records",
        ))
    }

    async fn sign(&self, my_vk: &str, msg: &[u8]) -> VcxCoreResult<Vec<u8>> {
        Ok(Vec::from(msg))
    }

    async fn verify(&self, vk: &str, msg: &[u8], signature: &[u8]) -> VcxCoreResult<bool> {
        Ok(true)
    }

    async fn pack_message(
        &self,
        sender_vk: Option<&str>,
        receiver_keys: &str,
        msg: &[u8],
    ) -> VcxCoreResult<Vec<u8>> {
        Ok(msg.to_vec())
    }

    async fn unpack_message(&self, msg: &[u8]) -> VcxCoreResult<UnpackMessageOutput> {
        Ok(UnpackMessageOutput {
            message: format!("{:?}", msg),
            recipient_verkey: "".to_owned(),
            sender_verkey: None,
        })
    }
}

impl BaseWallet2 for MockWallet {}

#[async_trait]
#[allow(unused_variables)]
impl RecordWallet for MockWallet {
    async fn add_record(&self, record: Record) -> VcxCoreResult<()> {
        Ok(())
    }

    async fn get_record(&self, name: &str, category: &str) -> VcxCoreResult<Record> {
        Ok(RecordBuilder::default()
            .name("123".into())
            .category("record type".into())
            .value("record value".into())
            .build()?)
    }

    async fn update_record(&self, record: RecordUpdate) -> VcxCoreResult<()> {
        Ok(())
    }

    async fn delete_record(&self, name: &str, category: &str) -> VcxCoreResult<()> {
        Ok(())
    }

    async fn search_record(
        &self,
        category: &str,
        search_filter: Option<SearchFilter>,
    ) -> VcxCoreResult<Vec<Record>> {
        Err(AriesVcxCoreError::from_msg(
            AriesVcxCoreErrorKind::UnimplementedFeature,
            "unimplemented mock method: search_record",
        ))
    }
}

#[async_trait]
#[allow(unused_variables)]
impl DidWallet for MockWallet {
    async fn create_and_store_my_did(
        &self,
        seed: Option<&str>,
        method_name: Option<&str>,
    ) -> VcxCoreResult<DidData> {
        Ok(DidData {
            did: utils::constants::DID.to_string(),
            verkey: utils::constants::VERKEY.to_string(),
        })
    }

    async fn did_key(&self, name: &str) -> VcxCoreResult<String> {
        Ok(utils::constants::VERKEY.to_string())
    }

    async fn replace_did_key_start(&self, did: &str, seed: Option<&str>) -> VcxCoreResult<String> {
        Ok(utils::constants::VERKEY.to_string())
    }

    async fn replace_did_key_apply(&self, did: &str) -> VcxCoreResult<()> {
        Ok(())
    }

    async fn sign(&self, key: &str, msg: &[u8]) -> VcxCoreResult<Vec<u8>> {
        Ok(Vec::from(msg))
    }

    async fn verify(&self, key: &str, msg: &[u8], signature: &[u8]) -> VcxCoreResult<bool> {
        Ok(true)
    }

    async fn pack_message(
        &self,
        sender_vk: Option<String>,
        receiver_keys: Vec<Key>,
        msg: &[u8],
    ) -> VcxCoreResult<Vec<u8>> {
        Ok(Vec::from(msg))
    }

    async fn unpack_message(&self, msg: &[u8]) -> VcxCoreResult<UnpackedMessage> {
        Ok(UnpackedMessage {
            message: format!("{:?}", msg),
            recipient_verkey: "".to_owned(),
            sender_verkey: None,
        })
    }
}
