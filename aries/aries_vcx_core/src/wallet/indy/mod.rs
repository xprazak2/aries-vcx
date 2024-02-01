use async_trait::async_trait;
use indy_api_types::domain::wallet::{
    default_key_derivation_method, IndyRecord, KeyDerivationMethod,
};
use serde::{Deserialize, Serialize};
use typed_builder::TypedBuilder;
use vdrtools::{indy_wallet::iterator::WalletIterator, Locator, WalletRecord};

use self::indy_tag::IndyTags;
use super::{
    base_wallet::{
        issuer_config::IssuerConfig,
        record::{AllRecords, PartialRecord, Record},
        wallet_config::WalletConfig,
        BaseWallet, DidWallet,
    },
    entry_tag::EntryTags,
};
use crate::{
    errors::error::{AriesVcxCoreError, AriesVcxCoreErrorKind, VcxCoreResult},
    WalletHandle,
};

mod indy_did_wallet;
mod indy_record_wallet;
pub(crate) mod indy_tag;
pub mod internal;
pub mod wallet;

#[derive(Debug)]
pub struct IndySdkWallet {
    wallet_handle: WalletHandle,
}

impl IndySdkWallet {
    pub fn new(wallet_handle: WalletHandle) -> Self {
        IndySdkWallet { wallet_handle }
    }

    pub fn get_wallet_handle(&self) -> WalletHandle {
        self.wallet_handle
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WalletCredentials {
    key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    rekey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    storage_credentials: Option<serde_json::Value>,
    key_derivation_method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    rekey_derivation_method: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndyWalletRecord {
    id: Option<String>,
    #[serde(rename = "type")]
    record_type: Option<String>,
    pub value: Option<String>,
    tags: Option<String>,
}

impl IndyWalletRecord {
    pub fn from_record(record: Record) -> VcxCoreResult<Self> {
        let tags = if record.tags().is_empty() {
            None
        } else {
            Some(serde_json::to_string(&record.tags())?)
        };

        Ok(Self {
            id: Some(record.name().into()),
            record_type: Some(record.category().into()),
            value: Some(record.value().into()),
            tags,
        })
    }

    // pub fn into_record(self) -> VcxCoreResult<Record> {
    //     let category = self.record_type.ok_or_else(|| {
    //         AriesVcxCoreError::from_msg(
    //             AriesVcxCoreErrorKind::InvalidInput,
    //             "invalid record category",
    //         )
    //     })?;
    //     let name = self.id.ok_or_else(|| {
    //         AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::InvalidInput, "invalid record name")
    //     })?;
    //     let value = self.value.ok_or_else(|| {
    //         AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::InvalidInput, "invalid record value")
    //     })?;

    //     if let Some(tags) = self.tags {
    //         let parsed_tags: EntryTags = serde_json::from_str(&tags)?;

    //         Ok(Record::builder()
    //             .category(category)
    //             .name(name)
    //             .value(value)
    //             .tags(parsed_tags)
    //             .build())
    //     } else {
    //         Ok(Record::builder()
    //             .category(category)
    //             .name(name)
    //             .value(value)
    //             .build())
    //     }
    // }
}

impl From<IndyRecord> for Record {
    fn from(ir: IndyRecord) -> Self {
        Self::builder()
            .name(ir.id)
            .category(ir.type_)
            .value(ir.value)
            .tags(IndyTags::new(ir.tags).into_entry_tags())
            .build()
    }
}

impl From<Record> for IndyRecord {
    fn from(record: Record) -> Self {
        Self {
            id: record.name().into(),
            type_: record.category().into(),
            value: record.value().into(),
            tags: IndyTags::from_entry_tags(record.tags().to_owned()).into_inner(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RestoreWalletConfigs {
    pub wallet_name: String,
    pub wallet_key: String,
    pub exported_wallet_path: String,
    pub backup_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_key_derivation: Option<String>,
}

const WALLET_OPTIONS: &str =
    r#"{"retrieveType": true, "retrieveValue": true, "retrieveTags": true}"#;

const SEARCH_OPTIONS: &str = r#"{"retrieveType": true, "retrieveValue": true, "retrieveTags": true, "retrieveRecords": true}"#;

#[async_trait]
impl BaseWallet for IndySdkWallet {
    async fn export_wallet(&self, path: &str, backup_key: &str) -> VcxCoreResult<()> {
        Locator::instance()
            .wallet_controller
            .export(
                self.wallet_handle,
                vdrtools::types::domain::wallet::ExportConfig {
                    key: backup_key.into(),
                    path: path.into(),

                    key_derivation_method: default_key_derivation_method(),
                },
            )
            .await?;

        Ok(())
    }

    async fn close_wallet(&self) -> VcxCoreResult<()> {
        Locator::instance()
            .wallet_controller
            .close(self.wallet_handle)
            .await?;

        Ok(())
    }

    async fn configure_issuer(&self, key_seed: &str) -> VcxCoreResult<IssuerConfig> {
        let did_data = self.create_and_store_my_did(Some(key_seed), None).await?;

        Ok(IssuerConfig {
            institution_did: did_data.did().to_string(),
        })
    }

    async fn create_wallet(wallet_config: WalletConfig) -> VcxCoreResult<Box<dyn BaseWallet>>
    where
        Self: Sized,
    {
        let handle = Locator::instance()
            .wallet_controller
            .open(
                vdrtools::types::domain::wallet::Config {
                    id: wallet_config.wallet_name.clone(),
                    storage_type: wallet_config.wallet_type.clone(),
                    storage_config: wallet_config
                        .storage_config
                        .as_deref()
                        .map(serde_json::from_str)
                        .transpose()?,
                    cache: None,
                },
                vdrtools::types::domain::wallet::Credentials {
                    key: wallet_config.wallet_key.clone(),
                    key_derivation_method: parse_key_derivation_method(
                        &wallet_config.wallet_key_derivation,
                    )?,

                    rekey: wallet_config.rekey.clone(),
                    rekey_derivation_method: wallet_config
                        .rekey_derivation_method
                        .as_deref()
                        .map(parse_key_derivation_method)
                        .transpose()?
                        .unwrap_or_else(default_key_derivation_method),

                    storage_credentials: wallet_config
                        .storage_credentials
                        .as_deref()
                        .map(serde_json::from_str)
                        .transpose()?,
                },
            )
            .await?;

        Ok(Box::new(IndySdkWallet {
            wallet_handle: handle,
        }))
    }

    async fn open_wallet(wallet_config: &WalletConfig) -> VcxCoreResult<Box<dyn BaseWallet>>
    where
        Self: Sized,
    {
        let handle = Locator::instance()
            .wallet_controller
            .open(
                vdrtools::types::domain::wallet::Config {
                    id: wallet_config.wallet_name.clone(),
                    storage_type: wallet_config.wallet_type.clone(),
                    storage_config: wallet_config
                        .storage_config
                        .as_deref()
                        .map(serde_json::from_str)
                        .transpose()?,
                    cache: None,
                },
                vdrtools::types::domain::wallet::Credentials {
                    key: wallet_config.wallet_key.clone(),
                    key_derivation_method: parse_key_derivation_method(
                        &wallet_config.wallet_key_derivation,
                    )?,

                    rekey: wallet_config.rekey.clone(),
                    rekey_derivation_method: wallet_config
                        .rekey_derivation_method
                        .as_deref()
                        .map(parse_key_derivation_method)
                        .transpose()?
                        .unwrap_or_else(default_key_derivation_method),

                    storage_credentials: wallet_config
                        .storage_credentials
                        .as_deref()
                        .map(serde_json::from_str)
                        .transpose()?,
                },
            )
            .await?;

        Ok(Box::new(IndySdkWallet {
            wallet_handle: handle,
        }))
    }

    async fn all(&self) -> VcxCoreResult<Box<dyn AllRecords>> {
        let all = Locator::instance()
            .wallet_controller
            .get_all(self.get_wallet_handle())
            .await?;

        Ok(Box::new(AllIndyRecords::new(all)))
    }
}

pub struct AllIndyRecords {
    iterator: WalletIterator,
}

impl AllIndyRecords {
    pub fn new(iterator: WalletIterator) -> Self {
        Self { iterator }
    }
}

#[async_trait]
impl AllRecords for AllIndyRecords {
    fn total_count(&self) -> VcxCoreResult<Option<usize>> {
        Ok(self.iterator.get_total_count()?)
    }

    async fn next(&mut self) -> VcxCoreResult<Option<PartialRecord>> {
        let item = self.iterator.next().await?;

        Ok(item.map(PartialRecord::from_wallet_record))
    }
}

fn parse_key_derivation_method(method: &str) -> VcxCoreResult<KeyDerivationMethod> {
    match method {
        "RAW" => Ok(KeyDerivationMethod::RAW),
        "ARGON2I_MOD" => Ok(KeyDerivationMethod::ARGON2I_MOD),
        "ARGON2I_INT" => Ok(KeyDerivationMethod::ARGON2I_INT),
        _ => Err(AriesVcxCoreError::from_msg(
            AriesVcxCoreErrorKind::InvalidOption,
            format!("Unknown derivation method {method}"),
        )),
    }
}

#[cfg(test)]
pub mod tests {
    use crate::wallet::base_wallet::wallet_config::WalletConfig;

    use super::IndySdkWallet;

    pub async fn dev_setup_indy_wallet() -> IndySdkWallet {
        use crate::wallet::indy::wallet::create_and_open_wallet;

        let config_wallet = WalletConfig {
            wallet_name: format!("wallet_{}", uuid::Uuid::new_v4()),
            wallet_key: "8dvfYSt5d1taSd6yJdpjq4emkwsPDDLYxkNFysFD2cZY".into(),
            wallet_key_derivation: "RAW".into(),
            wallet_type: None,
            storage_config: None,
            storage_credentials: None,
            rekey: None,
            rekey_derivation_method: None,
        };
        let wallet_handle = create_and_open_wallet(&config_wallet).await.unwrap();

        IndySdkWallet::new(wallet_handle)
    }
}
