use std::sync::Arc;

use async_trait::async_trait;
use indy_api_types::domain::wallet::{default_key_derivation_method, KeyDerivationMethod};
use serde::{Deserialize, Serialize};
use typed_builder::TypedBuilder;
use vdrtools::Locator;

use crate::{
    errors::error::{AriesVcxCoreError, AriesVcxCoreErrorKind, VcxCoreResult},
    wallet::{base_wallet::ManageWallet, indy::IndySdkWallet},
};

use super::BaseWallet;

#[derive(Clone, Debug, TypedBuilder, Serialize, Deserialize)]
#[builder(field_defaults(default))]
pub struct WalletConfig {
    pub wallet_name: String,
    pub wallet_key: String,
    pub wallet_key_derivation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(setter(strip_option))]
    pub wallet_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(setter(strip_option))]
    pub storage_config: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(setter(strip_option))]
    pub storage_credentials: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(setter(strip_option))]
    pub rekey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(setter(strip_option))]
    pub rekey_derivation_method: Option<String>,
}

#[async_trait]
impl ManageWallet for WalletConfig {
    // type Wallet = AnyWallet;

    async fn create_wallet(&self) -> VcxCoreResult<Arc<dyn BaseWallet>> {
        let handle = Locator::instance()
            .wallet_controller
            .open(
                vdrtools::types::domain::wallet::Config {
                    id: self.wallet_name.clone(),
                    storage_type: self.wallet_type.clone(),
                    storage_config: self
                        .storage_config
                        .as_deref()
                        .map(serde_json::from_str)
                        .transpose()?,
                    cache: None,
                },
                vdrtools::types::domain::wallet::Credentials {
                    key: self.wallet_key.clone(),
                    key_derivation_method: parse_key_derivation_method(
                        &self.wallet_key_derivation,
                    )?,

                    rekey: self.rekey.clone(),
                    rekey_derivation_method: self
                        .rekey_derivation_method
                        .as_deref()
                        .map(parse_key_derivation_method)
                        .transpose()?
                        .unwrap_or_else(default_key_derivation_method),

                    storage_credentials: self
                        .storage_credentials
                        .as_deref()
                        .map(serde_json::from_str)
                        .transpose()?,
                },
            )
            .await?;

        Ok(Arc::new(IndySdkWallet::new(handle)))
    }

    async fn open_wallet(&self) -> VcxCoreResult<Arc<dyn BaseWallet>> {
        let handle = Locator::instance()
            .wallet_controller
            .open(
                vdrtools::types::domain::wallet::Config {
                    id: self.wallet_name.clone(),
                    storage_type: self.wallet_type.clone(),
                    storage_config: self
                        .storage_config
                        .as_deref()
                        .map(serde_json::from_str)
                        .transpose()?,
                    cache: None,
                },
                vdrtools::types::domain::wallet::Credentials {
                    key: self.wallet_key.clone(),
                    key_derivation_method: parse_key_derivation_method(
                        &self.wallet_key_derivation,
                    )?,

                    rekey: self.rekey.clone(),
                    rekey_derivation_method: self
                        .rekey_derivation_method
                        .as_deref()
                        .map(parse_key_derivation_method)
                        .transpose()?
                        .unwrap_or_else(default_key_derivation_method),

                    storage_credentials: self
                        .storage_credentials
                        .as_deref()
                        .map(serde_json::from_str)
                        .transpose()?,
                },
            )
            .await?;

        Ok(Arc::new(IndySdkWallet::new(handle)))
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
