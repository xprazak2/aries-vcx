use aries_vcx_core::wallet::{
    base_wallet::issuer_config::IssuerConfig, indy::wallet_config::WalletConfig,
};
use display_as_json::Display;
use serde::Serialize;

#[derive(Clone, Serialize, Display)]
pub struct AgentConfig {
    pub config_wallet: WalletConfig,
    pub config_issuer: IssuerConfig,
}
