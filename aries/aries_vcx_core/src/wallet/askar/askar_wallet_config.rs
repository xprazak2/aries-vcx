use std::sync::Arc;

use async_trait::async_trait;
use serde::Deserialize;

use super::{key_method::KeyMethod, AskarWallet};
use crate::{
    errors::error::VcxCoreResult,
    wallet::base_wallet::{BaseWallet, ManageWallet},
};

#[derive(Clone, Debug, Deserialize)]
pub struct AskarWalletConfig {
    db_url: String,
    key_method: KeyMethod,
    pass_key: String,
    profile: String,
}

impl AskarWalletConfig {
    pub fn new(db_url: &str, key_method: KeyMethod, pass_key: &str, profile: &str) -> Self {
        Self {
            db_url: db_url.into(),
            key_method,
            pass_key: pass_key.into(),
            profile: profile.into(),
        }
    }

    pub fn db_url(&self) -> &str {
        &self.db_url
    }

    pub fn key_method(&self) -> &KeyMethod {
        &self.key_method
    }

    pub fn pass_key(&self) -> &str {
        &self.pass_key
    }

    pub fn profile(&self) -> &str {
        &self.profile
    }
}

#[async_trait]
impl ManageWallet for AskarWalletConfig {
    async fn create_wallet(&self) -> VcxCoreResult<Arc<dyn BaseWallet>> {
        let askar_wallet = AskarWallet::create(self, false).await?;
        Ok(Arc::new(askar_wallet))
    }

    async fn open_wallet(&self) -> VcxCoreResult<Arc<dyn BaseWallet>> {
        Ok(Arc::new(AskarWallet::open(self).await?))
    }

    async fn delete_wallet(&self) -> VcxCoreResult<()> {
        todo!();
    }
}
