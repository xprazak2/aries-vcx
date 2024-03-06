use aries_vcx::aries_vcx_core::wallet::indy::{wallet_config::IndyWalletConfig, IndySdkWallet};

use aries_vcx::aries_vcx_core::{
    anoncreds::{base_anoncreds::BaseAnonCreds, credx_anoncreds::IndyCredxAnonCreds},
    ledger::{
        indy_vdr_ledger::{indyvdr_build_ledger_read, IndyVdrLedgerRead},
        request_submitter::vdr_ledger::{IndyVdrLedgerPool, IndyVdrSubmitter},
        response_cacher::in_memory::{InMemoryResponseCacher, InMemoryResponseCacherConfig},
    },
    PoolConfig,
};

use crate::core::logging::enable_logging;
use crate::{errors::error::VcxUniFFIResult, runtime::block_on};

use crate::ProfileHolder;
use std::sync::Arc;

use aries_vcx::aries_vcx_core::wallet::base_wallet::ManageWallet;

#[derive(Debug)]
pub struct UniffiProfile {
    pub wallet: IndySdkWallet,
    pub anoncreds: IndyCredxAnonCreds,
    pub ledger_read: IndyVdrLedgerRead<IndyVdrSubmitter, InMemoryResponseCacher>,
}

pub fn new_indy_profile(
    wallet_config: IndyWalletConfig,
    genesis_file_path: String,
) -> VcxUniFFIResult<Arc<ProfileHolder>> {
    // Enable android logging
    enable_logging();

    block_on(async {
        let wallet = wallet_config.create_wallet().await?;

        let anoncreds = IndyCredxAnonCreds;

        anoncreds
            .prover_create_link_secret(&wallet, &"main".to_string())
            .await
            .ok();

        let indy_vdr_config = PoolConfig::default();
        let cache_config = InMemoryResponseCacherConfig::builder()
            .ttl(std::time::Duration::from_secs(60))
            .capacity(1000)?
            .build();
        let ledger_pool = IndyVdrLedgerPool::new(genesis_file_path, indy_vdr_config, vec![])?;
        let request_submitter = IndyVdrSubmitter::new(ledger_pool);
        let ledger_read = indyvdr_build_ledger_read(request_submitter, cache_config)?;
        let profile = UniffiProfile {
            anoncreds: IndyCredxAnonCreds,
            wallet,
            ledger_read,
        };

        Ok(Arc::new(ProfileHolder { inner: profile }))
    })
}
