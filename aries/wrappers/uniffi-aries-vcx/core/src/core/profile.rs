use std::sync::Arc;

use aries_vcx::{
    aries_vcx_core::{
        anoncreds::{base_anoncreds::BaseAnonCreds, credx_anoncreds::IndyCredxAnonCreds},
        ledger::{
            base_ledger::TxnAuthrAgrmtOptions,
            indy_vdr_ledger::{indyvdr_build_ledger_read, IndyVdrLedgerRead},
            request_submitter::vdr_ledger::{IndyVdrLedgerPool, IndyVdrSubmitter},
            response_cacher::in_memory::{InMemoryResponseCacher, InMemoryResponseCacherConfig},
        },
        wallet::{
            base_wallet::{BaseWallet, ManageWallet},
            indy::{wallet_config::WalletConfig, IndySdkWallet},
        },
        PoolConfig,
    },
    errors::error::{AriesVcxError, AriesVcxErrorKind, VcxResult},
};

use super::logging::enable_logging;
use crate::{errors::error::VcxUniFFIResult, runtime::block_on};

#[derive(Debug)]
pub struct UniffiProfile {
    wallet: Arc<dyn BaseWallet>,
    anoncreds: IndyCredxAnonCreds,
    ledger_read: IndyVdrLedgerRead<IndyVdrSubmitter, InMemoryResponseCacher>,
}

impl UniffiProfile {
    pub fn ledger_read(&self) -> &IndyVdrLedgerRead<IndyVdrSubmitter, InMemoryResponseCacher> {
        &self.ledger_read
    }

    pub fn anoncreds(&self) -> &IndyCredxAnonCreds {
        &self.anoncreds
    }

    pub fn wallet(&self) -> &Arc<dyn BaseWallet> {
        &self.wallet
    }

    pub fn update_taa_configuration(&self, _taa_options: TxnAuthrAgrmtOptions) -> VcxResult<()> {
        Err(AriesVcxError::from_msg(
            AriesVcxErrorKind::ActionNotSupported,
            "update_taa_configuration no implemented for VdrtoolsProfile",
        ))
    }
}

pub struct ProfileHolder {
    pub(crate) inner: UniffiProfile,
}

pub fn new_indy_profile(
    wallet_config: WalletConfig,
    genesis_file_path: String,
) -> VcxUniFFIResult<Arc<ProfileHolder>> {
    // Enable android logging
    enable_logging();

    block_on(async {
        wallet_config.create_wallet().await?;
        let wallet = wallet_config.open_wallet().await?;

        let anoncreds = IndyCredxAnonCreds;

        anoncreds
            .prover_create_link_secret(&wallet, "main")
            .await
            .ok();

        let indy_vdr_config = PoolConfig::default();
        let cache_config = InMemoryResponseCacherConfig::builder()
            .ttl(std::time::Duration::from_secs(60))
            .capacity(1000)?
            .build();
        let ledger_pool = IndyVdrLedgerPool::new(genesis_file_path, indy_vdr_config, vec![])?;
        let request_submitter = IndyVdrSubmitter::new(ledger_pool);
        let ledger_read = indyvdr_build_ledger_read(request_submitter.clone(), cache_config)?;
        let profile = UniffiProfile {
            anoncreds: IndyCredxAnonCreds,
            wallet,
            ledger_read,
        };

        Ok(Arc::new(ProfileHolder { inner: profile }))
    })
}
