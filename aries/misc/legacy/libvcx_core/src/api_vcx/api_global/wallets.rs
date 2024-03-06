use std::{
    str::FromStr,
    sync::{Arc, RwLock},
};

use aries_vcx::{
    aries_vcx_core::{
        anoncreds::{base_anoncreds::BaseAnonCreds, credx_anoncreds::IndyCredxAnonCreds},
        wallet::structs_io::UnpackMessageOutput,
    },
    global::settings::DEFAULT_LINK_SECRET_ALIAS,
    protocols::mediated_connection::pairwise_info::PairwiseInfo,
};
use aries_vcx_core::{
    errors::error::{AriesVcxCoreError, AriesVcxCoreErrorKind},
    wallet::{
        base_wallet::{
            did_wallet::DidWallet, issuer_config::IssuerConfig, record::Record,
            record_category::RecordCategory, record_wallet::RecordWallet,
            search_filter::SearchFilter, BaseWallet, ManageWallet,
        },
        indy::indy_wallet_record::IndyWalletRecord,
        record_tags::RecordTags,
    },
};
use public_key::{Key, KeyType};

use crate::{
    api_vcx::api_global::profile::{
        get_main_anoncreds, get_main_ledger_write, get_main_wallet, try_get_main_wallet,
    },
    errors::{
        error::{LibvcxError, LibvcxErrorKind, LibvcxResult},
        mapping_from_ariesvcx::map_ariesvcx_result,
        mapping_from_ariesvcxcore::map_ariesvcx_core_result,
    },
};

#[cfg(feature = "vdrtools_wallet")]
use aries_vcx_core::wallet::indy::{
    indy_wallet_record::IndyWalletRecord, restore_wallet_configs::ImportWalletConfigs,
    wallet_config::WalletConfig, IndySdkWallet,
};

#[cfg(feature = "askar_wallet")]
use aries_vcx_core::wallet::askar::askar_import_config::AskarImportConfig;
#[cfg(feature = "askar_wallet")]
use aries_vcx_core::wallet::askar::AskarWallet;

#[cfg(feature = "askar_wallet")]
use aries_vcx_core::wallet::askar::askar_wallet_config::AskarWalletConfig;

#[cfg(feature = "vdrtools_wallet")]
pub static GLOBAL_INDY_WALLET: RwLock<Option<Arc<IndySdkWallet>>> = RwLock::new(None);

#[cfg(feature = "askar_wallet")]
pub static GLOBAL_ASKAR_WALLET: RwLock<Option<Arc<AskarWallet>>> = RwLock::new(None);

pub static GLOBAL_BASE_ANONCREDS: RwLock<Option<Arc<IndyCredxAnonCreds>>> = RwLock::new(None);

pub async fn export_main_wallet(path: &str, backup_key: &str) -> LibvcxResult<()> {
    let main_wallet = get_main_wallet()?;
    map_ariesvcx_core_result(main_wallet.as_ref().export_wallet(path, backup_key).await)
}

#[cfg(all(feature = "vdrtools_wallet", feature = "askar_wallet"))]
compile_error!("features `vdrtools_wallet` and `askar_wallet` are mutually exclusive");

#[cfg(feature = "vdrtools_wallet")]
fn setup_global_wallet(wallet: Arc<IndySdkWallet>) -> LibvcxResult<()> {
    let mut b_wallet = GLOBAL_INDY_WALLET.write()?;
    *b_wallet = Some(wallet);

    setup_global_anoncreds()
}

#[cfg(feature = "askar_wallet")]
fn setup_global_wallet(wallet: Arc<AskarWallet>) -> LibvcxResult<()> {
    let mut b_wallet = GLOBAL_ASKAR_WALLET.write()?;
    *b_wallet = Some(wallet);

    setup_global_anoncreds()
}

fn setup_global_anoncreds() -> LibvcxResult<()> {
    let base_anoncreds_impl = Arc::new(IndyCredxAnonCreds);
    let mut b_anoncreds = GLOBAL_BASE_ANONCREDS.write()?;
    *b_anoncreds = Some(base_anoncreds_impl);
    Ok(())
}

#[cfg(feature = "vdrtools_wallet")]
pub async fn open_as_main_wallet(wallet_config: &WalletConfig) -> LibvcxResult<Arc<IndySdkWallet>> {
    let wallet = Arc::new(wallet_config.open_wallet().await?);
    setup_global_wallet(wallet.clone())?;
    Ok(wallet)
}

#[cfg(feature = "askar_wallet")]
pub async fn open_as_main_wallet(
    wallet_config: &AskarWalletConfig,
) -> LibvcxResult<Arc<impl BaseWallet>> {
    let wallet = Arc::new(wallet_config.open_wallet().await?);
    setup_global_wallet(wallet.clone())?;
    Ok(wallet)
}

#[cfg(feature = "vdrtools_wallet")]
pub async fn create_and_open_as_main_wallet(
    wallet_config: &WalletConfig,
) -> LibvcxResult<Arc<impl BaseWallet>> {
    let wallet = Arc::new(wallet_config.create_wallet().await?);

    setup_global_wallet(wallet.clone())?;
    Ok(wallet)
}

#[cfg(feature = "askar_wallet")]
pub async fn create_and_open_as_main_wallet(
    wallet_config: &AskarWalletConfig,
) -> LibvcxResult<Arc<impl BaseWallet>> {
    let wallet = Arc::new(wallet_config.create_wallet().await?);

    setup_global_wallet(wallet.clone())?;
    Ok(wallet)
}

#[cfg(feature = "vdrtools_wallet")]
pub async fn close_main_wallet() -> LibvcxResult<()> {
    let wallet = try_get_main_wallet()?;
    match wallet {
        None => {
            warn!("Skipping wallet close, no global wallet component available.")
        }
        Some(wallet) => {
            wallet.close_wallet().await?;
            let mut b_wallet = GLOBAL_INDY_WALLET.write()?;
            *b_wallet = None;
        }
    }
    Ok(())
}

#[cfg(feature = "askar_wallet")]
pub async fn close_main_wallet() -> LibvcxResult<()> {
    let wallet = try_get_main_wallet()?;
    match wallet {
        None => {
            warn!("Skipping wallet close, no global wallet component available.")
        }
        Some(wallet) => {
            wallet.close_wallet().await?;
            let mut b_wallet = GLOBAL_ASKAR_WALLET.write()?;
            *b_wallet = None;
        }
    }
    Ok(())
}

#[cfg(feature = "vdrtools_wallet")]
pub async fn create_main_wallet(config: &WalletConfig) -> LibvcxResult<()> {
    let wallet = create_and_open_as_main_wallet(&config).await?;
    trace!("Created wallet {:?}", wallet);
    let wallet = get_main_wallet()?;

    // If MS is already in wallet then just continue
    get_main_anoncreds()?
        .prover_create_link_secret(wallet.as_ref(), &DEFAULT_LINK_SECRET_ALIAS.to_string())
        .await
        .ok();

    close_main_wallet().await?;
    Ok(())
}

#[cfg(feature = "askar_wallet")]
pub async fn create_main_wallet(config: &AskarWalletConfig) -> LibvcxResult<()> {
    let wallet = create_and_open_as_main_wallet(config).await?;
    trace!("Created wallet {:?}", wallet);
    let wallet = get_main_wallet()?;

    // If MS is already in wallet then just continue
    get_main_anoncreds()?
        .prover_create_link_secret(wallet.as_ref(), &DEFAULT_LINK_SECRET_ALIAS.to_string())
        .await
        .ok();

    close_main_wallet().await?;
    Ok(())
}

pub async fn key_for_local_did(did: &str) -> LibvcxResult<String> {
    let wallet = get_main_wallet()?;

    map_ariesvcx_core_result(wallet.key_for_did(did).await.map(|key| key.base58()))
}

pub async fn wallet_sign(vk: &str, data_raw: &[u8]) -> LibvcxResult<Vec<u8>> {
    let wallet = get_main_wallet()?;

    let verkey = Key::from_base58(vk, KeyType::Ed25519)?;
    map_ariesvcx_core_result(wallet.sign(&verkey, data_raw).await)
}

pub async fn wallet_verify(vk: &str, msg: &[u8], signature: &[u8]) -> LibvcxResult<bool> {
    let wallet = get_main_wallet()?;

    let verkey = Key::from_base58(vk, KeyType::Ed25519)?;
    map_ariesvcx_core_result(wallet.verify(&verkey, msg, signature).await)
}

pub async fn replace_did_keys_start(did: &str) -> LibvcxResult<String> {
    let wallet = get_main_wallet()?;

    map_ariesvcx_core_result(
        wallet
            .replace_did_key_start(did, None)
            .await
            .map(|key| key.base58()),
    )
}

pub async fn rotate_verkey_apply(did: &str, temp_vk: &str) -> LibvcxResult<()> {
    let wallet = get_main_wallet()?;
    map_ariesvcx_result(
        aries_vcx::common::keys::rotate_verkey_apply(
            wallet.as_ref(),
            get_main_ledger_write()?.as_ref(),
            &did.parse()?,
            temp_vk,
        )
        .await,
    )
}

pub async fn wallet_unpack_message(payload: &[u8]) -> LibvcxResult<UnpackMessageOutput> {
    let wallet = get_main_wallet()?;
    map_ariesvcx_core_result(wallet.unpack_message(payload).await)
}

pub async fn wallet_create_and_store_did(seed: Option<&str>) -> LibvcxResult<PairwiseInfo> {
    let wallet = get_main_wallet()?;
    let did_data = wallet.create_and_store_my_did(seed, None).await?;
    Ok(PairwiseInfo {
        pw_did: did_data.did().into(),
        pw_vk: did_data.verkey().base58(),
    })
}

pub async fn wallet_configure_issuer(enterprise_seed: &str) -> LibvcxResult<IssuerConfig> {
    let wallet = get_main_wallet()?;
    map_ariesvcx_core_result(wallet.configure_issuer(enterprise_seed).await)
}

pub async fn wallet_add_wallet_record(
    type_: &str,
    id: &str,
    value: &str,
    option: Option<&str>,
) -> LibvcxResult<()> {
    let wallet = get_main_wallet()?;
    let tags: Option<RecordTags> = option.map(serde_json::from_str).transpose()?;

    let record = if let Some(record_tags) = tags {
        Record::builder()
            .name(id.into())
            .category(RecordCategory::from_str(type_)?)
            .value(value.into())
            .tags(record_tags)
            .build()
    } else {
        Record::builder()
            .name(id.into())
            .category(RecordCategory::from_str(type_)?)
            .value(value.into())
            .build()
    };

    map_ariesvcx_core_result(wallet.add_record(record).await)
}

pub async fn wallet_update_wallet_record_value(
    xtype: &str,
    id: &str,
    value: &str,
) -> LibvcxResult<()> {
    let wallet = get_main_wallet()?;
    map_ariesvcx_core_result(
        wallet
            .update_record_value(RecordCategory::from_str(xtype)?, id, value)
            .await,
    )
}

pub async fn wallet_update_wallet_record_tags(
    xtype: &str,
    id: &str,
    tags_json: &str,
) -> LibvcxResult<()> {
    let wallet = get_main_wallet()?;
    let tags: RecordTags = serde_json::from_str(tags_json)?;
    map_ariesvcx_core_result(
        wallet
            .update_record_tags(RecordCategory::from_str(xtype)?, id, tags)
            .await,
    )
}

pub async fn wallet_add_wallet_record_tags(
    xtype: &str,
    id: &str,
    tags_json: &str,
) -> LibvcxResult<()> {
    let wallet = get_main_wallet()?;
    let record = wallet
        .get_record(RecordCategory::from_str(xtype)?, id)
        .await?;

    let tags = {
        let mut tags: RecordTags = serde_json::from_str(tags_json)?;
        tags.merge(record.tags().clone());
        tags
    };

    map_ariesvcx_core_result(
        wallet
            .update_record_tags(RecordCategory::from_str(xtype)?, id, tags)
            .await,
    )
}

pub async fn wallet_delete_wallet_record_tags(
    xtype: &str,
    id: &str,
    tags_json: &str,
) -> LibvcxResult<()> {
    let wallet = get_main_wallet()?;
    let tags: RecordTags = serde_json::from_str(tags_json)?;

    let record = wallet
        .get_record(RecordCategory::from_str(xtype)?, id)
        .await?;

    let mut found_tags = record.tags().clone();
    for key in tags {
        found_tags.remove(key);
    }

    map_ariesvcx_core_result(
        wallet
            .update_record_tags(RecordCategory::from_str(xtype)?, id, found_tags)
            .await,
    )
}

pub async fn wallet_get_wallet_record(
    xtype: &str,
    id: &str,
    _options: &str,
) -> LibvcxResult<String> {
    let wallet = get_main_wallet()?;

    map_ariesvcx_result(
        wallet
            .get_record(RecordCategory::from_str(xtype)?, id)
            .await
            .map(|res| {
                let wallet_record = IndyWalletRecord::from_record(res)?;

                Ok(serde_json::to_string(&wallet_record)?)
            })?,
    )
}

pub async fn wallet_delete_wallet_record(xtype: &str, id: &str) -> LibvcxResult<()> {
    let wallet = get_main_wallet()?;
    map_ariesvcx_core_result(
        wallet
            .delete_record(RecordCategory::from_str(xtype)?, id)
            .await,
    )
}

pub async fn wallet_search_records(xtype: &str, query_json: &str) -> LibvcxResult<String> {
    let wallet = get_main_wallet()?;
    let records = wallet
        .search_record(
            RecordCategory::from_str(xtype)?,
            Some(SearchFilter::JsonFilter(query_json.into())),
        )
        .await?;

    let indy_records = records
        .into_iter()
        .map(IndyWalletRecord::from_record)
        .collect::<Result<Vec<_>, _>>()?;

    let res = serde_json::to_string(&indy_records)
        .map_err(|err| AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::InvalidJson, err));

    map_ariesvcx_core_result(res)
}

#[cfg(feature = "vdrtools_wallet")]
pub async fn wallet_import(config: &ImportWalletConfigs) -> LibvcxResult<()> {
    map_ariesvcx_core_result(config.import_wallet().await)
}

#[cfg(feature = "askar_wallet")]
pub async fn wallet_import(config: &AskarImportConfig) -> LibvcxResult<()> {
    map_ariesvcx_core_result(config.import_wallet().await)
}

#[cfg(feature = "vdrtools_wallet")]
pub async fn wallet_migrate(wallet_config: &WalletConfig) -> LibvcxResult<()> {
    let src_wallet = get_main_wallet()?;
    info!("Opening target wallet.");
    let dest_wallet = wallet_config.create_wallet().await?;

    let migration_res = wallet_migrator::migrate_wallet(
        src_wallet.as_ref(),
        &dest_wallet,
        wallet_migrator::vdrtools2credx::migrate_any_record,
    )
    .await;

    migration_res.map_err(|e| LibvcxError::from_msg(LibvcxErrorKind::WalletMigrationFailed, e))
}

#[cfg(feature = "askar_wallet")]
pub async fn wallet_migrate(wallet_config: &impl ManageWallet) -> LibvcxResult<()> {
    let src_wallet = get_main_wallet()?;
    info!("Opening target wallet.");
    let dest_wallet = wallet_config.create_wallet().await?;

    let migration_res = wallet_migrator::migrate_wallet(
        src_wallet.as_ref(),
        &dest_wallet,
        wallet_migrator::vdrtools2credx::migrate_any_record,
    )
    .await;

    migration_res.map_err(|e| LibvcxError::from_msg(LibvcxErrorKind::WalletMigrationFailed, e))
}

#[cfg(test)]
pub mod test_utils {
    use ::test_utils::devsetup::TempFile;
    use aries_vcx::global::settings::{
        DEFAULT_WALLET_BACKUP_KEY, DEFAULT_WALLET_KEY, WALLET_KDF_RAW,
    };
    use aries_vcx_core::wallet::{
        askar::{askar_wallet_config::AskarWalletConfig, key_method::KeyMethod},
        base_wallet::{
            did_wallet::DidWallet, record::Record, record_category::RecordCategory,
            record_wallet::RecordWallet, BaseWallet, ManageWallet,
        },
        indy::wallet_config::WalletConfig,
    };
    use uuid::Uuid;

    use crate::{
        api_vcx::api_global::{
            profile::get_main_wallet,
            wallets::{
                close_main_wallet, create_and_open_as_main_wallet, create_main_wallet,
                export_main_wallet, open_as_main_wallet,
            },
        },
        errors::error::LibvcxResult,
    };

    #[cfg(feature = "vdrtools_wallet")]
    pub async fn _create_main_wallet_and_its_backup() -> (TempFile, String, WalletConfig) {
        let wallet_config = WalletConfig {
            wallet_name: wallet_name.into(),
            wallet_key: DEFAULT_WALLET_KEY.into(),
            wallet_key_derivation: WALLET_KDF_RAW.into(),
            wallet_type: None,
            storage_config: None,
            storage_credentials: None,
            rekey: None,
            rekey_derivation_method: None,
        };
        let wallet = create_and_open_as_main_wallet(&wallet_config)
            .await
            .unwrap();
        // // let wallet = get_main_wallet().unwrap();
        // wallet.create_and_store_my_did(None, None).await.unwrap();

        // let new_record = Record::builder()
        //     .name("id1".to_owned())
        //     .category(RecordCategory::default())
        //     .value("value1".to_owned())
        //     .build();

        // wallet.add_record(new_record).await.unwrap();
        // export_main_wallet(&export_file.path, DEFAULT_WALLET_BACKUP_KEY)
        //     .await
        //     .unwrap();

        // close_main_wallet().await.unwrap();

        setup_wallet_backup(&wallet_config).await;

        // todo: import and verify
        (export_file, wallet_name.to_string(), wallet_config)
    }

    #[cfg(feature = "askar_wallet")]
    pub async fn _create_main_wallet_and_its_backup() -> (TempFile, String, AskarWalletConfig) {
        let wallet_config = AskarWalletConfig::new(
            "sqlite://:memory:",
            KeyMethod::Unprotected,
            "",
            &Uuid::new_v4().to_string(),
        );

        let wallet_name = &format!("export_test_wallet_{}", uuid::Uuid::new_v4());

        let export_file = TempFile::prepare_path(wallet_name);

        let wallet = create_and_open_as_main_wallet(&wallet_config)
            .await
            .unwrap();
        // let wallet = get_main_wallet().unwrap();
        // wallet.create_and_store_my_did(None, None).await.unwrap();

        // let new_record = Record::builder()
        //     .name("id1".to_owned())
        //     .category(RecordCategory::default())
        //     .value("value1".to_owned())
        //     .build();

        // wallet.add_record(new_record).await.unwrap();
        // export_main_wallet(&export_file.path, DEFAULT_WALLET_BACKUP_KEY)
        //     .await
        //     .unwrap();

        // close_main_wallet().await.unwrap();

        setup_wallet_backup(wallet.as_ref(), &export_file).await;

        // todo: import and verify
        (export_file, wallet_name.to_string(), wallet_config)
    }

    async fn setup_wallet_backup(wallet: &impl BaseWallet, export_file: &TempFile) {
        wallet.create_and_store_my_did(None, None).await.unwrap();

        let new_record = Record::builder()
            .name("id1".to_owned())
            .category(RecordCategory::default())
            .value("value1".to_owned())
            .build();

        wallet.add_record(new_record).await.unwrap();
        export_main_wallet(&export_file.path, DEFAULT_WALLET_BACKUP_KEY)
            .await
            .unwrap();

        close_main_wallet().await.unwrap();
    }

    // pub async fn _create_wallet() -> LibvcxResult<WalletConfig> {
    //     let wallet_name = format!("test_create_wallet_{}", uuid::Uuid::new_v4());
    //     let config_wallet: WalletConfig = serde_json::from_value(json!({
    //         "wallet_name": wallet_name,
    //         "wallet_key": DEFAULT_WALLET_KEY,
    //         "wallet_key_derivation": WALLET_KDF_RAW
    //     }))?;
    //     create_main_wallet(&config_wallet).await?;
    //     Ok(config_wallet)
    // }

    #[cfg(feature = "vdrtools_wallet")]
    pub async fn _create_and_open_wallet() -> LibvcxResult<WalletConfig> {
        // let config_wallet = _create_wallet().await?;
        let wallet_name = format!("test_create_wallet_{}", uuid::Uuid::new_v4());
        let config_wallet: WalletConfig = serde_json::from_value(json!({
            "wallet_name": wallet_name,
            "wallet_key": DEFAULT_WALLET_KEY,
            "wallet_key_derivation": WALLET_KDF_RAW
        }))?;
        create_main_wallet(&config_wallet).await?;

        open_as_main_wallet(&config_wallet).await?;
        Ok(config_wallet)
    }

    #[cfg(feature = "askar_wallet")]
    pub async fn _create_and_open_wallet() -> LibvcxResult<AskarWalletConfig> {
        // let config_wallet = _create_wallet().await?;
        let config_wallet: AskarWalletConfig = AskarWalletConfig::new(
            "sqlite://:memory:",
            KeyMethod::Unprotected,
            "",
            &Uuid::new_v4().to_string(),
        );
        create_main_wallet(&config_wallet).await?;
        open_as_main_wallet(&config_wallet).await?;
        Ok(config_wallet)
    }
}

#[cfg(test)]
mod tests {
    use aries_vcx::{
        aries_vcx_core::wallet::indy::restore_wallet_configs::ImportWalletConfigs,
        global::settings::{DEFAULT_WALLET_BACKUP_KEY, DEFAULT_WALLET_KEY, WALLET_KDF_RAW},
    };
    use aries_vcx_core::wallet::{
        base_wallet::{record_category::RecordCategory, ManageWallet},
        indy::{indy_wallet_record::IndyWalletRecord, wallet_config::WalletConfig},
    };
    use test_utils::devsetup::{SetupMocks, TempFile};

    use crate::{
        api_vcx::api_global::wallets::{
            close_main_wallet, create_and_open_as_main_wallet, create_main_wallet,
            export_main_wallet, open_as_main_wallet,
            test_utils::{_create_and_open_wallet, _create_main_wallet_and_its_backup},
            wallet_add_wallet_record, wallet_delete_wallet_record, wallet_get_wallet_record,
            wallet_import, wallet_update_wallet_record_value,
        },
        errors::error::{LibvcxErrorKind, LibvcxResult},
    };

    #[cfg(feature = "vdrtools_wallet")]
    #[tokio::test]
    async fn test_wallet_migrate() {
        let wallet_name = format!("test_create_wallet_{}", uuid::Uuid::new_v4());
        let config: WalletConfig = serde_json::from_value(json!({
            "wallet_name": wallet_name,
            "wallet_key": DEFAULT_WALLET_KEY,
            "wallet_key_derivation": WALLET_KDF_RAW
        }))
        .unwrap();

        create_and_open_as_main_wallet(&config).await.unwrap();

        let wallet_name = format!("test_migrate_wallet_{}", uuid::Uuid::new_v4());
        let new_config: WalletConfig = serde_json::from_value(json!({
            "wallet_name": wallet_name,
            "wallet_key": DEFAULT_WALLET_KEY,
            "wallet_key_derivation": WALLET_KDF_RAW
        }))
        .unwrap();

        super::wallet_migrate(&new_config).await.unwrap();
    }

    #[cfg(feature = "askar_wallet")]
    #[tokio::test]
    async fn test_wallet_migrate() {
        use aries_vcx_core::wallet::askar::askar_wallet_config::AskarWalletConfig;
        use aries_vcx_core::wallet::askar::key_method::KeyMethod;
        use uuid::Uuid;

        let config = AskarWalletConfig::new(
            "sqlite://:memory:",
            KeyMethod::Unprotected,
            "",
            &Uuid::new_v4().to_string(),
        );

        create_and_open_as_main_wallet(&config).await.unwrap();

        let new_config = AskarWalletConfig::new(
            "sqlite://:memory:",
            KeyMethod::Unprotected,
            "",
            &Uuid::new_v4().to_string(),
        );

        wallets::wallet_migrate(&new_config).await.unwrap();
    }

    #[cfg(feature = "vdrtools_wallet")]
    #[tokio::test]
    async fn test_wallet_create() {
        let _setup = SetupMocks::init();

        let wallet_name = format!("test_create_wallet_{}", uuid::Uuid::new_v4());
        let config: WalletConfig = serde_json::from_value(json!({
            "wallet_name": wallet_name,
            "wallet_key": DEFAULT_WALLET_KEY,
            "wallet_key_derivation": WALLET_KDF_RAW
        }))
        .unwrap();

        create_main_wallet(&config).await.unwrap();
    }

    #[cfg(feature = "askar_wallet")]
    #[tokio::test]
    async fn test_wallet_create() {
        use aries_vcx_core::wallet::askar::askar_wallet_config::AskarWalletConfig;
        use aries_vcx_core::wallet::askar::key_method::KeyMethod;
        use uuid::Uuid;

        let _setup = SetupMocks::init();

        let config = AskarWalletConfig::new(
            "sqlite://:memory:",
            KeyMethod::Unprotected,
            "",
            &Uuid::new_v4().to_string(),
        );

        create_main_wallet(&config).await.unwrap();
    }

    #[tokio::test]
    async fn test_wallet_record_add_with_tag() {
        _create_and_open_wallet().await.unwrap();

        let xtype = RecordCategory::default().to_string();
        let id = "123".to_string();
        let value = "Record Value".to_string();
        let tags = r#"{"tagName1":"tag1","tagName2":"tag2"}"#.to_string();

        wallet_add_wallet_record(&xtype, &id, &value, Some(&tags))
            .await
            .unwrap();
        close_main_wallet().await.unwrap();
    }

    #[tokio::test]
    async fn test_wallet_record_add_with_no_tag() {
        _create_and_open_wallet().await.unwrap();

        let xtype = RecordCategory::default().to_string();
        let id = "123".to_string();
        let value = "Record Value".to_string();

        wallet_add_wallet_record(&xtype, &id, &value, None)
            .await
            .unwrap();
        close_main_wallet().await.unwrap();
    }

    #[tokio::test]
    async fn test_wallet_record_add_fails_with_duplication_error() {
        _create_and_open_wallet().await.unwrap();

        let xtype = RecordCategory::default().to_string();
        let id = "123".to_string();
        let value = "Record Value".to_string();

        wallet_add_wallet_record(&xtype, &id, &value, None)
            .await
            .unwrap();
        let err = wallet_add_wallet_record(&xtype, &id, &value, None)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), LibvcxErrorKind::DuplicationWalletRecord);
        close_main_wallet().await.unwrap();
    }

    #[tokio::test]
    async fn test_wallet_record_get_fails_if_record_does_not_exist() {
        _create_and_open_wallet().await.unwrap();

        let xtype = RecordCategory::default().to_string();
        let id = "123".to_string();
        let options = json!({
            "retrieveType": true,
            "retrieveValue": true,
            "retrieveTags": false
        })
        .to_string();
        let _err = wallet_get_wallet_record(&xtype, &id, &options)
            .await
            .unwrap_err();
        // copilot demo: example
        close_main_wallet().await.unwrap();
    }

    async fn _add_and_get_wallet_record() -> LibvcxResult<()> {
        let xtype = RecordCategory::default().to_string();
        let id = "123".to_string();
        let value = "Record Value".to_string();
        let tags = r#"{"tagName1":"tag1","tagName2":"tag2"}"#.to_string();

        wallet_add_wallet_record(&xtype, &id, &value, Some(&tags)).await?;

        let options = json!({
            "retrieveType": true,
            "retrieveValue": true,
            "retrieveTags": true
        })
        .to_string();

        let record = wallet_get_wallet_record(&xtype, &id, &options).await?;
        let record: IndyWalletRecord = serde_json::from_str(&record)?;
        assert_eq!(record.value.unwrap(), value);
        Ok(())
    }

    #[tokio::test]
    async fn test_wallet_record_delete() {
        _create_and_open_wallet().await.unwrap();

        let xtype = RecordCategory::default().to_string();
        let id = "123".to_string();
        let value = "Record Value".to_string();

        wallet_add_wallet_record(&xtype, &id, &value, None)
            .await
            .unwrap();
        wallet_delete_wallet_record(&xtype, &id).await.unwrap();
        let err = wallet_delete_wallet_record(&xtype, &id).await.unwrap_err();
        assert_eq!(err.kind(), LibvcxErrorKind::WalletRecordNotFound);
        let err = wallet_get_wallet_record(&xtype, &id, "{}")
            .await
            .unwrap_err();
        assert_eq!(err.kind(), LibvcxErrorKind::WalletRecordNotFound);
    }

    #[cfg(feature = "vdrtools_wallet")]
    #[tokio::test]
    async fn test_wallet_export_import() {
        let _setup = SetupMocks::init();
        let wallet_name = uuid::Uuid::new_v4().to_string();
        let export_file = TempFile::prepare_path(&wallet_name);
        let wallet_config = WalletConfig {
            wallet_name,
            wallet_key: DEFAULT_WALLET_KEY.into(),
            wallet_key_derivation: WALLET_KDF_RAW.into(),
            wallet_type: None,
            storage_config: None,
            storage_credentials: None,
            rekey: None,
            rekey_derivation_method: None,
        };
        create_and_open_as_main_wallet(&wallet_config)
            .await
            .unwrap();
        let backup_key = DEFAULT_WALLET_BACKUP_KEY;
        export_main_wallet(&export_file.path.to_string(), backup_key)
            .await
            .unwrap();
        close_main_wallet().await.unwrap();
        wallet_config.delete_wallet().await.unwrap();
        let import_config: ImportWalletConfigs = serde_json::from_value(json!({
            "wallet_name": wallet_config.wallet_name.clone(),
            "wallet_key": wallet_config.wallet_key.clone(),
            "exported_wallet_path": export_file.path,
            "backup_key": backup_key,
            "wallet_key_derivation": WALLET_KDF_RAW
        }))
        .unwrap();
        wallet_import(&import_config).await.unwrap();
        wallet_config.delete_wallet().await.unwrap();
    }

    #[cfg(feature = "vdrtools_wallet")]
    #[tokio::test]
    async fn test_wallet_open_with_incorrect_key_fails() {
        let _setup = SetupMocks::init();
        let wallet_name = uuid::Uuid::new_v4().to_string();
        let _export_file = TempFile::prepare_path(&wallet_name);
        let mut wallet_config = WalletConfig {
            wallet_name,
            wallet_key: DEFAULT_WALLET_KEY.into(),
            wallet_key_derivation: WALLET_KDF_RAW.into(),
            wallet_type: None,
            storage_config: None,
            storage_credentials: None,
            rekey: None,
            rekey_derivation_method: None,
        };
        create_and_open_as_main_wallet(&wallet_config)
            .await
            .unwrap();
        close_main_wallet().await.unwrap();
        wallet_config.wallet_key = "8dvfYSt5d1taSd6yJdpjq4emkwsPDDLYxkNFysFA2cAA".to_string();
        let err = open_as_main_wallet(&wallet_config).await.unwrap_err();
        assert_eq!(err.kind(), LibvcxErrorKind::WalletAccessFailed);
    }

    #[cfg(feature = "vdrtools_wallet")]
    #[tokio::test]
    async fn test_wallet_open_with_wrong_name_fails() {
        let _setup = SetupMocks::init();

        let wallet_config: WalletConfig = serde_json::from_value(json!({
            "wallet_name": "different_wallet_name",
            "wallet_key": DEFAULT_WALLET_KEY,
            "wallet_key_derivation": WALLET_KDF_RAW,
        }))
        .unwrap();

        assert_eq!(
            open_as_main_wallet(&wallet_config)
                .await
                .unwrap_err()
                .kind(),
            LibvcxErrorKind::WalletNotFound
        )
    }

    #[cfg(feature = "vdrtools_wallet")]
    #[tokio::test]
    async fn test_wallet_open_of_imported_wallet_succeeds() {
        let _setup = SetupMocks::init();

        let (export_wallet_path, wallet_name, wallet_config) =
            _create_main_wallet_and_its_backup().await;

        wallet_config.delete_wallet().await.unwrap();

        let import_config = ImportWalletConfigs {
            wallet_name: wallet_name.clone(),
            wallet_key: DEFAULT_WALLET_KEY.into(),
            exported_wallet_path: export_wallet_path.path.clone(),
            backup_key: DEFAULT_WALLET_BACKUP_KEY.to_string(),
            wallet_key_derivation: Some(WALLET_KDF_RAW.into()),
        };
        wallet_import(&import_config).await.unwrap();

        let wallet_config: WalletConfig = serde_json::from_value(json!({
            "wallet_name": &wallet_name,
            "wallet_key": DEFAULT_WALLET_KEY,
            "wallet_key_derivation": WALLET_KDF_RAW,
        }))
        .unwrap();

        open_as_main_wallet(&wallet_config).await.unwrap();
    }

    #[cfg(feature = "vdrtools_wallet")]
    #[tokio::test]
    async fn test_wallet_import_of_opened_wallet_fails() {
        let _setup = SetupMocks::init();

        let (export_wallet_path, wallet_name, wallet_config) =
            _create_main_wallet_and_its_backup().await;

        open_as_main_wallet(&wallet_config).await.unwrap();

        let import_config = ImportWalletConfigs {
            wallet_name,
            wallet_key: DEFAULT_WALLET_KEY.into(),
            exported_wallet_path: export_wallet_path.path.clone(),
            backup_key: DEFAULT_WALLET_BACKUP_KEY.to_string(),
            wallet_key_derivation: None,
        };
        assert_eq!(
            wallet_import(&import_config).await.unwrap_err().kind(),
            LibvcxErrorKind::DuplicationWallet
        )
    }

    #[tokio::test]
    async fn test_wallet_record_update() {
        _create_and_open_wallet().await.unwrap();

        let xtype = RecordCategory::default().to_string();
        let id = "123".to_string();
        let value = "Record Value".to_string();
        let new_value = "New Record Value".to_string();

        let err = wallet_update_wallet_record_value(&xtype, &id, &new_value)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), LibvcxErrorKind::WalletRecordNotFound);
        wallet_add_wallet_record(&xtype, &id, &value, None)
            .await
            .unwrap();
        wallet_update_wallet_record_value(&xtype, &id, &new_value)
            .await
            .unwrap();
        let record = wallet_get_wallet_record(&xtype, &id, "{}").await.unwrap();
        let record: IndyWalletRecord = serde_json::from_str(&record).unwrap();
        assert_eq!(record.value.unwrap(), new_value);
    }
}
