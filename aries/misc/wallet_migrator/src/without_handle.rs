use std::collections::HashMap;

use aries_vcx_core::errors::error::AriesVcxCoreErrorKind;
use aries_vcx_core::wallet::indy::WalletRecord;
use aries_vcx_core::wallet2::{
    constants::{DID_CATEGORY, TMP_DID_CATEGORY},
    BaseWallet2, Record,
};
use log::{debug, error, info, trace, warn};

use vdrtools::indy_wallet::{MigrationResult as IndyMigrationResult, WalletIterator};
use vdrtools::{Locator, WalletHandle};

use crate::error::MigrationResult;
use crate::vdrtools2credx::{
    INDY_CRED, INDY_CRED_DEF, INDY_CRED_DEF_CR_PROOF, INDY_CRED_DEF_PRIV, INDY_DID, INDY_KEY,
    INDY_REV_REG, INDY_REV_REG_DEF, INDY_REV_REG_DEF_PRIV, INDY_REV_REG_DELTA, INDY_REV_REG_INFO,
    INDY_SCHEMA, INDY_SCHEMA_ID,
};

pub async fn migrate_without_handle(
    src_wallet_handle: WalletHandle,
    dest_wallet: &impl BaseWallet2,
) -> MigrationResult<IndyMigrationResult> {
    let all_records = Locator::instance()
        .wallet_controller
        .get_all_records(src_wallet_handle)
        .await?;

    migrate_records(all_records, dest_wallet).await

    // Ok(())
}

async fn migrate_records(
    mut records: WalletIterator,
    new_wallet: &impl BaseWallet2,
) -> MigrationResult<IndyMigrationResult> {
    let total = records.get_total_count()?;
    info!("Migrating {total:?} records");
    let mut num_record = 0;
    let mut migration_result = IndyMigrationResult {
        migrated: 0,
        skipped: 0,
        duplicated: 0,
        failed: 0,
    };

    while let Some(source_record) = records.next().await? {
        num_record += 1;
        if num_record % 1000 == 1 {
            warn!(
                "Migrating wallet record number {num_record} / {total:?}, intermediary migration \
                 result: ${migration_result:?}"
            );
        }
        // trace!("Migrating record: {:?}", source_record);
        let unwrapped_type_ = match &source_record.get_type() {
            None => {
                warn!(
                    "Skipping item missing 'type' field, record ({num_record}): {source_record:?}"
                );
                migration_result.skipped += 1;
                continue;
            }
            Some(type_) => type_.clone(),
        };
        let unwrapped_value = match &source_record.get_value() {
            None => {
                warn!(
                    "Skipping item missing 'value' field, record ({num_record}): {source_record:?}"
                );
                migration_result.skipped += 1;
                continue;
            }
            Some(value) => value.clone(),
        };
        let unwrapped_tags = match source_record.get_tags() {
            None => HashMap::new(),
            Some(tags) => tags.clone(),
        };

        let mapped_record = match map_record(
            source_record.get_id(),
            unwrapped_type_,
            unwrapped_value,
            unwrapped_tags,
        ) {
            Ok(record) => match record {
                None => {
                    warn!("Skipping non-migratable record ({num_record}): {source_record:?}");
                    migration_result.skipped += 1;
                    continue;
                }
                Some(record) => record,
            },
            Err(err) => {
                warn!(
                    "Skipping item due failed item migration, record ({num_record}): \
                     {source_record:?}, err: {err}"
                );
                migration_result.failed += 1;
                continue;
            }
        };

        add_record(new_wallet, &mut migration_result, mapped_record).await
    }
    warn!("Migration of total {total:?} records completed, result: ${migration_result:?}");
    Ok(migration_result)
}

fn transform_record(
    num_record: i32,
    // type_: &str,
    // id: &str,
    // value: &str,
    // tags: HashMap<String, String>,
    source_record: WalletRecord,
    migration_result: &mut IndyMigrationResult,
) -> MigrationResult<Option<Record>> {
    let unwrapped_type = match &source_record.get_type() {
        None => {
            warn!("Skipping item missing 'type' field, record ({num_record}): {source_record:?}");
            migration_result.skipped += 1;
            None;
        }
        Some(type_) => type_.clone(),
    };
    let unwrapped_value = match &source_record.get_value() {
        None => {
            warn!("Skipping item missing 'value' field, record ({num_record}): {source_record:?}");
            migration_result.skipped += 1;
            None;
        }
        Some(value) => value.clone(),
    };
    let unwrapped_tags = match source_record.get_tags() {
        None => HashMap::new(),
        Some(tags) => tags.clone(),
    };

    let mapped_record = match map_record(
        source_record.get_id(),
        unwrapped_type,
        unwrapped_value,
        unwrapped_tags,
    ) {
        Ok(record) => match record {
            None => {
                warn!("Skipping non-migratable record ({num_record}): {source_record:?}");
                migration_result.skipped += 1;
            }
            Some(record) => record,
        },
        Err(err) => {
            warn!(
                "Skipping item due failed item migration, record ({num_record}): \
                 {source_record:?}, err: {err}"
            );
            migration_result.failed += 1;
        }
    };
}

async fn add_record(
    new_wallet: &impl BaseWallet2,
    migration_result: &mut IndyMigrationResult,
    record: Record,
) {
    match new_wallet.add_record(record.clone()).await {
        Err(err) => match err.kind() {
            AriesVcxCoreErrorKind::CredDefAlreadyCreated
            | AriesVcxCoreErrorKind::DuplicationSchema
            | AriesVcxCoreErrorKind::DuplicationWalletRecord
            | AriesVcxCoreErrorKind::DuplicationDid => {
                trace!(
                    "Record type: {record:?} already exists in destination wallet, \
                     skipping"
                );
                migration_result.duplicated += 1;
            }
            _ => {
                error!("Error adding record {record:?} to destination wallet: {err:?}");
                migration_result.failed += 1;
            }
        },
        Ok(()) => {
            migration_result.migrated += 1;
        }
    }
}

fn map_record(
    name: &str,
    category: &str,
    value: &str,
    tags: HashMap<String, String>,
) -> MigrationResult<Option<Record>> {
    let record = Record {
        category: category.into(),
        name: name.into(),
        value: value.into(),
        tags: tags.into(),
    };

    info!("Migrating wallet record {record:?}");

    let record = match record.category.as_str() {
        DID_CATEGORY
        | TMP_DID_CATEGORY
        | INDY_KEY
        | INDY_CRED
        | INDY_CRED_DEF
        | INDY_CRED_DEF_PRIV
        | INDY_CRED_DEF_CR_PROOF
        | INDY_SCHEMA
        | INDY_SCHEMA_ID
        | INDY_REV_REG
        | INDY_REV_REG_DELTA
        | INDY_REV_REG_INFO
        | INDY_REV_REG_DEF
        | INDY_REV_REG_DEF_PRIV => Ok(Some(record)),

        _ => Ok(None),
    };

    record
}

#[cfg(test)]
mod tests {
    use aries_askar::StoreKeyMethod;
    use aries_vcx_core::{
        wallet::{base_wallet::BaseWallet, indy::IndySdkWallet},
        wallet2::{
            askar_wallet::AskarWallet, utils::random_seed, DidWallet, Record, RecordBuilder,
            RecordWallet,
        },
    };
    use log::{debug, info};
    use uuid::Uuid;
    use vdrtools::{
        types::domain::wallet::{Config, Credentials},
        Locator,
    };

    use super::migrate_without_handle;

    type TestDataVec = Vec<(&'static str, String, u32)>;
    struct TestData {
        pub data_vec: TestDataVec,
        pub expected_count: u32,
    }

    use crate::{
        test_helper::{
            make_dummy_cred, make_dummy_cred_def, make_dummy_cred_def_correctness_proof,
            make_dummy_cred_def_priv_key, make_dummy_master_secret, make_dummy_rev_reg,
            make_dummy_rev_reg_def, make_dummy_rev_reg_def_priv, make_dummy_rev_reg_delta,
            make_dummy_rev_reg_info, make_dummy_schema, make_dummy_schema_id, make_wallet_reqs,
        },
        vdrtools2credx::{
            INDY_CRED, INDY_CRED_DEF, INDY_CRED_DEF_CR_PROOF, INDY_CRED_DEF_PRIV,
            INDY_MASTER_SECRET, INDY_REV_REG, INDY_REV_REG_DEF, INDY_REV_REG_DEF_PRIV,
            INDY_REV_REG_DELTA, INDY_REV_REG_INFO, INDY_SCHEMA, INDY_SCHEMA_ID,
        },
    };

    #[tokio::test]
    async fn test_wallet_migration_to_askar() {
        let (creds, config) = make_wallet_reqs("original_wallet".into());
        let indy_wallet = open_indy_wallet(config.clone(), creds.clone()).await;
        let askar_wallet = open_askar_wallet().await;

        let data = generate_test_data();
        create_test_data(&indy_wallet, data.data_vec).await;

        let res = migrate_without_handle(indy_wallet.get_wallet_handle(), &askar_wallet)
            .await
            .unwrap();

        teardown_indy_wallet(indy_wallet, config, creds).await;

        assert_eq!(data.expected_count, res.migrated);
    }

    #[test_log::test(tokio::test)]
    async fn test_create_and_store_my_did_compatibility() {
        let (creds, config) = make_wallet_reqs("original_wallet".into());
        let indy_wallet = open_indy_wallet(config.clone(), creds.clone()).await;
        let askar_wallet = open_askar_wallet().await;

        let did_data = DidWallet::create_and_store_my_did(&indy_wallet, None, None)
            .await
            .unwrap();

        // println!("Did data: {:?}", did_data);

        // let askar_data = askar_wallet
        //     .create_and_store_my_did(None, None)
        //     .await
        //     .unwrap();

        // let askar_all = askar_wallet.get_all().await.unwrap();

        // for record in askar_all {
        //     info!("Askar record: {record:?}");
        // }

        let res = migrate_without_handle(indy_wallet.get_wallet_handle(), &askar_wallet)
            .await
            .unwrap();

        teardown_indy_wallet(indy_wallet, config, creds).await;

        let res = askar_wallet.did_key(&did_data.did).await.unwrap();
    }

    async fn list_askar_records(askar_wallet: &AskarWallet) {
        let askar_all = askar_wallet.get_all_records().await.unwrap();

        for record in askar_all {
            info!("Askar record: {record:?}");
        }
    }

    async fn list_askar_keys(askar_wallet: &AskarWallet) {
        let askar_all = askar_wallet.get_all_keys().await.unwrap();

        for key in askar_all {
            info!("Askar key: {key:?}");
        }
    }

    #[test_log::test(tokio::test)]
    async fn test_replace_key_compatibility() {
        let (creds, config) = make_wallet_reqs("original_wallet".into());
        let indy_wallet = open_indy_wallet(config.clone(), creds.clone()).await;
        let askar_wallet = open_askar_wallet().await;

        askar_wallet
            .create_and_store_my_did(Some("foo"), None)
            .await
            .unwrap();

        list_askar_records(&askar_wallet).await;
        list_askar_keys(&askar_wallet).await;

        println!("listed askar");

        let did_data = DidWallet::create_and_store_my_did(&indy_wallet, Some(&random_seed()), None)
            .await
            .unwrap();

        let res = indy_wallet
            .replace_did_key_start(&did_data.did, Some(&random_seed()))
            .await
            .unwrap();

        println!("Did data: {:?}", did_data);

        let res = migrate_without_handle(indy_wallet.get_wallet_handle(), &askar_wallet)
            .await
            .unwrap();

        // println!("\nFirst migrate\n");

        // indy_wallet
        //     .replace_did_key_apply(&did_data.did)
        //     .await
        //     .unwrap();

        // let res = migrate_without_handle(indy_wallet.get_wallet_handle(), &askar_wallet)
        //     .await
        //     .unwrap();

        list_askar_records(&askar_wallet).await;

        teardown_indy_wallet(indy_wallet, config, creds).await;

        let res = askar_wallet
            .replace_did_key_apply(&did_data.did)
            .await
            .unwrap();
    }

    async fn create_test_data(indy_wallet: &IndySdkWallet, data_vec: TestDataVec) {
        for (category, value, count) in data_vec {
            for _ in 0..count {
                add_wallet_item(indy_wallet, category, &value).await;
            }
        }
    }

    async fn add_wallet_item(indy_wallet: &IndySdkWallet, category: &str, value: &str) {
        let record = RecordBuilder::default()
            .name(Uuid::new_v4().to_string())
            .category(category.into())
            .value(value.into())
            .build()
            .unwrap();

        indy_wallet.add_record(record).await.unwrap();
    }

    fn generate_test_data() -> TestData {
        let master_secret_count = 1;
        let indy_cred_count = 1;
        let indy_cred_def_count = 1;
        let indy_cred_def_priv_count = 1;
        let indy_cred_def_cr_proof_count = 1;
        let indy_schema_count = 1;
        let indy_schema_id_count = 1;
        let indy_rev_reg_count = 1;
        let indy_rev_reg_delta_count = 1;
        let indy_rev_reg_info_count = 1;
        let infy_rev_reg_def_count = 1;
        let indy_rev_reg_def_priv_count = 1;

        let wallet_items = vec![
            (
                INDY_MASTER_SECRET,
                make_dummy_master_secret(),
                master_secret_count,
            ),
            (INDY_CRED, make_dummy_cred(), indy_cred_count),
            (INDY_CRED_DEF, make_dummy_cred_def(), indy_cred_def_count),
            (
                INDY_CRED_DEF_PRIV,
                make_dummy_cred_def_priv_key(),
                indy_cred_def_priv_count,
            ),
            (
                INDY_CRED_DEF_CR_PROOF,
                make_dummy_cred_def_correctness_proof(),
                indy_cred_def_cr_proof_count,
            ),
            (INDY_SCHEMA, make_dummy_schema(), indy_schema_count),
            (INDY_SCHEMA_ID, make_dummy_schema_id(), indy_schema_id_count),
            (INDY_REV_REG, make_dummy_rev_reg(), indy_rev_reg_count),
            (
                INDY_REV_REG_DELTA,
                make_dummy_rev_reg_delta(),
                indy_rev_reg_delta_count,
            ),
            (
                INDY_REV_REG_INFO,
                make_dummy_rev_reg_info(),
                indy_rev_reg_info_count,
            ),
            (
                INDY_REV_REG_DEF,
                make_dummy_rev_reg_def(),
                infy_rev_reg_def_count,
            ),
            (
                INDY_REV_REG_DEF_PRIV,
                make_dummy_rev_reg_def_priv(),
                indy_rev_reg_def_priv_count,
            ),
        ];

        let expected_count = indy_cred_count
            + indy_cred_def_count
            + indy_cred_def_priv_count
            + indy_cred_def_cr_proof_count
            + indy_schema_count
            + indy_schema_id_count
            + indy_rev_reg_count
            + indy_rev_reg_delta_count
            + indy_rev_reg_info_count
            + infy_rev_reg_def_count
            + indy_rev_reg_def_priv_count;

        TestData {
            expected_count,
            data_vec: wallet_items,
        }
    }

    async fn open_indy_wallet(config: Config, creds: Credentials) -> IndySdkWallet {
        Locator::instance()
            .wallet_controller
            .delete(config.clone(), creds.clone())
            .await
            .ok();

        Locator::instance()
            .wallet_controller
            .create(config.clone(), creds.clone())
            .await
            .unwrap();

        let handle = Locator::instance()
            .wallet_controller
            .open(config.clone(), creds.clone())
            .await
            .unwrap();

        IndySdkWallet::new(handle)
    }

    async fn teardown_indy_wallet(wallet: IndySdkWallet, config: Config, creds: Credentials) {
        Locator::instance()
            .wallet_controller
            .close(wallet.get_wallet_handle())
            .await
            .unwrap();

        Locator::instance()
            .wallet_controller
            .delete(config, creds)
            .await
            .unwrap();
    }

    pub async fn open_askar_wallet() -> AskarWallet {
        AskarWallet::create(
            "sqlite://:memory:",
            StoreKeyMethod::Unprotected,
            None.into(),
            true,
            Some(Uuid::new_v4().to_string()),
        )
        .await
        .unwrap()
    }
}
