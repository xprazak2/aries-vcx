use std::collections::HashMap;

use aries_askar::entry::EntryTag as AskarEntryTag;
use aries_vcx_core::errors::error::AriesVcxCoreErrorKind;
use aries_vcx_core::wallet::base_wallet::BaseWallet;
use aries_vcx_core::wallet::{
    askar::AskarWallet,
    base_wallet::Record,
    constants::{DID_CATEGORY, TMP_DID_CATEGORY},
    utils::bs58_to_bytes,
};
use log::{error, info, trace, warn};

use vdrtools::indy_wallet::{MigrationResult as IndyMigrationResult, WalletIterator, WalletRecord};
use vdrtools::{Locator, WalletHandle};

use serde::Deserialize;

use crate::error::{MigrationError, MigrationResult};
use crate::vdrtools2credx::{
    INDY_CRED, INDY_CRED_DEF, INDY_CRED_DEF_CR_PROOF, INDY_CRED_DEF_PRIV, INDY_DID, INDY_KEY,
    INDY_REV_REG, INDY_REV_REG_DEF, INDY_REV_REG_DEF_PRIV, INDY_REV_REG_DELTA, INDY_REV_REG_INFO,
    INDY_SCHEMA, INDY_SCHEMA_ID,
};

pub async fn migrate_without_handle(
    src_wallet_handle: WalletHandle,
    dest_wallet: &AskarWallet,
) -> MigrationResult<IndyMigrationResult> {
    let all_records = Locator::instance()
        .wallet_controller
        .get_all_records(src_wallet_handle)
        .await?;

    migrate_records(all_records, dest_wallet).await
}

async fn migrate_records(
    mut records: WalletIterator,
    new_wallet: &AskarWallet,
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

        let rec = transform_record(num_record, source_record, &mut migration_result);

        if let Some(wallet_item) = rec {
            match wallet_item {
                WalletItem::Record(mapped_record) => {
                    add_record(new_wallet, &mut migration_result, mapped_record).await;
                }
                WalletItem::Key(key) => add_key(&new_wallet, &mut migration_result, key).await,
            }
        }
    }
    warn!("Migration of total {total:?} records completed, result: ${migration_result:?}");
    Ok(migration_result)
}

fn transform_record(
    num_record: i32,
    source_record: WalletRecord,
    migration_result: &mut IndyMigrationResult,
) -> Option<WalletItem> {
    let unwrapped_type = match &source_record.get_type() {
        None => {
            warn!("Skipping item missing 'type' field, record ({num_record}): {source_record:?}");
            migration_result.skipped += 1;
            return None;
        }
        Some(type_) => type_.clone(),
    };
    let unwrapped_value = match &source_record.get_value() {
        None => {
            warn!("Skipping item missing 'value' field, record ({num_record}): {source_record:?}");
            migration_result.skipped += 1;
            return None;
        }
        Some(value) => value.clone(),
    };
    let unwrapped_tags = match source_record.get_tags() {
        None => HashMap::new(),
        Some(tags) => tags.clone(),
    };

    let maybe_mapped_record = map_record(
        source_record.get_id(),
        unwrapped_type,
        unwrapped_value,
        unwrapped_tags,
    );

    let mapped_record = match maybe_mapped_record {
        None => {
            warn!("Skipping non-migratable record ({num_record}): {source_record:?}");
            migration_result.skipped += 1;
            None
        }
        Some(record) => Some(record),
    };

    mapped_record
}

#[derive(Debug, Deserialize)]
struct KeyValue {
    verkey: String,
    signkey: String,
}

async fn add_key(
    new_wallet: &AskarWallet,
    migration_result: &mut IndyMigrationResult,
    key_record: Record,
) {
    let val: KeyValue = match serde_json::from_str(&key_record.get_value()) {
        Ok(val) => val,
        Err(err) => {
            error!("Deserialization error when adding key {key_record:?} to destination wallet: {err:?}");
            migration_result.failed += 1;
            return;
        }
    };

    let tags_vec: Vec<AskarEntryTag> = key_record.get_tags().clone().into();

    let private_bytes = match bs58_to_bytes(&val.signkey) {
        Ok(val) => val,
        Err(err) => {
            error!("Failed to decode private key from base58 when adding key {key_record:?} to destination wallet: {err:?}");
            migration_result.failed += 1;
            return;
        }
    };

    // println!("Key data length: {:?}", private_bytes.len());

    match new_wallet
        .create_key(
            &key_record.get_name(),
            &private_bytes[0..32],
            Some(&tags_vec),
        )
        .await
    {
        Err(err) => {
            error!("Error adding key {key_record:?} to destination wallet: {err:?}");
            migration_result.failed += 1;
        }
        Ok(_) => {
            migration_result.migrated += 1;
        }
    }
}

async fn add_record(
    new_wallet: &impl BaseWallet,
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

enum WalletItem {
    Record(Record),
    Key(Record),
}

fn map_record(
    name: &str,
    category: &str,
    value: &str,
    tags: HashMap<String, String>,
) -> Option<WalletItem> {
    let record = Record::builder()
        .category(category.into())
        .name(name.into())
        .value(value.into())
        .tags(tags.into())
        .build();

    info!("Migrating wallet record {record:?}");

    let record = match record.get_category() {
        DID_CATEGORY
        | TMP_DID_CATEGORY
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
        | INDY_REV_REG_DEF_PRIV => Some(WalletItem::Record(record)),

        INDY_KEY => Some(WalletItem::Key(record)),

        _ => None,
    };

    record
}

#[cfg(test)]
mod tests {
    use aries_askar::StoreKeyMethod;
    use aries_vcx_core::{
        wallet::{askar::AskarWallet, utils::random_seed},
        wallet::{
            base_wallet::{BaseWallet, DidWallet, Record, RecordBuilder, RecordWallet},
            indy::IndySdkWallet,
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

        let res = migrate_without_handle(indy_wallet.get_wallet_handle(), &askar_wallet)
            .await
            .unwrap();

        teardown_indy_wallet(indy_wallet, config, creds).await;

        let res = askar_wallet.did_key(&did_data.get_did()).await.unwrap();
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

        let did_data = DidWallet::create_and_store_my_did(&indy_wallet, Some(&random_seed()), None)
            .await
            .unwrap();

        let res = indy_wallet
            .replace_did_key_start(&did_data.get_did(), Some(&random_seed()))
            .await
            .unwrap();

        let res = migrate_without_handle(indy_wallet.get_wallet_handle(), &askar_wallet)
            .await
            .unwrap();

        // list_askar_records(&askar_wallet).await;
        // list_askar_keys(&askar_wallet).await;

        teardown_indy_wallet(indy_wallet, config, creds).await;

        let res = askar_wallet
            .replace_did_key_apply(&did_data.get_did())
            .await
            .unwrap();
    }

    #[test_log::test(tokio::test)]
    async fn test_sign_and_verify_compatibility() {
        let (creds, config) = make_wallet_reqs("original_wallet".into());
        let indy_wallet = open_indy_wallet(config.clone(), creds.clone()).await;
        let askar_wallet = open_askar_wallet().await;

        let did_data = DidWallet::create_and_store_my_did(&indy_wallet, Some(&random_seed()), None)
            .await
            .unwrap();

        let msg = "sign this message";
        let sig = DidWallet::sign(&indy_wallet, &did_data.get_verkey(), msg.as_bytes())
            .await
            .unwrap();

        let res = migrate_without_handle(indy_wallet.get_wallet_handle(), &askar_wallet)
            .await
            .unwrap();

        teardown_indy_wallet(indy_wallet, config, creds).await;

        assert!(askar_wallet
            .verify(&did_data.get_verkey(), msg.as_bytes(), &sig)
            .await
            .unwrap());
    }

    #[test_log::test(tokio::test)]
    async fn test_pack_and_unpack_authcrypt_compatibility() {
        let (creds, config) = make_wallet_reqs("original_wallet".into());
        let indy_wallet = open_indy_wallet(config.clone(), creds.clone()).await;
        let askar_wallet = open_askar_wallet().await;

        let sender_did_data =
            DidWallet::create_and_store_my_did(&indy_wallet, Some(&random_seed()), None)
                .await
                .unwrap();

        let recipient_did_data =
            DidWallet::create_and_store_my_did(&indy_wallet, Some(&random_seed()), None)
                .await
                .unwrap();

        let msg = "pack me";

        let data = indy_wallet
            .pack_message(
                Some(sender_did_data.get_verkey().to_owned()),
                vec![recipient_did_data.get_verkey().to_owned()],
                msg.as_bytes(),
            )
            .await
            .unwrap();

        let res = migrate_without_handle(indy_wallet.get_wallet_handle(), &askar_wallet)
            .await
            .unwrap();

        teardown_indy_wallet(indy_wallet, config, creds).await;

        let res = askar_wallet.unpack_message(&data).await.unwrap();

        assert_eq!(res.message, msg);
    }

    #[test_log::test(tokio::test)]
    async fn test_pack_and_unpack_anoncrypt_compatibility() {
        let (creds, config) = make_wallet_reqs("original_wallet".into());
        let indy_wallet = open_indy_wallet(config.clone(), creds.clone()).await;
        let askar_wallet = open_askar_wallet().await;

        let recipient_did_data =
            DidWallet::create_and_store_my_did(&indy_wallet, Some(&random_seed()), None)
                .await
                .unwrap();

        let msg = "pack me";

        let data = indy_wallet
            .pack_message(
                None,
                vec![recipient_did_data.get_verkey().to_owned()],
                msg.as_bytes(),
            )
            .await
            .unwrap();

        let res = migrate_without_handle(indy_wallet.get_wallet_handle(), &askar_wallet)
            .await
            .unwrap();

        teardown_indy_wallet(indy_wallet, config, creds).await;

        let res = askar_wallet.unpack_message(&data).await.unwrap();

        assert_eq!(res.message, msg);
    }

    async fn create_test_data(indy_wallet: &IndySdkWallet, data_vec: TestDataVec) {
        for (category, value, count) in data_vec {
            for _ in 0..count {
                add_wallet_item(indy_wallet, category, &value).await;
            }
        }
    }

    async fn add_wallet_item(indy_wallet: &IndySdkWallet, category: &str, value: &str) {
        let record = Record::builder()
            .name(Uuid::new_v4().to_string())
            .category(category.into())
            .value(value.into())
            .build();

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
