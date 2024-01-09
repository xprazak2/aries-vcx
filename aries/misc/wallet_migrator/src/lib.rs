pub mod credx2anoncreds;
pub mod error;
pub mod vdrtools2credx;

use std::fmt::Display;

use aries_vcx_core::wallet2::BaseWallet2;
use error::MigrationResult;
use log::{error, info};
pub use vdrtools::types::domain::wallet::Record;
use vdrtools::{iterator::WalletIterator, Locator, WalletHandle};

use crate::error::MigrationError;

/// Retrieves all records from the source wallet and migrates them
/// by applying the `migrate_fn` argument. The records are then
/// placed in the destination wallet.
pub async fn migrate_wallet<E>(
    src_wallet_handle: WalletHandle,
    dest_wallet_handle: WalletHandle,
    migrate_fn: impl FnMut(Record) -> Result<Option<Record>, E>,
) -> MigrationResult<()>
where
    E: Display,
{
    info!("Starting wallet migration");

    if src_wallet_handle == dest_wallet_handle {
        error!("Equal wallet handles: {src_wallet_handle:?} {dest_wallet_handle:?}");
        return Err(MigrationError::EqualWalletHandles);
    }

    info!(
        "Migrating records from wallet with handle {src_wallet_handle:?} to wallet with handle \
         {dest_wallet_handle:?}"
    );

    Locator::instance()
        .wallet_controller
        .migrate_records(src_wallet_handle, dest_wallet_handle, migrate_fn)
        .await?;

    info!(
        "Completed migration from wallet with handle {src_wallet_handle:?} to wallet with handle \
         {dest_wallet_handle:?}"
    );

    Ok(())
}

pub async fn migrate_without_handle(
    src_wallet_handle: WalletHandle,
    dest_wallet: impl BaseWallet2,
    migrate_fn: impl FnMut(Record) -> Result<Option<Record>, E>,
) -> MigrationResult<()> {
    let all_records = Locator::instance()
        .wallet_controller
        .get_all_records(src_wallet_handle)
        .await?;

    Ok(())
}

async fn migrate_records(
    records: WalletIterator,
    new_wallet: impl BaseWallet2,
) -> MigrationResult<()> {
    let total = records.get_total_count()?;
    info!("Migrating {total:?} records");
    let mut num_record = 0;
    let mut migration_result = MigrationResult {
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
        trace!("Migrating record: {:?}", source_record);
        let unwrapped_type_ = match &source_record.type_ {
            None => {
                warn!(
                    "Skipping item missing 'type' field, record ({num_record}): {source_record:?}"
                );
                migration_result.skipped += 1;
                continue;
            }
            Some(type_) => type_.clone(),
        };
        let unwrapped_value = match &source_record.value {
            None => {
                warn!(
                    "Skipping item missing 'value' field, record ({num_record}): {source_record:?}"
                );
                migration_result.skipped += 1;
                continue;
            }
            Some(value) => value.clone(),
        };
        let unwrapped_tags = match &source_record.tags {
            None => HashMap::new(),
            Some(tags) => tags.clone(),
        };

        let record = Record {
            type_: unwrapped_type_,
            id: source_record.id.clone(),
            value: unwrapped_value,
            tags: unwrapped_tags,
        };

        let migrated_record = match migrate_fn(record) {
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

        match new_wallet
            .add(
                &migrated_record.type_,
                &migrated_record.id,
                &migrated_record.value,
                &migrated_record.tags,
                false,
            )
            .await
        {
            Err(err) => match err.kind() {
                IndyErrorKind::WalletItemAlreadyExists => {
                    trace!(
                        "Record type: {migrated_record:?} already exists in destination wallet, \
                         skipping"
                    );
                    migration_result.duplicated += 1;
                    continue;
                }
                _ => {
                    error!(
                        "Error adding record {migrated_record:?} to destination wallet: {err:?}"
                    );
                    migration_result.failed += 1;
                    return Err(err);
                }
            },
            Ok(()) => {
                migration_result.migrated += 1;
            }
        }
    }
    warn!("Migration of total {total:?} records completed, result: ${migration_result:?}");
    Ok(migration_result)
}

#[cfg(test)]
mod tests {
    use vdrtools::{
        types::domain::wallet::{Config, Credentials, KeyDerivationMethod},
        Locator,
    };

    #[tokio::test]
    #[should_panic]
    async fn test_cant_open_wallet_twice() {
        let wallet_key = "8dvfYSt5d1taSd6yJdpjq4emkwsPDDLYxkNFysFD2cZY".to_owned();
        let wallet_name = "wallet_with_some_name".to_owned();

        let credentials = Credentials {
            key: wallet_key,
            key_derivation_method: KeyDerivationMethod::RAW,
            rekey: None,
            rekey_derivation_method: KeyDerivationMethod::ARGON2I_MOD,
            storage_credentials: None,
        };

        let config = Config {
            id: wallet_name,
            storage_type: None,
            storage_config: None,
            cache: None,
        };

        Locator::instance()
            .wallet_controller
            .create(config.clone(), credentials.clone())
            .await
            .unwrap();

        let _first_wh = Locator::instance()
            .wallet_controller
            .open(config.clone(), credentials.clone())
            .await
            .unwrap();

        let _second_wh = Locator::instance()
            .wallet_controller
            .open(config, credentials)
            .await
            .unwrap();
    }
}
