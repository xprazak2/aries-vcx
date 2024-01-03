pub mod conv;

use log::trace;
use vdrtools::types::domain::wallet::Record;

use crate::error::MigrationResult;

pub(crate) const INDY_DID: &str = "Indy::Did";
pub(crate) const INDY_KEY: &str = "Indy::Key";
pub(crate) const INDY_MASTER_SECRET: &str = "Indy::MasterSecret";
pub(crate) const INDY_CRED: &str = "Indy::Credential";
pub(crate) const INDY_CRED_DEF: &str = "Indy::CredentialDefinition";
pub(crate) const INDY_CRED_DEF_PRIV: &str = "Indy::CredentialDefinitionPrivateKey";
pub(crate) const INDY_CRED_DEF_CR_PROOF: &str = "Indy::CredentialDefinitionCorrectnessProof";
pub(crate) const INDY_SCHEMA: &str = "Indy::Schema";
pub(crate) const INDY_SCHEMA_ID: &str = "Indy::SchemaId";
pub(crate) const INDY_REV_REG: &str = "Indy::RevocationRegistry";
pub(crate) const INDY_REV_REG_DELTA: &str = "cache"; // very intuitive, indy devs
pub(crate) const INDY_REV_REG_INFO: &str = "Indy::RevocationRegistryInfo";
pub(crate) const INDY_REV_REG_DEF: &str = "Indy::RevocationRegistryDefinition";
pub(crate) const INDY_REV_REG_DEF_PRIV: &str = "Indy::RevocationRegistryDefinitionPrivate";

/// Contains the logic for record mapping and migration.
pub fn migrate_any_record(record: Record) -> MigrationResult<Option<Record>> {
    trace!("Migrating wallet record {record:?}");

    let record = match record.type_.as_str() {
        // Indy wallet records - to be left alone!
        INDY_DID | INDY_KEY => Ok(Some(record)),
        // Master secret
        INDY_MASTER_SECRET => Some(conv::convert_master_secret(record)).transpose(),
        // Credential
        INDY_CRED => Some(conv::convert_cred(record)).transpose(),
        INDY_CRED_DEF => Some(conv::convert_cred_def(record)).transpose(),
        INDY_CRED_DEF_PRIV => Some(conv::convert_cred_def_priv_key(record)).transpose(),
        INDY_CRED_DEF_CR_PROOF => {
            Some(conv::convert_cred_def_correctness_proof(record)).transpose()
        }
        // Schema
        INDY_SCHEMA => Some(conv::convert_schema(record)).transpose(),
        INDY_SCHEMA_ID => Some(conv::convert_schema_id(record)).transpose(),
        // Revocation registry
        INDY_REV_REG => Some(conv::convert_rev_reg(record)).transpose(),
        INDY_REV_REG_DELTA => Some(conv::convert_rev_reg_delta(record)).transpose(),
        INDY_REV_REG_INFO => Some(conv::convert_rev_reg_info(record)).transpose(),
        INDY_REV_REG_DEF => Some(conv::convert_rev_reg_def(record)).transpose(),
        INDY_REV_REG_DEF_PRIV => Some(conv::convert_rev_reg_def_priv(record)).transpose(),
        _ => Ok(None), // Ignore unknown/uninteresting records
    };

    trace!("Converted wallet record to {record:?}");
    record
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use aries_vcx_core::anoncreds::credx_anoncreds::{
        RevocationRegistryInfo, CATEGORY_CREDENTIAL, CATEGORY_CRED_DEF, CATEGORY_CRED_DEF_PRIV,
        CATEGORY_CRED_KEY_CORRECTNESS_PROOF, CATEGORY_CRED_MAP_SCHEMA_ID, CATEGORY_CRED_SCHEMA,
        CATEGORY_LINK_SECRET, CATEGORY_REV_REG, CATEGORY_REV_REG_DEF, CATEGORY_REV_REG_DEF_PRIV,
        CATEGORY_REV_REG_DELTA, CATEGORY_REV_REG_INFO,
    };
    use credx::{
        anoncreds_clsignatures::{bn::BigNumber, LinkSecret as ClLinkSecret},
        types::LinkSecret,
    };
    use serde_json::json;
    use vdrtools::{
        types::domain::wallet::{Config, Credentials, KeyDerivationMethod},
        Locator, WalletHandle,
    };

    use super::*;
    use crate::{
        migrate_wallet,
        test_helper::{
            make_dummy_cred, make_dummy_cred_def, make_dummy_cred_def_correctness_proof,
            make_dummy_cred_def_priv_key, make_dummy_master_secret, make_dummy_rev_reg,
            make_dummy_rev_reg_def, make_dummy_rev_reg_def_priv, make_dummy_rev_reg_delta,
            make_dummy_rev_reg_info, make_dummy_schema, make_dummy_schema_id, make_wallet_reqs,
        },
    };

    const WALLET_KEY: &str = "8dvfYSt5d1taSd6yJdpjq4emkwsPDDLYxkNFysFD2cZY";

    #[tokio::test]
    async fn test_sqlite_migration() {
        let (credentials, config) = make_wallet_reqs("wallet_test_migration".to_owned());
        let (new_credentials, new_config) = make_wallet_reqs("new_better_wallet".to_owned());

        test_migration(credentials, config, new_credentials, new_config).await;
    }

    #[tokio::test]
    async fn test_mysql_migration() {
        let wallet_name = "wallet_test_migration";
        let new_wallet_name = "new_better_wallet";

        let (mut credentials, mut config) = make_wallet_reqs(wallet_name.to_owned());
        let (mut new_credentials, mut new_config) = make_wallet_reqs(new_wallet_name.to_owned());

        config.storage_type = Some("mysql".to_owned());
        new_config.storage_type = Some("mysql".to_owned());

        let storage_config = json!({
            "read_host": "localhost",
            "write_host": "localhost",
            "port": 3306,
            "db_name": wallet_name,
            "default_connection_limit": 50
        });

        let new_storage_config = json!({
            "read_host": "localhost",
            "write_host": "localhost",
            "port": 3306,
            "db_name": new_wallet_name,
            "default_connection_limit": 50
        });

        let storage_credentials = json!({
            "user": "root",
            "pass": "mysecretpassword"
        });

        config.storage_config = Some(storage_config);
        credentials.storage_credentials = Some(storage_credentials.clone());

        new_config.storage_config = Some(new_storage_config);
        new_credentials.storage_credentials = Some(storage_credentials);

        test_migration(credentials, config, new_credentials, new_config).await;
    }

    macro_rules! add_wallet_item {
        ($wh:expr, $category:expr, $val:expr) => {
            Locator::instance()
                .non_secret_controller
                .add_record(
                    $wh,
                    $category.to_owned(),
                    "test_id".to_owned(),
                    $val.to_owned(),
                    None,
                )
                .await
                .unwrap();
        };
    }

    macro_rules! get_wallet_item {
        ($wh:expr, $category:expr, $res:ty) => {{
            let val = get_wallet_item_raw($wh, $category).await;
            serde_json::from_str::<$res>(&val).unwrap()
        }};
    }

    async fn test_migration(
        credentials: Credentials,
        config: Config,
        new_credentials: Credentials,
        new_config: Config,
    ) {
        // Removes old wallet if it already exists
        Locator::instance()
            .wallet_controller
            .delete(config.clone(), credentials.clone())
            .await
            .ok();

        // Create and open the old wallet
        // where we'll store old indy anoncreds types
        Locator::instance()
            .wallet_controller
            .create(config.clone(), credentials.clone())
            .await
            .unwrap();

        let src_wallet_handle = Locator::instance()
            .wallet_controller
            .open(config.clone(), credentials.clone())
            .await
            .unwrap();

        // Construct and add legacy indy records
        // These are dummy records with dummy values
        // and are NOT expected to be functional
        //
        // ################# Ingestion start #################

        // Master secret
        add_wallet_item!(
            src_wallet_handle,
            INDY_MASTER_SECRET,
            make_dummy_master_secret()
        );

        // Credential
        add_wallet_item!(src_wallet_handle, INDY_CRED, make_dummy_cred());
        add_wallet_item!(src_wallet_handle, INDY_CRED_DEF, make_dummy_cred_def());
        add_wallet_item!(
            src_wallet_handle,
            INDY_CRED_DEF_PRIV,
            make_dummy_cred_def_priv_key()
        );
        add_wallet_item!(
            src_wallet_handle,
            INDY_CRED_DEF_CR_PROOF,
            make_dummy_cred_def_correctness_proof()
        );

        // Schema
        add_wallet_item!(src_wallet_handle, INDY_SCHEMA, make_dummy_schema());
        add_wallet_item!(src_wallet_handle, INDY_SCHEMA_ID, make_dummy_schema_id());

        // Revocation registry
        add_wallet_item!(src_wallet_handle, INDY_REV_REG, make_dummy_rev_reg());
        add_wallet_item!(
            src_wallet_handle,
            INDY_REV_REG_DELTA,
            make_dummy_rev_reg_delta()
        );
        add_wallet_item!(
            src_wallet_handle,
            INDY_REV_REG_INFO,
            make_dummy_rev_reg_info()
        );
        add_wallet_item!(
            src_wallet_handle,
            INDY_REV_REG_DEF,
            make_dummy_rev_reg_def()
        );
        add_wallet_item!(
            src_wallet_handle,
            INDY_REV_REG_DEF_PRIV,
            make_dummy_rev_reg_def_priv()
        );

        // ################# Ingestion end #################

        // Remove new wallet if it already exists
        Locator::instance()
            .wallet_controller
            .delete(new_config.clone(), new_credentials.clone())
            .await
            .ok();

        Locator::instance()
            .wallet_controller
            .create(new_config.clone(), new_credentials.clone())
            .await
            .unwrap();

        let dest_wallet_handle = Locator::instance()
            .wallet_controller
            .open(new_config.clone(), new_credentials.clone())
            .await
            .unwrap();

        // Migrate the records
        migrate_wallet(src_wallet_handle, dest_wallet_handle, migrate_any_record)
            .await
            .unwrap();

        // Old wallet cleanup
        Locator::instance()
            .wallet_controller
            .close(src_wallet_handle)
            .await
            .unwrap();

        Locator::instance()
            .wallet_controller
            .delete(config, credentials)
            .await
            .unwrap();

        // ################# Retrieval start #################

        // Master secret
        get_master_secret(dest_wallet_handle).await;

        // Credential
        get_wallet_item!(
            dest_wallet_handle,
            CATEGORY_CREDENTIAL,
            credx::types::Credential
        );
        get_wallet_item!(
            dest_wallet_handle,
            CATEGORY_CRED_DEF,
            credx::types::CredentialDefinition
        );
        get_wallet_item!(
            dest_wallet_handle,
            CATEGORY_CRED_DEF_PRIV,
            credx::types::CredentialDefinitionPrivate
        );
        get_wallet_item!(
            dest_wallet_handle,
            CATEGORY_CRED_KEY_CORRECTNESS_PROOF,
            credx::types::CredentialKeyCorrectnessProof
        );

        // Schema
        get_wallet_item!(
            dest_wallet_handle,
            CATEGORY_CRED_SCHEMA,
            credx::types::Schema
        );
        get_wallet_item!(
            dest_wallet_handle,
            CATEGORY_CRED_MAP_SCHEMA_ID,
            credx::types::SchemaId
        );

        // Revocation registry
        get_wallet_item!(
            dest_wallet_handle,
            CATEGORY_REV_REG,
            credx::types::RevocationRegistry
        );
        get_wallet_item!(
            dest_wallet_handle,
            CATEGORY_REV_REG_DELTA,
            credx::types::RevocationRegistryDelta
        );
        get_wallet_item!(
            dest_wallet_handle,
            CATEGORY_REV_REG_INFO,
            RevocationRegistryInfo
        );
        get_wallet_item!(
            dest_wallet_handle,
            CATEGORY_REV_REG_DEF,
            credx::types::RevocationRegistryDefinition
        );
        get_wallet_item!(
            dest_wallet_handle,
            CATEGORY_REV_REG_DEF_PRIV,
            credx::types::RevocationRegistryDefinitionPrivate
        );

        // ################# Retrieval end #################

        // New wallet cleanup
        Locator::instance()
            .wallet_controller
            .close(dest_wallet_handle)
            .await
            .unwrap();

        Locator::instance()
            .wallet_controller
            .delete(new_config, new_credentials)
            .await
            .unwrap();
    }

    async fn get_wallet_item_raw(wallet_handle: WalletHandle, category: &str) -> String {
        let options = r#"{"retrieveType": true, "retrieveValue": true, "retrieveTags": true}"#;

        let record_str = Locator::instance()
            .non_secret_controller
            .get_record(
                wallet_handle,
                category.to_owned(),
                "test_id".to_owned(),
                options.to_owned(),
            )
            .await
            .unwrap();

        let record: Record = serde_json::from_str(&record_str).unwrap();
        record.value
    }

    // MasterSecret needs special processing
    async fn get_master_secret(wallet_handle: WalletHandle) {
        let ms_decimal = get_wallet_item_raw(wallet_handle, CATEGORY_LINK_SECRET).await;
        let ms_bn = BigNumber::from_dec(&ms_decimal).unwrap();

        let ursa_ms: ClLinkSecret = serde_json::from_value(json!({ "ms": ms_bn })).unwrap();
        let _ = LinkSecret { value: ursa_ms };
    }
}
