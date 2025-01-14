mod prover_internal;

use std::collections::HashMap;

use aries_vcx_core::{
    anoncreds::base_anoncreds::BaseAnonCreds, ledger::base_ledger::AnoncredsLedgerRead,
    wallet::base_wallet::BaseWallet,
};

use crate::{
    common::proofs::{
        proof_request::ProofRequestData,
        prover::prover_internal::{
            build_cred_defs_json_prover, build_requested_credentials_json, build_rev_states_json,
            build_schemas_json_prover, credential_def_identifiers,
        },
    },
    errors::error::prelude::*,
    global::settings,
    handlers::proof_presentation::types::SelectedCredentials,
};

pub async fn generate_indy_proof(
    wallet: &impl BaseWallet,
    ledger: &impl AnoncredsLedgerRead,
    anoncreds: &impl BaseAnonCreds,
    credentials: &SelectedCredentials,
    self_attested_attrs: &HashMap<String, String>,
    proof_req_data_json: &str,
) -> VcxResult<String> {
    trace!(
        "generate_indy_proof >>> credentials: {:?}, self_attested_attrs: {:?}",
        secret!(&credentials),
        secret!(&self_attested_attrs)
    );

    let proof_request: ProofRequestData =
        serde_json::from_str(proof_req_data_json).map_err(|err| {
            AriesVcxError::from_msg(
                AriesVcxErrorKind::InvalidJson,
                format!("Cannot deserialize proof request: {}", err),
            )
        })?;

    let mut credentials_identifiers = credential_def_identifiers(credentials, &proof_request)?;

    let revoc_states_json =
        build_rev_states_json(ledger, anoncreds, &mut credentials_identifiers).await?;
    let requested_credentials = build_requested_credentials_json(
        &credentials_identifiers,
        self_attested_attrs,
        &proof_request,
    )?;

    let schemas_json = build_schemas_json_prover(ledger, &credentials_identifiers).await?;
    let credential_defs_json =
        build_cred_defs_json_prover(ledger, &credentials_identifiers).await?;

    let proof = anoncreds
        .prover_create_proof(
            wallet,
            proof_req_data_json,
            &requested_credentials,
            settings::DEFAULT_LINK_SECRET_ALIAS,
            &schemas_json,
            &credential_defs_json,
            Some(&revoc_states_json),
        )
        .await?;
    Ok(proof)
}
