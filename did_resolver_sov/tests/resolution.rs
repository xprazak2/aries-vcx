use std::{thread, time::Duration};

use aries_vcx::common::ledger::{
    service_didsov::{DidSovServiceType, EndpointDidSov},
    transactions::write_endpoint,
};
use aries_vcx_core::{ledger::base_ledger::IndyLedgerWrite, wallet::base_wallet::BaseWallet};
use did_resolver::{
    did_parser::Did,
    traits::resolvable::{resolution_options::DidResolutionOptions, DidResolvable},
};
use did_resolver_sov::resolution::DidSovResolver;
use test_utils::run_setup_test;

async fn write_test_endpoint(
    wallet: &impl BaseWallet,
    ledger_write: &impl IndyLedgerWrite,
    did: &str,
) {
    let endpoint = EndpointDidSov::create()
        .set_service_endpoint("http://localhost:8080".parse().unwrap())
        .set_routing_keys(Some(vec!["key1".to_string(), "key2".to_string()]))
        .set_types(Some(vec![DidSovServiceType::Endpoint]));
    write_endpoint(wallet, ledger_write, did, &endpoint)
        .await
        .unwrap();
    thread::sleep(Duration::from_millis(50));
}

#[tokio::test]
async fn write_service_on_ledger_and_resolve_did_doc() {
    run_setup_test!(|init| async move {
        let did = format!("did:sov:{}", init.institution_did);
        write_test_endpoint(&init.wallet, &init.ledger_write, &init.institution_did).await;
        let resolver = DidSovResolver::new(&init.ledger_read);
        let did_doc = resolver
            .resolve(
                &Did::parse(did.clone()).unwrap(),
                &DidResolutionOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(did_doc.did_document().id().to_string(), did);
    })
    .await;
}

#[tokio::test]
async fn test_error_handling_during_resolution() {
    run_setup_test!(|init| async move {
        let did = format!("did:unknownmethod:{}", init.institution_did);

        let resolver = DidSovResolver::new(&init.ledger_read);

        let result = resolver
            .resolve(
                &Did::parse(did.clone()).unwrap(),
                &DidResolutionOptions::default(),
            )
            .await;

        assert!(result.is_err());
    })
    .await;
}
