use std::collections::{HashMap, HashSet};

use serde_json::json;
use vdrtools::types::domain::wallet::{Config, Credentials, KeyDerivationMethod};

const WALLET_KEY: &str = "8dvfYSt5d1taSd6yJdpjq4emkwsPDDLYxkNFysFD2cZY";

pub fn make_wallet_reqs(wallet_name: String) -> (Credentials, Config) {
    let credentials = Credentials {
        key: WALLET_KEY.to_owned(),
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

    (credentials, config)
}

pub fn make_dummy_master_secret() -> String {
    json!({
        "value": {
            "ms": "1234567890"
        }
    })
    .to_string()
}

pub fn make_dummy_cred() -> String {
    let cred_sig_str = json!({
        "p_credential": {
            "m_2": "1234567890",
            "a": "1234567890",
            "e": "1234567890",
            "v": "1234567890"
        },
        "r_credential": null
    })
    .to_string();

    let sig_cor_proof_str = json!({
        "se": "1234567890",
        "c": "1234567890"
    })
    .to_string();

    serde_json::to_string(&vdrtools::Credential {
        schema_id: vdrtools::SchemaId("test_schema_id".to_owned()),
        cred_def_id: vdrtools::CredentialDefinitionId("test_cred_def_id".to_owned()),
        rev_reg_id: Some(vdrtools::RevocationRegistryId("test_rev_reg_id".to_owned())),
        values: vdrtools::CredentialValues(HashMap::new()),
        signature: serde_json::from_str(&cred_sig_str).unwrap(),
        signature_correctness_proof: serde_json::from_str(&sig_cor_proof_str).unwrap(),
        rev_reg: None,
        witness: None,
    })
    .unwrap()
}

pub fn make_dummy_cred_def() -> String {
    let primary = json!({
        "n": "1234567890",
        "s": "1234567890",
        "r": {},
        "rctxt": "1234567890",
        "z": "1234567890",
    })
    .to_string();

    serde_json::to_string(&vdrtools::CredentialDefinition::CredentialDefinitionV1(
        vdrtools::CredentialDefinitionV1 {
            id: vdrtools::CredentialDefinitionId("test_cred_def_id".to_owned()),
            schema_id: vdrtools::SchemaId("test_schema_id".to_owned()),
            signature_type: vdrtools::SignatureType::CL,
            tag: "{}".to_owned(),
            value: vdrtools::CredentialDefinitionData {
                primary: serde_json::from_str(&primary).unwrap(),
                revocation: None,
            },
        },
    ))
    .unwrap()
}

pub fn make_dummy_cred_def_priv_key() -> String {
    let priv_key = json!({
        "p_key": {
            "p": "1234567890",
            "q": "1234567890"
        }
    })
    .to_string();

    serde_json::to_string(&vdrtools::CredentialDefinitionPrivateKey {
        value: serde_json::from_str(&priv_key).unwrap(),
    })
    .unwrap()
}

pub fn make_dummy_cred_def_correctness_proof() -> String {
    let cor_proof = json!({
        "c": "1234567890",
        "xz_cap": "1234567890",
        "xr_cap": []
    })
    .to_string();

    serde_json::to_string(&vdrtools::CredentialDefinitionCorrectnessProof {
        value: serde_json::from_str(&cor_proof).unwrap(),
    })
    .unwrap()
}

pub fn make_dummy_schema() -> String {
    serde_json::to_string(&vdrtools::Schema::SchemaV1(vdrtools::SchemaV1 {
        id: vdrtools::SchemaId("test_schema_id".to_owned()),
        name: "test_schema_name".to_owned(),
        version: "test_schema_version".to_owned(),
        attr_names: vdrtools::AttributeNames(HashSet::new()),
        seq_no: None,
    }))
    .unwrap()
}

pub fn make_dummy_schema_id() -> String {
    "test_schema_id".to_owned()
}

pub fn make_dummy_rev_reg() -> String {
    let rev_reg = json!({
        "accum": "21 11ED98357F9B9B3077E633D35A72CECEF107F85DA7BBFBF2873E2EE7E0F27D326 21 1371CDA6174D6F01A39157428768D328B4B80088EB14AA0AAB7F046B645E1A235 6 65BBFAC37012790BB8B283F164BE3C0585AB60CD7B72123E4DC43DDA7A6A4E6D 4 3BB64FAF922865095CD5AA4349C0437D04EA30FB7592D932531732F2DCB83DB8 6 77039B80A78AB4A2476373C6F8ECC5E2D94B8F37F924549AFA247E2D6EE86DEE 4 24E94FB6B5233B22BDF47745AA821A1797BC6504BC11D5B825B4F8137F1E307F"
    }).to_string();

    serde_json::to_string(&vdrtools::RevocationRegistry::RevocationRegistryV1(
        vdrtools::RevocationRegistryV1 {
            value: serde_json::from_str(&rev_reg).unwrap(),
        },
    ))
    .unwrap()
}

pub fn make_dummy_rev_reg_delta() -> String {
    let rev_reg = json!({
        "prevAccum": "21 11ED98357F9B9B3077E633D35A72CECEF107F85DA7BBFBF2873E2EE7E0F27D326 21 1371CDA6174D6F01A39157428768D328B4B80088EB14AA0AAB7F046B645E1A235 6 65BBFAC37012790BB8B283F164BE3C0585AB60CD7B72123E4DC43DDA7A6A4E6D 4 3BB64FAF922865095CD5AA4349C0437D04EA30FB7592D932531732F2DCB83DB8 6 77039B80A78AB4A2476373C6F8ECC5E2D94B8F37F924549AFA247E2D6EE86DEE 4 24E94FB6B5233B22BDF47745AA821A1797BC6504BC11D5B825B4F8137F1E307F",
        "accum": "21 11ED98357F9B9B3077E633D35A72CECEF107F85DA7BBFBF2873E2EE7E0F27D326 21 1371CDA6174D6F01A39157428768D328B4B80088EB14AA0AAB7F046B645E1A235 6 65BBFAC37012790BB8B283F164BE3C0585AB60CD7B72123E4DC43DDA7A6A4E6D 4 3BB64FAF922865095CD5AA4349C0437D04EA30FB7592D932531732F2DCB83DB8 6 77039B80A78AB4A2476373C6F8ECC5E2D94B8F37F924549AFA247E2D6EE86DEE 4 24E94FB6B5233B22BDF47745AA821A1797BC6504BC11D5B825B4F8137F1E307F",
        "issued": [],
        "revoked": []
    }).to_string();

    let rev_reg_delta = vdrtools::RevocationRegistryDelta::RevocationRegistryDeltaV1(
        vdrtools::RevocationRegistryDeltaV1 {
            value: serde_json::from_str(&rev_reg).unwrap(),
        },
    );

    json!(rev_reg_delta).to_string()
}

pub fn make_dummy_rev_reg_info() -> String {
    serde_json::to_string(&vdrtools::RevocationRegistryInfo {
        id: vdrtools::RevocationRegistryId("test_rev_reg_id".to_owned()),
        curr_id: 1,
        used_ids: HashSet::new(),
    })
    .unwrap()
}

pub fn make_dummy_rev_reg_def() -> String {
    let accum_key = json!({
        "z": "1 042CDA7AA76FFD05D0EA1C97F0F238A579AAE4348442298B7F8513277A21D671 1 04C49DDECC3731B11BC98A1495C39DF7F94A297EA6D691DADAF1493300D2977E 1 0D78B673DE9F1CE37FA98E0765B69D963BFF9973317722981943797EFEF1F628 1 1F4DFD2C1ED2BD80D9D92600AB7A1B2911180B4B44C6BC42962084AC4C042385 1 07724871AD4FFC1C30BCAEFE289FAF6F2F322203C34D8D2D3C36DFD816AF9430 1 050F4014E2AFD680A67C197B39D35CA4D03332D6C6922A4D991EC1402B7FF4E6 1 07C0DCAF303CF4B0741447A1A808C8C2BAE6CD30397AAF834428848FEE70FC3D 1 1C028C08BD426B053942A4409F71A5215B6B0B58FF651C72303F1B4C5DDB84C4 1 22DE20332A0E1B0C58F76CBADBF73D0B6875A5F3479AC0E3C4D27A605656BF6E 1 1F461563E404002F9AFE37D09FA98F34B4666D1A4424C89B3C8CE7E85DE23B8A 1 096DA55063F6ABA1B578471DEBDEACA5DE485994F99099BBBB6E326DDF8C3DD2 1 12FFCEFF31CE5781FF6BB9AB279BF8A100E97D43B0F6C31E6FCD6373227E34FD"
    }).to_string();

    serde_json::to_string(
        &vdrtools::RevocationRegistryDefinition::RevocationRegistryDefinitionV1(
            vdrtools::RevocationRegistryDefinitionV1 {
                id: vdrtools::RevocationRegistryId("test_rev_reg_id".to_owned()),
                revoc_def_type: vdrtools::RegistryType::CL_ACCUM,
                tag: "{}".to_owned(),
                cred_def_id: vdrtools::CredentialDefinitionId("test_cred_def_id".to_owned()),
                value: vdrtools::RevocationRegistryDefinitionValue {
                    issuance_type: vdrtools::IssuanceType::ISSUANCE_BY_DEFAULT,
                    max_cred_num: 10,
                    public_keys: vdrtools::RevocationRegistryDefinitionValuePublicKeys {
                        accum_key: serde_json::from_str(&accum_key).unwrap(),
                    },
                    tails_hash: "abc".to_owned(),
                    tails_location: "/dev/null".to_owned(),
                },
            },
        ),
    )
    .unwrap()
}

pub fn make_dummy_rev_reg_def_priv() -> String {
    let rev_key_priv = json!({
        "gamma": "12345"
    })
    .to_string();

    serde_json::to_string(&vdrtools::RevocationRegistryDefinitionPrivate {
        value: serde_json::from_str(&rev_key_priv).unwrap(),
    })
    .unwrap()
}
