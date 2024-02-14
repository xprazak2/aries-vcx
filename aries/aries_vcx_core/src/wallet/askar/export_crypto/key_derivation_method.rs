use std::default;

use serde::{Deserialize, Serialize};

// #[allow(non_camel_case_types)]
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub enum KeyDerivationMethod {
    RAW,
    #[default]
    ARGON2I_MOD,
    ARGON2I_INT,
}

// pub fn default_key_derivation_method() -> KeyDerivationMethod {
//     KeyDerivationMethod::ARGON2I_MOD
// }
