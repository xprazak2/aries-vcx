use async_trait::async_trait;

use crate::errors::error::VcxCoreResult;

use self::key_alg::KeyAlg;

pub mod key_alg;

#[derive(Clone, Default)]
pub enum RngMethod {
    #[default]
    RandomDet,
    Bls,
}

pub enum SigType {
    EdDSA,
    ES256,
    ES256K,
    ES384,
}

impl From<SigType> for &str {
    fn from(value: SigType) -> Self {
        match value {
            SigType::EdDSA => "eddsa",
            SigType::ES256 => "es256",
            SigType::ES256K => "es256k",
            SigType::ES384 => "es384",
        }
    }
}

#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum EntryTag {
    /// An entry tag to be stored encrypted
    Encrypted(String, String),
    /// An entry tag to be stored in plaintext (for ordered comparison)
    Plaintext(String, String),
}


#[derive(Default, Clone)]
pub struct Record {
    pub category: String,
    pub name: String,
    pub value: String,
    pub tags: Option<Vec<EntryTag>>,
}

pub struct Did {}

pub struct WalletKey {}

pub struct SearchFilter {}

#[async_trait]
pub trait BaseWallet2: RecordWallet + DidWallet {}

#[async_trait]
pub trait DidWallet {
    async fn create_key(&self, name: &str, alg: KeyAlg, seed: &str, rng_method: RngMethod) -> VcxCoreResult<WalletKey>;

    async fn create_did(&self, name: &str, category: &str, tags: Vec<&str>) -> VcxCoreResult<Did>;

    async fn current_did_key(&self, name: &str) -> VcxCoreResult<WalletKey>;

    async fn replace_did_key(&self, did: &str, key_name: &str) -> VcxCoreResult<WalletKey>;

    async fn sign(&self, key: &str, msg: &[u8], sig_type: SigType) -> VcxCoreResult<Vec<u8>>;

    async fn verify(
        &self,
        key: &str,
        msg: &[u8],
        signature: &[u8],
        sig_type: SigType,
    ) -> VcxCoreResult<bool>;
}

#[async_trait]
pub trait RecordWallet {
    async fn add_record(&self, record: Record) -> VcxCoreResult<()>;

    async fn get_record(&self, name: &str, category: &str) -> VcxCoreResult<Record>;

    async fn update_record(&self, record: Record) -> VcxCoreResult<()>;

    async fn delete_record(&self, name: &str, category: &str) -> VcxCoreResult<()>;

    async fn search_record(
        &self,
        filter: SearchFilter,
    ) -> VcxCoreResult<Vec<Record>>;
}
