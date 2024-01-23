use aries_askar::{
    entry::EntryTag,
    kms::{KeyAlg, KeyEntry, LocalKey},
    PassKey, Session, Store, StoreKeyMethod,
};

use crate::errors::error::{AriesVcxCoreError, AriesVcxCoreErrorKind, VcxCoreResult};

use super::{
    base_wallet::{BaseWallet, DidData, Record},
    constants::DID_CATEGORY,
    utils::key_from_base58,
};

pub mod askar_did_wallet;
pub mod askar_record_wallet;
pub mod askar_utils;
mod crypto_box;
pub mod packing;

#[derive(Clone, Default)]
pub enum RngMethod {
    #[default]
    RandomDet,
    Bls,
}

impl From<RngMethod> for Option<&str> {
    fn from(value: RngMethod) -> Self {
        match value {
            RngMethod::RandomDet => None,
            RngMethod::Bls => Some("bls_keygen"),
        }
    }
}

#[derive(Debug)]
pub struct AskarWallet {
    pub backend: Store,
    profile: Option<String>,
}

impl BaseWallet for AskarWallet {}

impl AskarWallet {
    pub async fn create(
        db_url: &str,
        key_method: StoreKeyMethod,
        pass_key: PassKey<'_>,
        recreate: bool,
        profile: Option<String>,
    ) -> Result<Self, AriesVcxCoreError> {
        let backend =
            Store::provision(db_url, key_method, pass_key, profile.clone(), recreate).await?;

        Ok(Self { backend, profile })
    }

    pub async fn open(
        db_url: &str,
        key_method: Option<StoreKeyMethod>,
        pass_key: PassKey<'_>,
        profile: Option<String>,
    ) -> Result<Self, AriesVcxCoreError> {
        let backend = Store::open(db_url, key_method, pass_key, profile.clone()).await?;

        Ok(Self { backend, profile })
    }

    async fn fetch_local_key(
        &self,
        session: &mut Session,
        key_name: &str,
    ) -> VcxCoreResult<LocalKey> {
        let key_entry = self.fetch_key_entry(session, &key_name).await?;

        Ok(key_entry.load_local_key()?)
    }

    async fn fetch_key_entry(
        &self,
        session: &mut Session,
        key_name: &str,
    ) -> Result<KeyEntry, AriesVcxCoreError> {
        session.fetch_key(key_name, false).await?.ok_or_else(|| {
            AriesVcxCoreError::from_msg(
                AriesVcxCoreErrorKind::WalletRecordNotFound,
                format!("no key with name '{}' found in wallet", key_name),
            )
        })
    }

    fn local_key_to_bs58_pubkey(&self, local_key: &LocalKey) -> VcxCoreResult<String> {
        Ok(bs58::encode(local_key.to_public_bytes()?).into_string())
    }

    // fn local_key_to_bs58_name(&self, local_key: &LocalKey) -> VcxCoreResult<String> {
    //     let public_bytes = local_key.to_public_bytes()?;
    //     let res = &bs58::encode(public_bytes).into_string()[0..16];
    //     Ok(res.to_string())
    // }

    pub async fn generate_key(
        &self,
        alg: KeyAlg,
        seed: &[u8],
        rng_method: RngMethod,
    ) -> Result<(String, LocalKey), AriesVcxCoreError> {
        let mut session = self.backend.session(self.profile.clone()).await?;
        self.insert_key(&mut session, alg, seed, rng_method).await
    }

    pub async fn create_key(
        &self,
        name: &str,
        private_bytes: &[u8],
        tags: Option<&[EntryTag]>,
    ) -> VcxCoreResult<LocalKey> {
        let mut session = self.backend.session(self.profile.clone()).await?;

        let key = LocalKey::from_secret_bytes(KeyAlg::Ed25519, private_bytes)?;
        let res = session.insert_key(name, &key, None, tags, None).await?;
        return Ok(key);
    }

    async fn insert_key(
        &self,
        session: &mut Session,
        alg: KeyAlg,
        seed: &[u8],
        rng_method: RngMethod,
    ) -> Result<(String, LocalKey), AriesVcxCoreError> {
        let key = LocalKey::from_seed(alg, seed, rng_method.into())?;

        // let key_name = self.local_key_to_bs58_name(&key)?;
        let key_name = self.local_key_to_bs58_pubkey(&key)?;

        session
            .insert_key(&key_name, &key, None, None, None)
            .await?;

        Ok((key_name, key))
    }

    async fn find_did(
        &self,
        session: &mut Session,
        did: &str,
        category: &str,
    ) -> VcxCoreResult<Option<DidData>> {
        let maybe_entry = session.fetch(category, did, false).await?;

        if let Some(entry) = maybe_entry {
            if let Some(val) = entry.value.as_opt_str() {
                let res: DidData = serde_json::from_str(val)?;
                return Ok(Some(res));
            }
        }

        Ok(None)
    }

    async fn find_current_did(
        &self,
        session: &mut Session,
        did: &str,
    ) -> VcxCoreResult<Option<DidData>> {
        self.find_did(session, did, DID_CATEGORY).await
    }

    async fn insert_did(
        &self,
        session: &mut Session,
        did: &str,
        category: &str,
        verkey: &str,
        tags: Option<&[EntryTag]>,
    ) -> VcxCoreResult<()> {
        if let Some(_) = session.fetch(&did, category, false).await? {
            return Err(AriesVcxCoreError::from_msg(
                AriesVcxCoreErrorKind::DuplicationDid,
                "did with given verkey already exists",
            ));
        }

        let did_data = DidData::new(did.into(), key_from_base58(verkey)?);

        let did_data = serde_json::to_string(&did_data)?;

        let res = session
            .insert(category, did, did_data.as_bytes(), tags, None)
            .await?;

        Ok(res)
    }

    async fn update_did(
        &self,
        session: &mut Session,
        did: &str,
        category: &str,
        verkey: &str,
        tags: Option<&[EntryTag]>,
    ) -> VcxCoreResult<()> {
        let did_data = DidData::new(did, key_from_base58(verkey)?);

        let did_data = serde_json::to_string(&did_data)?;
        session
            .replace(category, did, did_data.as_bytes(), tags, None)
            .await?;

        Ok(())
    }

    pub async fn get_all_records(&self) -> VcxCoreResult<Vec<Record>> {
        let mut session = self.backend.session(self.profile.clone()).await?;

        let res = session.fetch_all(None, None, None, false).await?;

        let rs = res
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(rs)
    }

    pub async fn get_all_keys(&self) -> VcxCoreResult<Vec<KeyEntry>> {
        let mut session = self.backend.session(self.profile.clone()).await?;

        let res = session
            .fetch_all_keys(None, None, None, None, false)
            .await?;

        Ok(res)
    }
}
