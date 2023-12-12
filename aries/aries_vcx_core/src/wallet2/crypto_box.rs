use crate::errors::error::{AriesVcxCoreError, AriesVcxCoreErrorKind, VcxCoreResult};

use sodiumoxide::crypto::box_::{self, PublicKey, SecretKey};
use sodiumoxide::crypto::sealedbox;

pub trait CryptoBox {
    fn box_encrypt(
        &self,
        secret_key: &[u8],
        public_key: &[u8],
        msg: &[u8],
    ) -> VcxCoreResult<(Vec<u8>, Vec<u8>)>;

    fn sealedbox_encrypt(&self, public_key: &[u8], msg: &[u8]) -> VcxCoreResult<Vec<u8>>;
}

pub struct SodiumCryptoBox {}

impl SodiumCryptoBox {
    pub fn new() -> Self {
        Self {}
    }
}

impl CryptoBox for SodiumCryptoBox {
    fn box_encrypt(
        &self,
        secret_key: &[u8],
        public_key: &[u8],
        msg: &[u8],
    ) -> VcxCoreResult<(Vec<u8>, Vec<u8>)> {
        let sk_bytes = secret_key
            // .as_bytes()
            .try_into()
            .map_err(|err| AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::InvalidInput, err))?;

        let pk_bytes = public_key
            // .as_bytes()
            .try_into()
            .map_err(|err| AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::InvalidInput, err))?;

        let sk = SecretKey(sk_bytes);
        let pk = PublicKey(pk_bytes);

        let nonce = box_::gen_nonce();

        let res = box_::seal(msg, &nonce, &pk, &sk);

        Ok((res, nonce.0.to_vec()))
    }

    fn sealedbox_encrypt(&self, public_key: &[u8], msg: &[u8]) -> VcxCoreResult<Vec<u8>> {
        let pk_bytes = public_key
            // .as_bytes()
            .try_into()
            .map_err(|err| AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::InvalidInput, err))?;

        let pk = box_::PublicKey(pk_bytes);

        Ok(sealedbox::seal(msg, &pk))
    }
}
