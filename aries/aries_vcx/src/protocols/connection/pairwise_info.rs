use aries_vcx_core::wallet2::BaseWallet2;

use crate::errors::error::VcxResult;

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairwiseInfo {
    pub pw_did: String,
    pub pw_vk: String,
}

impl PairwiseInfo {
    pub async fn create(wallet: &impl BaseWallet2) -> VcxResult<PairwiseInfo> {
        let did_data = wallet.create_and_store_my_did("", None).await?;
        Ok(PairwiseInfo {
            pw_did: did_data.did,
            pw_vk: did_data.verkey,
        })
    }
}
