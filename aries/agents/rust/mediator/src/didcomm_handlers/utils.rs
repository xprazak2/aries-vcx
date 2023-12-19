pub mod prelude {
    pub use std::sync::Arc;

    pub use aries_vcx::utils::encryption_envelope::EncryptionEnvelope;
    pub use aries_vcx_core::wallet2::BaseWallet2;

    pub use crate::{aries_agent::ArcAgent, persistence::MediatorPersistence, utils::prelude::*};
}
