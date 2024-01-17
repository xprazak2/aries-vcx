use std::sync::PoisonError;

use public_key::PublicKeyError;

use crate::errors::error::{AriesVcxCoreError, AriesVcxCoreErrorKind};

impl From<serde_json::Error> for AriesVcxCoreError {
    fn from(_err: serde_json::Error) -> Self {
        AriesVcxCoreError::from_msg(
            AriesVcxCoreErrorKind::InvalidJson,
            "Invalid json".to_string(),
        )
    }
}

impl<T> From<PoisonError<T>> for AriesVcxCoreError {
    fn from(err: PoisonError<T>) -> Self {
        AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::InvalidState, err.to_string())
    }
}

impl From<PublicKeyError> for AriesVcxCoreError {
    fn from(value: PublicKeyError) -> Self {
        AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::NotBase58, value)
    }
}
