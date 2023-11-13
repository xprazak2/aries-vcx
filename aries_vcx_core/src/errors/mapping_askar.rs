use aries_askar::ErrorKind;

use super::error::{AriesVcxCoreError, AriesVcxCoreErrorKind};

impl From<aries_askar::Error> for AriesVcxCoreError {
    fn from(err: aries_askar::Error) -> Self {
        match err.kind() {
            ErrorKind::Backend => {
                AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::AskarBackend, err)
            }
            ErrorKind::Busy => AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::AskarBusy, err),
            ErrorKind::Custom => {
                AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::AskarCustom, err)
            }
            ErrorKind::Duplicate => {
                AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::AskarDuplicate, err)
            }
            ErrorKind::Encryption => {
                AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::AskarEncryption, err)
            }
            ErrorKind::Input => AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::AskarInput, err),
            ErrorKind::NotFound => {
                AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::AskarNotFound, err)
            }
            ErrorKind::Unexpected => {
                AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::AskarUnexpected, err)
            }
            ErrorKind::Unsupported => {
                AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::AskarUnsupported, err)
            }
        }
    }
}
