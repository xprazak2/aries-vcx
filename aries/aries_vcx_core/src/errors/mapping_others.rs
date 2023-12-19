use std::sync::PoisonError;

use crate::{
    errors::error::{AriesVcxCoreError, AriesVcxCoreErrorKind},
    wallet2::{RecordBuilderError, RecordUpdateBuilderError},
};

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

impl From<RecordBuilderError> for AriesVcxCoreError {
    fn from(value: RecordBuilderError) -> Self {
        match value {
            RecordBuilderError::UninitializedField(field) => AriesVcxCoreError::from_msg(
                AriesVcxCoreErrorKind::InvalidState,
                format!("uninitialized record field: {:?}", field),
            ),
            RecordBuilderError::ValidationError(field) => AriesVcxCoreError::from_msg(
                AriesVcxCoreErrorKind::InvalidState,
                format!("invalid record field: {:?}", field),
            ),
        }
    }
}

impl From<RecordUpdateBuilderError> for AriesVcxCoreError {
    fn from(value: RecordUpdateBuilderError) -> Self {
        match value {
            RecordUpdateBuilderError::UninitializedField(field) => AriesVcxCoreError::from_msg(
                AriesVcxCoreErrorKind::InvalidState,
                format!("uninitialized record field: {:?}", field),
            ),
            RecordUpdateBuilderError::ValidationError(field) => AriesVcxCoreError::from_msg(
                AriesVcxCoreErrorKind::InvalidState,
                format!("invalid record field: {:?}", field),
            ),
        }
    }
}
