use std::sync::PoisonError;

use did_parser::ParseError;
use public_key::PublicKeyError;

use crate::errors::error::{AriesVcxCoreError, AriesVcxCoreErrorKind};

impl From<serde_json::Error> for AriesVcxCoreError {
    fn from(err: serde_json::Error) -> Self {
        AriesVcxCoreError::from_msg(
            AriesVcxCoreErrorKind::InvalidJson,
            format!("Invalid json: {err}"),
        )
    }
}

impl<T> From<PoisonError<T>> for AriesVcxCoreError {
    fn from(err: PoisonError<T>) -> Self {
        AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::InvalidState, err.to_string())
    }
}

impl From<ParseError> for AriesVcxCoreError {
    fn from(err: ParseError) -> Self {
        AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::ParsingError, err.to_string())
    }
}

impl From<Box<dyn std::error::Error>> for AriesVcxCoreError {
    fn from(err: Box<dyn std::error::Error>) -> Self {
        AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::InvalidState, err.to_string())
    }
}

impl From<PublicKeyError> for AriesVcxCoreError {
    fn from(value: PublicKeyError) -> Self {
        AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::NotBase58, value)
    }
}

impl From<std::io::Error> for AriesVcxCoreError {
    fn from(value: std::io::Error) -> Self {
        AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::IOError, value)
    }
}

impl From<rmp_serde::encode::Error> for AriesVcxCoreError {
    fn from(value: rmp_serde::encode::Error) -> Self {
        AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::EncodeError, value)
    }
}
