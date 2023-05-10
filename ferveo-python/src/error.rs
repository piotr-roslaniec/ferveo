use std::fmt::{Debug, Formatter};

use pyo3::{
    create_exception,
    exceptions::{PyException, PyRuntimeError},
    prelude::*,
};

#[derive(thiserror::Error)]
pub enum FerveoPythonError {
    #[error(transparent)]
    FerveoError(#[from] ferveo::Error),

    /// Any other errors that are too trivial to be put here explicitly.
    #[error("{0}")]
    Other(String),
}

impl From<FerveoPythonError> for PyErr {
    fn from(err: FerveoPythonError) -> PyErr {
        let default = || PyRuntimeError::new_err(format!("{:?}", &err));

        use FerveoPythonError::*;
        match &err {
            FerveoError(err) => match err {
                ferveo::Error::ThresholdEncryptionError(err) => {
                    ThresholdEncryptionError::new_err(err.to_string())
                }
                ferveo::Error::InvalidShareNumberParameter(actual) => {
                    InvalidShareNumberParameter::new_err(actual.to_string())
                }
                ferveo::Error::InvalidDkgStateToDeal => {
                    InvalidDkgStateToDeal::new_err("")
                }
                ferveo::Error::InvalidDkgStateToAggregate => {
                    InvalidDkgStateToAggregate::new_err("")
                }
                ferveo::Error::InvalidDkgStateToVerify => {
                    InvalidDkgStateToVerify::new_err("")
                }
                ferveo::Error::InvalidDkgStateToIngest => {
                    InvalidDkgStateToIngest::new_err("")
                }
                ferveo::Error::DealerNotInValidatorSet(dealer) => {
                    DealerNotInValidatorSet::new_err(dealer.to_string())
                }
                ferveo::Error::UnknownDealer(dealer) => {
                    UnknownDealer::new_err(dealer.to_string())
                }
                ferveo::Error::DuplicateDealer(dealer) => {
                    DuplicateDealer::new_err(dealer.to_string())
                }
                ferveo::Error::InvalidPvssTranscript => {
                    InvalidPvssTranscript::new_err("")
                }
                ferveo::Error::InsufficientTranscriptsForAggregate(
                    expected,
                    actual,
                ) => InsufficientTranscriptsForAggregate::new_err(format!(
                    "expected: {}, actual: {}",
                    expected, actual
                )),
                ferveo::Error::InvalidFinalKey => InvalidFinalKey::new_err(""),
                ferveo::Error::InsufficientValidators(expected, actual) => {
                    InsufficientValidators::new_err(format!(
                        "expected: {}, actual: {}",
                        expected, actual
                    ))
                }
                ferveo::Error::InvalidTranscriptAggregate => {
                    InvalidTranscriptAggregate::new_err("")
                }
                ferveo::Error::ValidatorsNotSorted => {
                    ValidatorsNotSorted::new_err("")
                }
                ferveo::Error::ValidatorPublicKeyMismatch => {
                    ValidatorPublicKeyMismatch::new_err("")
                }
                ferveo::Error::BincodeError(err) => {
                    BincodeError::new_err(err.to_string())
                }
                ferveo::Error::ArkSerializeError(err) => {
                    ArkSerializeError::new_err(err.to_string())
                }
            },
            _ => default(),
        }
    }
}

impl Debug for FerveoPythonError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        use FerveoPythonError::*;
        match self {
            FerveoError(err) => write!(f, "FerveoError: {err:?}"),
            Other(err) => write!(f, "Other: {err:?}"),
        }
    }
}

create_exception!(exceptions, ThresholdEncryptionError, PyException);
create_exception!(exceptions, InvalidShareNumberParameter, PyException);
create_exception!(exceptions, InvalidDkgStateToDeal, PyException);
create_exception!(exceptions, InvalidDkgStateToAggregate, PyException);
create_exception!(exceptions, InvalidDkgStateToVerify, PyException);
create_exception!(exceptions, InvalidDkgStateToIngest, PyException);
create_exception!(exceptions, DealerNotInValidatorSet, PyException);
create_exception!(exceptions, UnknownDealer, PyException);
create_exception!(exceptions, DuplicateDealer, PyException);
create_exception!(exceptions, InvalidPvssTranscript, PyException);
create_exception!(exceptions, InsufficientTranscriptsForAggregate, PyException);
create_exception!(exceptions, InvalidFinalKey, PyException);
create_exception!(exceptions, InsufficientValidators, PyException);
create_exception!(exceptions, InvalidTranscriptAggregate, PyException);
create_exception!(exceptions, ValidatorsNotSorted, PyException);
create_exception!(exceptions, ValidatorPublicKeyMismatch, PyException);
create_exception!(exceptions, BincodeError, PyException);
create_exception!(exceptions, ArkSerializeError, PyException);
