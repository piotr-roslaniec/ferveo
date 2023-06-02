use ferveo::bindings_python::*;
use pyo3::prelude::*;

#[pymodule]
fn ferveo_py(py: Python, m: &PyModule) -> PyResult<()> {
    // Functions
    m.add_function(wrap_pyfunction!(encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(combine_decryption_shares_simple, m)?)?;
    m.add_function(wrap_pyfunction!(
        combine_decryption_shares_precomputed,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(decrypt_with_shared_secret, m)?)?;

    // Classes
    m.add_class::<Keypair>()?;
    m.add_class::<PublicKey>()?;
    m.add_class::<Validator>()?;
    m.add_class::<Transcript>()?;
    m.add_class::<Dkg>()?;
    m.add_class::<Ciphertext>()?;
    m.add_class::<DecryptionShareSimple>()?;
    m.add_class::<DecryptionSharePrecomputed>()?;
    m.add_class::<AggregatedTranscript>()?;
    m.add_class::<DkgPublicKey>()?;
    m.add_class::<DkgPublicParameters>()?;
    m.add_class::<SharedSecret>()?;

    // Exceptions
    m.add(
        "ThresholdEncryptionError",
        py.get_type::<ThresholdEncryptionError>(),
    )?;
    m.add(
        "InvalidShareNumberParameter",
        py.get_type::<InvalidShareNumberParameter>(),
    )?;
    m.add(
        "InvalidDkgStateToDeal",
        py.get_type::<InvalidDkgStateToDeal>(),
    )?;
    m.add(
        "InvalidDkgStateToAggregate",
        py.get_type::<InvalidDkgStateToAggregate>(),
    )?;
    m.add(
        "InvalidDkgStateToVerify",
        py.get_type::<InvalidDkgStateToVerify>(),
    )?;
    m.add(
        "InvalidDkgStateToIngest",
        py.get_type::<InvalidDkgStateToIngest>(),
    )?;
    m.add(
        "DealerNotInValidatorSet",
        py.get_type::<DealerNotInValidatorSet>(),
    )?;
    m.add("UnknownDealer", py.get_type::<UnknownDealer>())?;
    m.add("DuplicateDealer", py.get_type::<DuplicateDealer>())?;
    m.add(
        "InvalidPvssTranscript",
        py.get_type::<InvalidPvssTranscript>(),
    )?;
    m.add(
        "InsufficientTranscriptsForAggregate",
        py.get_type::<InsufficientTranscriptsForAggregate>(),
    )?;
    m.add("InvalidDkgPublicKey", py.get_type::<InvalidDkgPublicKey>())?;
    m.add(
        "InsufficientValidators",
        py.get_type::<InsufficientValidators>(),
    )?;
    m.add(
        "InvalidTranscriptAggregate",
        py.get_type::<InvalidTranscriptAggregate>(),
    )?;
    m.add("ValidatorsNotSorted", py.get_type::<ValidatorsNotSorted>())?;
    m.add(
        "ValidatorPublicKeyMismatch",
        py.get_type::<ValidatorPublicKeyMismatch>(),
    )?;
    m.add("SerializationError", py.get_type::<SerializationError>())?;
    Ok(())
}
