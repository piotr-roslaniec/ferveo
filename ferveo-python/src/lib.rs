extern crate alloc;

use std::fmt;

use ferveo::api::E;
use ferveo_common::serialization::{FromBytes, ToBytes};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rand::thread_rng;

fn from_py_bytes<T: FromBytes>(bytes: &[u8]) -> PyResult<T> {
    T::from_bytes(bytes).map_err(map_py_error)
}

fn to_py_bytes<T: ToBytes>(t: T) -> PyResult<PyObject> {
    let bytes = t.to_bytes().map_err(map_py_error)?;
    Ok(Python::with_gil(|py| -> PyObject {
        PyBytes::new(py, &bytes).into()
    }))
}

fn map_py_error<T: fmt::Display>(err: T) -> PyErr {
    PyValueError::new_err(format!("{}", err))
}

#[pyfunction]
pub fn encrypt(
    message: &[u8],
    aad: &[u8],
    public_key: &DkgPublicKey,
) -> PyResult<Ciphertext> {
    let rng = &mut thread_rng();
    let ciphertext = ferveo::api::encrypt(message, aad, &public_key.0, rng)
        .map_err(map_py_error)?;
    Ok(Ciphertext(ciphertext))
}

#[pyfunction]
pub fn combine_decryption_shares(shares: Vec<DecryptionShare>) -> SharedSecret {
    let shares = shares
        .iter()
        .map(|share| share.0.clone())
        .collect::<Vec<_>>();
    SharedSecret(ferveo::api::share_combine_simple_precomputed(&shares))
}

#[pyfunction]
pub fn decrypt_with_shared_secret(
    ciphertext: &Ciphertext,
    aad: &[u8],
    shared_secret: &SharedSecret,
    g1_inv: &G1Prepared,
) -> PyResult<Vec<u8>> {
    ferveo::api::decrypt_with_shared_secret(
        &ciphertext.0,
        aad,
        &shared_secret.0,
        &g1_inv.0,
    )
    .map_err(|err| PyValueError::new_err(format!("{}", err)))
}

#[pyclass(module = "ferveo")]
#[derive(derive_more::AsRef)]
pub struct G1Prepared(ferveo::api::G1Prepared);

#[pyclass(module = "ferveo")]
#[derive(derive_more::AsRef)]
pub struct SharedSecret(ferveo::api::SharedSecret);

#[pyclass(module = "ferveo")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct Keypair(ferveo::api::Keypair<E>);

#[pymethods]
impl Keypair {
    #[staticmethod]
    pub fn random() -> Self {
        Self(ferveo::api::Keypair::new(&mut thread_rng()))
    }

    #[staticmethod]
    pub fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        from_py_bytes(bytes).map(Self)
    }

    fn __bytes__(&self) -> PyResult<PyObject> {
        to_py_bytes(self.0)
    }

    #[getter]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public())
    }
}

#[pyclass(module = "ferveo")]
#[derive(Clone, derive_more::From, derive_more::AsRef)]
pub struct PublicKey(ferveo::api::PublicKey<E>);

#[pymethods]
impl PublicKey {
    #[staticmethod]
    pub fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        from_py_bytes(bytes).map(Self)
    }

    fn __bytes__(&self) -> PyResult<PyObject> {
        to_py_bytes(self.0)
    }
}

#[pyclass(module = "ferveo")]
#[derive(Clone, derive_more::From, derive_more::AsRef)]
pub struct ExternalValidator(ferveo::api::ExternalValidator<E>);

#[pymethods]
impl ExternalValidator {
    #[new]
    pub fn new(address: String, public_key: PublicKey) -> Self {
        Self(ferveo::api::ExternalValidator::new(address, public_key.0))
    }
}

#[pyclass(module = "ferveo")]
#[derive(Clone, derive_more::From, derive_more::AsRef)]
pub struct Transcript(ferveo::api::Transcript<E>);

#[pymethods]
impl Transcript {
    #[staticmethod]
    pub fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        from_py_bytes(bytes).map(Self)
    }

    fn __bytes__(&self) -> PyResult<PyObject> {
        to_py_bytes(&self.0)
    }
}

#[pyclass(module = "ferveo")]
#[derive(Clone, derive_more::From, derive_more::AsRef)]
pub struct DkgPublicKey(ferveo::api::DkgPublicKey);

#[derive(FromPyObject)]
pub struct ExternalValidatorMessage(ExternalValidator, Transcript);

#[pyclass(module = "ferveo")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct Dkg(ferveo::api::Dkg);

#[pymethods]
impl Dkg {
    #[new]
    pub fn new(
        tau: u64,
        shares_num: u32,
        security_threshold: u32,
        validators: Vec<ExternalValidator>,
        me: ExternalValidator,
    ) -> PyResult<Self> {
        let validators: Vec<_> = validators.into_iter().map(|v| v.0).collect();
        let dkg = ferveo::api::Dkg::new(
            tau,
            shares_num,
            security_threshold,
            &validators,
            &me.0,
        )
        .map_err(|err| PyValueError::new_err(format!("{}", err)))?;
        Ok(Self(dkg))
    }

    #[getter]
    pub fn final_key(&self) -> DkgPublicKey {
        DkgPublicKey(self.0.final_key())
    }

    pub fn generate_transcript(&self) -> PyResult<Transcript> {
        let rng = &mut thread_rng();
        let transcript = self
            .0
            .generate_transcript(rng)
            .map_err(|err| PyValueError::new_err(format!("{}", err)))?;
        Ok(Transcript(transcript))
    }
}

#[pyclass(module = "ferveo")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct Ciphertext(ferveo::api::Ciphertext);

#[pyclass(module = "ferveo")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct UnblindingKey(ferveo::api::UnblindingKey);

#[pyclass(module = "ferveo")]
#[derive(Clone, derive_more::AsRef, derive_more::From)]
pub struct DecryptionShare(ferveo::api::DecryptionShare);

#[pyclass(module = "ferveo")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct AggregatedTranscript(ferveo::api::AggregatedTranscript);

#[pymethods]
impl AggregatedTranscript {
    pub fn validate(&self, dkg: &Dkg) -> bool {
        self.0.validate(&dkg.0)
    }

    pub fn create_decryption_share(
        &self,
        dkg: &Dkg,
        ciphertext: &Ciphertext,
        aad: &[u8],
        validator_keypair: &Keypair,
    ) -> PyResult<DecryptionShare> {
        let decryption_share = self
            .0
            .create_decryption_share(
                &dkg.0,
                &ciphertext.0,
                aad,
                &validator_keypair.0,
            )
            .map_err(|err| PyValueError::new_err(format!("{}", err)))?;
        Ok(DecryptionShare(decryption_share))
    }

    #[staticmethod]
    pub fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        from_py_bytes(bytes).map(Self)
    }

    fn __bytes__(&self) -> PyResult<PyObject> {
        to_py_bytes(&self.0)
    }
}

/// A Python module implemented in Rust.
#[pymodule]
fn _ferveo(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(combine_decryption_shares, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_with_shared_secret, m)?)?;
    m.add_class::<Keypair>()?;
    m.add_class::<PublicKey>()?;
    m.add_class::<ExternalValidator>()?;
    m.add_class::<Transcript>()?;
    m.add_class::<Dkg>()?;
    m.add_class::<Ciphertext>()?;
    m.add_class::<UnblindingKey>()?;
    m.add_class::<DecryptionShare>()?;
    m.add_class::<AggregatedTranscript>()?;
    Ok(())
}
