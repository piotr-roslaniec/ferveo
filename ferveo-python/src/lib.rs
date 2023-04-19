extern crate alloc;

use std::fmt::{self};

use ferveo::api::E;
use ferveo_common::serialization::{FromBytes, ToBytes};
use pyo3::{exceptions::PyValueError, prelude::*, types::PyBytes};
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
    dkg_public_key: &DkgPublicKey,
) -> PyResult<Ciphertext> {
    let rng = &mut thread_rng();
    let ciphertext =
        ferveo::api::encrypt(message, aad, &dkg_public_key.0 .0, rng)
            .map_err(map_py_error)?;
    Ok(Ciphertext(ciphertext))
}

#[pyfunction]
pub fn combine_decryption_shares_simple(
    shares: Vec<DecryptionShareSimple>,
    dkg_public_params: &DkgPublicParameters,
) -> SharedSecret {
    let shares = shares
        .iter()
        .map(|share| share.0.clone())
        .collect::<Vec<_>>();
    let domain_points = &dkg_public_params.0.domain_points;
    let lagrange_coefficients =
        ferveo::api::prepare_combine_simple::<E>(&domain_points[..]);
    let shared_secret = ferveo::api::share_combine_simple(
        &shares[..],
        &lagrange_coefficients[..],
    );
    SharedSecret(ferveo::api::SharedSecret(shared_secret))
}

#[pyfunction]
pub fn combine_decryption_shares_precomputed(
    shares: Vec<DecryptionSharePrecomputed>,
) -> SharedSecret {
    let shares = shares
        .iter()
        .map(|share| share.0.clone())
        .collect::<Vec<_>>();
    let shared_secret = ferveo::api::share_combine_precomputed(&shares[..]);
    SharedSecret(ferveo::api::SharedSecret(shared_secret))
}

#[pyfunction]
pub fn decrypt_with_shared_secret(
    ciphertext: &Ciphertext,
    aad: &[u8],
    shared_secret: &SharedSecret,
    dkg_params: &DkgPublicParameters,
) -> PyResult<Vec<u8>> {
    ferveo::api::decrypt_with_shared_secret(
        &ciphertext.0,
        aad,
        &shared_secret.0 .0,
        &dkg_params.0.g1_inv,
    )
    .map_err(map_py_error)
}

#[pyclass(module = "ferveo")]
#[derive(derive_more::AsRef)]
pub struct DkgPublicParameters(ferveo::api::DkgPublicParameters);

#[pymethods]
impl DkgPublicParameters {
    #[staticmethod]
    pub fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        from_py_bytes(bytes).map(Self)
    }

    fn __bytes__(&self) -> PyResult<PyObject> {
        to_py_bytes(self.0.clone())
    }
}

#[pyclass(module = "ferveo")]
#[derive(derive_more::AsRef)]
pub struct SharedSecret(ferveo::api::SharedSecret);

#[pymethods]
impl SharedSecret {
    #[staticmethod]
    pub fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        from_py_bytes(bytes).map(Self)
    }

    fn __bytes__(&self) -> PyResult<PyObject> {
        to_py_bytes(self.0)
    }
}

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
    pub fn from_secure_randomness(bytes: &[u8]) -> PyResult<Self> {
        let keypair = ferveo::api::Keypair::<E>::from_secure_randomness(bytes)
            .map_err(map_py_error)?;
        Ok(Self(keypair))
    }

    #[staticmethod]
    pub fn secure_randomness_size() -> usize {
        ferveo::api::Keypair::<E>::secure_randomness_size()
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
#[derive(Clone, PartialEq, Eq, derive_more::From, derive_more::AsRef)]
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

    #[getter]
    pub fn address(&self) -> String {
        self.0.address.to_string()
    }

    #[getter]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public_key)
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

#[pymethods]
impl DkgPublicKey {
    #[staticmethod]
    pub fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        from_py_bytes(bytes).map(Self)
    }

    fn __bytes__(&self) -> PyResult<PyObject> {
        to_py_bytes(self.0)
    }
}

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
        .map_err(map_py_error)?;
        Ok(Self(dkg))
    }

    #[getter]
    pub fn final_key(&self) -> DkgPublicKey {
        DkgPublicKey(self.0.final_key())
    }

    pub fn generate_transcript(&self) -> PyResult<Transcript> {
        let rng = &mut thread_rng();
        let transcript =
            self.0.generate_transcript(rng).map_err(map_py_error)?;
        Ok(Transcript(transcript))
    }

    pub fn aggregate_transcripts(
        &mut self,
        transcripts: Vec<(ExternalValidator, Transcript)>,
    ) -> PyResult<AggregatedTranscript> {
        let transcripts: Vec<_> = transcripts
            .into_iter()
            .map(|(validator, transcript)| (validator.0, transcript.0))
            .collect();
        let aggregated_transcript = self
            .0
            .aggregate_transcripts(&transcripts)
            .map_err(map_py_error)?;
        Ok(AggregatedTranscript(aggregated_transcript))
    }

    #[getter]
    pub fn public_params(&self) -> DkgPublicParameters {
        DkgPublicParameters(self.0.public_params())
    }
}

#[pyclass(module = "ferveo")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct Ciphertext(ferveo::api::Ciphertext);

#[pymethods]
impl Ciphertext {
    #[staticmethod]
    pub fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        from_py_bytes(bytes).map(Self)
    }

    fn __bytes__(&self) -> PyResult<PyObject> {
        to_py_bytes(&self.0)
    }
}

#[pyclass(module = "ferveo")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct UnblindingKey(ferveo::api::UnblindingKey);

#[pymethods]
impl UnblindingKey {
    #[staticmethod]
    pub fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        from_py_bytes(bytes).map(Self)
    }

    fn __bytes__(&self) -> PyResult<PyObject> {
        to_py_bytes(self.0)
    }
}

#[pyclass(module = "ferveo")]
#[derive(Clone, derive_more::AsRef, derive_more::From)]
pub struct DecryptionShareSimple(ferveo::api::DecryptionShareSimple);

#[pymethods]
impl DecryptionShareSimple {
    #[staticmethod]
    pub fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        from_py_bytes(bytes).map(Self)
    }

    fn __bytes__(&self) -> PyResult<PyObject> {
        to_py_bytes(&self.0)
    }
}

#[pyclass(module = "ferveo")]
#[derive(Clone, derive_more::AsRef, derive_more::From)]
pub struct DecryptionSharePrecomputed(ferveo::api::DecryptionSharePrecomputed);

#[pyclass(module = "ferveo")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct AggregatedTranscript(ferveo::api::AggregatedTranscript);

#[pymethods]
impl AggregatedTranscript {
    pub fn validate(&self, dkg: &Dkg) -> bool {
        self.0.validate(&dkg.0)
    }

    pub fn create_decryption_share_precomputed(
        &self,
        dkg: &Dkg,
        ciphertext: &Ciphertext,
        aad: &[u8],
        validator_keypair: &Keypair,
    ) -> PyResult<DecryptionSharePrecomputed> {
        let decryption_share = self
            .0
            .create_decryption_share_precomputed(
                &dkg.0,
                &ciphertext.0,
                aad,
                &validator_keypair.0,
            )
            .map_err(map_py_error)?;
        Ok(DecryptionSharePrecomputed(decryption_share))
    }

    pub fn create_decryption_share_simple(
        &self,
        dkg: &Dkg,
        ciphertext: &Ciphertext,
        aad: &[u8],
        validator_keypair: &Keypair,
    ) -> PyResult<DecryptionShareSimple> {
        let decryption_share = self
            .0
            .create_decryption_share_simple(
                &dkg.0,
                &ciphertext.0,
                aad,
                &validator_keypair.0,
            )
            .map_err(map_py_error)?;
        Ok(DecryptionShareSimple(decryption_share))
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
fn ferveo_py(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(combine_decryption_shares_simple, m)?)?;
    m.add_function(wrap_pyfunction!(
        combine_decryption_shares_precomputed,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(decrypt_with_shared_secret, m)?)?;
    m.add_class::<Keypair>()?;
    m.add_class::<PublicKey>()?;
    m.add_class::<ExternalValidator>()?;
    m.add_class::<Transcript>()?;
    m.add_class::<Dkg>()?;
    m.add_class::<Ciphertext>()?;
    m.add_class::<UnblindingKey>()?;
    m.add_class::<DecryptionShareSimple>()?;
    m.add_class::<DecryptionSharePrecomputed>()?;
    m.add_class::<AggregatedTranscript>()?;
    m.add_class::<DkgPublicKey>()?;
    m.add_class::<DkgPublicParameters>()?;
    m.add_class::<SharedSecret>()?;
    Ok(())
}
