extern crate alloc;

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rand::thread_rng;

#[pyfunction]
pub fn encrypt(
    message: &[u8],
    aad: &[u8],
    public_key: &DkgPublicKey,
) -> Ciphertext {
    Ciphertext(ferveo::api::encrypt(message, aad, &public_key.0))
}

#[pyfunction]
pub fn combine_decryption_shares(shares: Vec<DecryptionShare>) -> SharedSecret {
    let shares = shares
        .iter()
        .map(|share| share.0.clone())
        .collect::<Vec<_>>();
    SharedSecret(ferveo::api::combine_decryption_shares(&shares))
}

#[pyfunction]
pub fn decrypt_with_shared_secret(
    ciphertext: &Ciphertext,
    aad: &[u8],
    shared_secret: &SharedSecret,
) -> Vec<u8> {
    ferveo::api::decrypt_with_shared_secret(
        &ciphertext.0,
        aad,
        &shared_secret.0,
    )
}

#[pyclass(module = "ferveo")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct SharedSecret(ferveo::api::SharedSecret);

#[pyclass(module = "ferveo")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct Keypair(ferveo::api::Keypair);

#[pymethods]
impl Keypair {
    #[staticmethod]
    pub fn random() -> Self {
        Self(ferveo::api::Keypair::random(&mut thread_rng()))
    }

    #[staticmethod]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(ferveo::api::Keypair::from_bytes(bytes))
    }

    fn __bytes__(&self) -> PyObject {
        let serialized = self.0.to_bytes();
        Python::with_gil(|py| PyBytes::new(py, &serialized).into())
    }

    #[getter]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public_key())
    }
}

#[pyclass(module = "ferveo")]
#[derive(Clone, derive_more::From, derive_more::AsRef)]
pub struct PublicKey(ferveo::api::PublicKey);

#[pymethods]
impl PublicKey {
    #[staticmethod]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(ferveo::api::PublicKey::from_bytes(bytes))
    }

    fn __bytes__(&self) -> PyObject {
        let serialized = self.0.to_bytes();
        Python::with_gil(|py| PyBytes::new(py, &serialized).into())
    }
}

#[pyclass(module = "ferveo")]
#[derive(Clone, derive_more::From, derive_more::AsRef)]
pub struct ExternalValidator(ferveo::api::ExternalValidator);

#[pymethods]
impl ExternalValidator {
    #[new]
    pub fn new(address: String, public_key: PublicKey) -> Self {
        Self(ferveo::api::ExternalValidator::new(address, public_key.0))
    }
}

#[pyclass(module = "ferveo")]
#[derive(Clone, derive_more::From, derive_more::AsRef)]
pub struct Transcript(ferveo::api::Transcript);

#[pymethods]
impl Transcript {
    #[staticmethod]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(ferveo::api::Transcript::from_bytes(bytes))
    }

    fn __bytes__(&self) -> PyObject {
        let serialized = self.0.to_bytes();
        Python::with_gil(|py| PyBytes::new(py, &serialized).into())
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
    ) -> Self {
        let validators: Vec<_> = validators.into_iter().map(|v| v.0).collect();
        Self(ferveo::api::Dkg::new(
            tau,
            shares_num,
            security_threshold,
            &validators,
            &me.0,
        ))
    }

    #[getter]
    pub fn final_key(&self) -> DkgPublicKey {
        DkgPublicKey(self.0.final_key())
    }

    pub fn generate_transcript(&self) -> Transcript {
        let rng = &mut thread_rng();
        Transcript(self.0.generate_transcript(rng))
    }

    pub fn aggregate_transcripts(
        // TODO: Avoid mutating current state
        &mut self,
        messages: Vec<ExternalValidatorMessage>,
    ) -> AggregatedTranscript {
        let messages = &messages
            .into_iter()
            .map(|message| (message.0 .0, message.1 .0))
            .collect();
        AggregatedTranscript(self.0.aggregate_transcripts(messages))
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
    ) -> DecryptionShare {
        DecryptionShare(self.0.create_decryption_share(
            &dkg.0,
            &ciphertext.0,
            aad,
            &validator_keypair.0,
        ))
    }

    #[staticmethod]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(ferveo::api::AggregatedTranscript::from_bytes(bytes))
    }

    fn __bytes__(&self) -> PyObject {
        let serialized = self.0.to_bytes();
        Python::with_gil(|py| PyBytes::new(py, &serialized).into())
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
