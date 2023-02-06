extern crate alloc;

use pyo3::prelude::*;
use rand::thread_rng;

#[pyclass(module = "ferveo")]
#[derive(Clone, derive_more::From, derive_more::AsRef)]
pub struct Validator(ferveo::api::Validator);

#[pyclass(module = "ferveo")]
#[derive(Clone, derive_more::From, derive_more::AsRef)]
pub struct Transcript(ferveo::api::Transcript);

#[pyclass(module = "ferveo")]
#[derive(Clone, derive_more::From, derive_more::AsRef)]
pub struct DkgPublicKey(ferveo::api::DkgPublicKey);

#[derive(FromPyObject)]
pub struct ValidatorMessage(Validator, Transcript);

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
        validators: Vec<Validator>,
        me: Validator,
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
        messages: Vec<ValidatorMessage>,
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
#[derive(derive_more::From, derive_more::AsRef)]
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
        unblinding_key: &UnblindingKey,
    ) -> DecryptionShare {
        DecryptionShare(self.0.create_decryption_share(
            &dkg.0,
            &ciphertext.0,
            aad,
            &unblinding_key.0,
        ))
    }
}

/// A Python module implemented in Rust.
#[pymodule]
fn _ferveo(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<Validator>()?;
    m.add_class::<Transcript>()?;
    m.add_class::<Dkg>()?;
    m.add_class::<Ciphertext>()?;
    m.add_class::<UnblindingKey>()?;
    m.add_class::<DecryptionShare>()?;
    m.add_class::<AggregatedTranscript>()?;
    Ok(())
}
