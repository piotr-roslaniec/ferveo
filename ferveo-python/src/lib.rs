extern crate alloc;
extern crate core;

use std::fmt::{self};

use ferveo::api::E;
use ferveo_common::serialization::{FromBytes, ToBytes};
use generic_array::{typenum::U48, GenericArray};
use pyo3::{
    basic::CompareOp,
    exceptions::PyValueError,
    prelude::*,
    types::{PyBytes, PyUnicode},
    PyClass,
};
use rand::thread_rng;

fn from_py_bytes<T: FromBytes>(bytes: &[u8]) -> PyResult<T> {
    T::from_bytes(bytes).map_err(map_py_err)
}

fn to_py_bytes<T: ToBytes>(t: T) -> PyResult<PyObject> {
    let bytes = t.to_bytes().map_err(map_py_err)?;
    as_py_bytes(&bytes)
}

fn as_py_bytes(bytes: &[u8]) -> PyResult<PyObject> {
    Ok(Python::with_gil(|py| -> PyObject {
        PyBytes::new(py, bytes).into()
    }))
}

fn map_py_err<T: fmt::Display>(err: T) -> PyErr {
    PyValueError::new_err(format!("{}", err))
}

// TODO: Not using generics here since some of the types don't implement AsRef<[u8]>
fn hash(type_name: &str, bytes: &[u8]) -> PyResult<isize> {
    // call `hash((class_name, bytes(obj)))`
    Python::with_gil(|py| {
        let builtins = PyModule::import(py, "builtins")?;
        let arg1 = PyUnicode::new(py, type_name);
        let arg2: PyObject = PyBytes::new(py, bytes).into();
        builtins.getattr("hash")?.call1(((arg1, arg2),))?.extract()
    })
}

fn richcmp<T>(obj: &T, other: &T, op: CompareOp) -> PyResult<bool>
where
    T: PyClass + PartialEq + PartialOrd,
{
    match op {
        CompareOp::Eq => Ok(obj == other),
        CompareOp::Ne => Ok(obj != other),
        CompareOp::Lt => Ok(obj < other),
        CompareOp::Le => Ok(obj <= other),
        CompareOp::Gt => Ok(obj > other),
        CompareOp::Ge => Ok(obj >= other),
    }
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
            .map_err(map_py_err)?;
    Ok(Ciphertext(ciphertext))
}

#[pyfunction]
pub fn combine_decryption_shares_simple(
    shares: Vec<DecryptionShareSimple>,
) -> SharedSecret {
    let shares = shares
        .iter()
        .map(|share| share.0.clone())
        .collect::<Vec<_>>();
    let shared_secret = ferveo::api::combine_shares_simple(&shares[..]);
    SharedSecret(shared_secret)
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
    .map_err(map_py_err)
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
            .map_err(map_py_err)?;
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

    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public())
    }
}

#[pyclass(module = "ferveo")]
#[derive(
    Clone, PartialEq, PartialOrd, Eq, derive_more::From, derive_more::AsRef,
)]
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

    fn __richcmp__(&self, other: &Self, op: CompareOp) -> PyResult<bool> {
        richcmp(self, other, op)
    }

    fn __hash__(&self) -> PyResult<isize> {
        let bytes = self.0.to_bytes().map_err(map_py_err)?;
        hash("PublicKey", &bytes)
    }
}

#[pyclass(module = "ferveo")]
#[derive(Clone, derive_more::From, derive_more::AsRef)]
pub struct Validator(ferveo::api::Validator<E>);

#[pymethods]
impl Validator {
    #[new]
    pub fn new(address: String, public_key: &PublicKey) -> PyResult<Self> {
        let validator = ferveo::api::Validator::new(address, public_key.0)
            .map_err(map_py_err)?;
        Ok(Self(validator))
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
        let bytes =
            GenericArray::<u8, U48>::from_exact_iter(bytes.iter().cloned())
                .ok_or_else(|| {
                    map_py_err("Invalid length of bytes for DkgPublicKey")
                })?;
        Ok(Self(
            ferveo::api::DkgPublicKey::from_bytes(bytes.as_slice())
                .map_err(map_py_err)?,
        ))
    }

    fn __bytes__(&self) -> PyResult<PyObject> {
        let bytes = self.0.to_bytes().map_err(map_py_err)?;
        let bytes = GenericArray::<u8, U48>::from_slice(bytes.as_slice());
        as_py_bytes(bytes)
    }

    #[staticmethod]
    pub fn serialized_size() -> usize {
        ferveo::api::DkgPublicKey::serialized_size()
    }
}

// TODO: Consider using a `pyclass` instead
#[derive(FromPyObject, Clone)]
pub struct ValidatorMessage(Validator, Transcript);

#[pyclass(module = "ferveo")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct Dkg(ferveo::api::Dkg);

#[pymethods]
impl Dkg {
    #[new]
    pub fn new(
        tau: u32,
        shares_num: u32,
        security_threshold: u32,
        validators: Vec<Validator>,
        me: &Validator,
    ) -> PyResult<Self> {
        let validators: Vec<_> = validators.into_iter().map(|v| v.0).collect();
        let dkg = ferveo::api::Dkg::new(
            tau,
            shares_num,
            security_threshold,
            &validators,
            &me.0,
        )
        .map_err(map_py_err)?;
        Ok(Self(dkg))
    }

    #[getter]
    pub fn public_key(&self) -> DkgPublicKey {
        DkgPublicKey(self.0.public_key())
    }

    pub fn generate_transcript(&self) -> PyResult<Transcript> {
        let rng = &mut thread_rng();
        let transcript = self.0.generate_transcript(rng).map_err(map_py_err)?;
        Ok(Transcript(transcript))
    }

    pub fn aggregate_transcripts(
        &mut self,
        messages: Vec<ValidatorMessage>,
    ) -> PyResult<AggregatedTranscript> {
        let messages: Vec<_> = messages
            .iter()
            .map(|m| ((m.0).0.clone(), (m.1).0.clone()))
            .collect();
        let aggregated_transcript = self
            .0
            .aggregate_transcripts(&messages)
            .map_err(map_py_err)?;
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

#[pymethods]
impl DecryptionSharePrecomputed {
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
pub struct AggregatedTranscript(ferveo::api::AggregatedTranscript);

#[pymethods]
impl AggregatedTranscript {
    #[new]
    pub fn new(messages: Vec<ValidatorMessage>) -> Self {
        let messages: Vec<_> = messages
            .into_iter()
            .map(|ValidatorMessage(v, t)| (v.0, t.0))
            .collect();
        Self(ferveo::api::AggregatedTranscript::new(&messages))
    }

    pub fn verify(
        &self,
        shares_num: u32,
        messages: Vec<ValidatorMessage>,
    ) -> PyResult<bool> {
        let messages: Vec<_> = messages
            .into_iter()
            .map(|ValidatorMessage(v, t)| (v.0, t.0))
            .collect();
        let is_valid =
            self.0.verify(shares_num, &messages).map_err(map_py_err)?;
        Ok(is_valid)
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
            .map_err(map_py_err)?;
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
            .map_err(map_py_err)?;
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
    Ok(())
}

// TODO: Consider adding remaining ferveo/api.rs tests here
#[cfg(test)]
mod test_ferveo_python {
    use itertools::izip;

    use crate::*;

    type TestInputs = (Vec<ValidatorMessage>, Vec<Validator>, Vec<Keypair>);

    fn make_test_inputs(
        tau: u32,
        security_threshold: u32,
        shares_num: u32,
    ) -> TestInputs {
        let validator_keypairs = (0..shares_num)
            .map(|_| Keypair::random())
            .collect::<Vec<_>>();
        let validators: Vec<_> = validator_keypairs
            .iter()
            .enumerate()
            .map(|(i, keypair)| {
                Validator::new(format!("0x{:040}", i), &keypair.public_key())
                    .unwrap()
            })
            .collect();

        // Each validator holds their own DKG instance and generates a transcript every
        // every validator, including themselves
        let messages: Vec<_> = validators
            .iter()
            .cloned()
            .map(|sender| {
                let dkg = Dkg::new(
                    tau,
                    shares_num,
                    security_threshold,
                    validators.clone(),
                    &sender,
                )
                .unwrap();
                ValidatorMessage(sender, dkg.generate_transcript().unwrap())
            })
            .collect();
        (messages, validators, validator_keypairs)
    }

    #[test]
    fn test_server_api_tdec_precomputed() {
        let tau = 1;
        let shares_num = 4;
        // In precomputed variant, the security threshold is equal to the number of shares
        let security_threshold = shares_num;

        let (messages, validators, validator_keypairs) =
            make_test_inputs(tau, security_threshold, shares_num);

        // Now that every validator holds a dkg instance and a transcript for every other validator,
        // every validator can aggregate the transcripts

        let me = validators[0].clone();
        let mut dkg = Dkg::new(
            tau,
            shares_num,
            security_threshold,
            validators.clone(),
            &me,
        )
        .unwrap();

        // Lets say that we've only receives `security_threshold` transcripts
        let messages = messages[..security_threshold as usize].to_vec();
        let pvss_aggregated =
            dkg.aggregate_transcripts(messages.clone()).unwrap();
        assert!(pvss_aggregated
            .verify(shares_num, messages.clone())
            .unwrap());

        // At this point, any given validator should be able to provide a DKG public key
        let dkg_public_key = dkg.public_key();

        // In the meantime, the client creates a ciphertext and decryption request
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();
        let ciphertext = encrypt(msg, aad, &dkg_public_key).unwrap();

        // Having aggregated the transcripts, the validators can now create decryption shares
        let decryption_shares: Vec<_> = izip!(&validators, &validator_keypairs)
            .map(|(validator, validator_keypair)| {
                // Each validator holds their own instance of DKG and creates their own aggregate
                let mut dkg = Dkg::new(
                    tau,
                    shares_num,
                    security_threshold,
                    validators.clone(),
                    validator,
                )
                .unwrap();
                let aggregate =
                    dkg.aggregate_transcripts(messages.clone()).unwrap();
                assert!(pvss_aggregated
                    .verify(shares_num, messages.clone())
                    .is_ok());
                aggregate
                    .create_decryption_share_precomputed(
                        &dkg,
                        &ciphertext,
                        aad,
                        validator_keypair,
                    )
                    .unwrap()
            })
            .collect();

        // Now, the decryption share can be used to decrypt the ciphertext
        // This part is part of the client API

        let shared_secret =
            combine_decryption_shares_precomputed(decryption_shares);

        let plaintext = decrypt_with_shared_secret(
            &ciphertext,
            aad,
            &shared_secret,
            &dkg.public_params(),
        )
        .unwrap();
        assert_eq!(plaintext, msg);
    }

    #[test]
    fn test_server_api_tdec_simple() {
        let tau = 1;
        let shares_num = 4;
        let security_threshold = 3;

        let (messages, validators, validator_keypairs) =
            make_test_inputs(tau, security_threshold, shares_num);

        // Now that every validator holds a dkg instance and a transcript for every other validator,
        // every validator can aggregate the transcripts
        let me = validators[0].clone();
        let mut dkg = Dkg::new(
            tau,
            shares_num,
            security_threshold,
            validators.clone(),
            &me,
        )
        .unwrap();

        // Lets say that we've only receives `security_threshold` transcripts
        let messages = messages[..security_threshold as usize].to_vec();
        let pvss_aggregated =
            dkg.aggregate_transcripts(messages.clone()).unwrap();
        assert!(pvss_aggregated
            .verify(shares_num, messages.clone())
            .unwrap());

        // At this point, any given validator should be able to provide a DKG public key
        let dkg_public_key = dkg.public_key();

        // In the meantime, the client creates a ciphertext and decryption request
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();
        let ciphertext = encrypt(msg, aad, &dkg_public_key).unwrap();

        // Having aggregated the transcripts, the validators can now create decryption shares
        let decryption_shares: Vec<_> = izip!(&validators, &validator_keypairs)
            .map(|(validator, validator_keypair)| {
                // Each validator holds their own instance of DKG and creates their own aggregate
                let mut dkg = Dkg::new(
                    tau,
                    shares_num,
                    security_threshold,
                    validators.clone(),
                    validator,
                )
                .unwrap();
                let aggregate =
                    dkg.aggregate_transcripts(messages.clone()).unwrap();
                assert!(aggregate
                    .verify(shares_num, messages.clone())
                    .unwrap());
                aggregate
                    .create_decryption_share_simple(
                        &dkg,
                        &ciphertext,
                        aad,
                        validator_keypair,
                    )
                    .unwrap()
            })
            .collect();

        // Now, the decryption share can be used to decrypt the ciphertext
        // This part is part of the client API

        let shared_secret = combine_decryption_shares_simple(decryption_shares);

        // TODO: Fails because of a bad shared secret
        let plaintext = decrypt_with_shared_secret(
            &ciphertext,
            aad,
            &shared_secret,
            &dkg.public_params(),
        )
        .unwrap();
        assert_eq!(plaintext, msg);
    }
}
