// Clippy shows false positives in PyO3 methods.
// See https://github.com/rust-lang/rust-clippy/issues/8971
// Will probably be fixed by Rust 1.65
#![allow(clippy::borrow_deref_ref)]

extern crate alloc;

extern crate group_threshold_cryptography as tpke;

use pyo3::prelude::*;
use pyo3::types::PyBytes;

#[pyclass(module = "tpke")]
pub struct DecryptionShare(tpke::api::DecryptionShare);

impl DecryptionShare {
    pub fn to_bytes(&self) -> PyResult<PyObject> {
        Ok(Python::with_gil(|py| -> PyObject {
            PyBytes::new(py, &self.0.to_bytes()).into()
        }))
    }
}

#[pyclass(module = "tpke")]
pub struct ParticipantPayload(tpke::api::ParticipantPayload);

#[pymethods]
impl ParticipantPayload {
    #[staticmethod]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(tpke::api::ParticipantPayload::from_bytes(bytes))
    }

    pub fn to_decryption_share(&self) -> DecryptionShare {
        DecryptionShare(self.0.to_decryption_share())
    }
}

/// A Python module implemented in Rust.
#[pymodule]
fn _tpke(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<DecryptionShare>()?;
    m.add_class::<ParticipantPayload>()?;

    Ok(())
}
