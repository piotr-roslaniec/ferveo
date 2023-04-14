extern crate alloc;

extern crate group_threshold_cryptography as tpke;

use ferveo_common::serialization::ToBytes;
use pyo3::{exceptions::PyValueError, prelude::*, types::PyBytes};

#[pyclass(module = "tpke")]
pub struct DecryptionShare(tpke::api::DecryptionSharePrecomputed);

impl DecryptionShare {
    pub fn to_bytes(&self) -> PyResult<PyObject> {
        let bytes = self
            .0
            .to_bytes()
            .map_err(|err| PyValueError::new_err(format!("{}", err)))?;
        Ok(Python::with_gil(|py| -> PyObject {
            PyBytes::new(py, &bytes).into()
        }))
    }
}

/// A Python module implemented in Rust.
#[pymodule]
fn _tpke(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<DecryptionShare>()?;

    Ok(())
}
