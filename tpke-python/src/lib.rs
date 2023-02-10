extern crate alloc;

extern crate group_threshold_cryptography as tpke;

use pyo3::prelude::*;
use pyo3::types::PyBytes;

#[pyclass(module = "tpke")]
pub struct DecryptionShare(tpke::api::DecryptionShareSimplePrecomputed);

impl DecryptionShare {
    pub fn to_bytes(&self) -> PyResult<PyObject> {
        Ok(Python::with_gil(|py| -> PyObject {
            PyBytes::new(py, &self.0.to_bytes()).into()
        }))
    }
}

/// A Python module implemented in Rust.
#[pymodule]
fn _tpke(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<DecryptionShare>()?;

    Ok(())
}
