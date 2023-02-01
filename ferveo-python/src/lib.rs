extern crate alloc;

use pyo3::prelude::*;

#[pyclass(module = "ferveo")]
#[derive(Clone, derive_more::From, derive_more::AsRef)]
pub struct ExternalValidator(ferveo::api::ExternalValidator);

#[pyclass(module = "ferveo")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct PubliclyVerifiableDkg(ferveo::api::PubliclyVerifiableDkg);

#[pymethods]
impl PubliclyVerifiableDkg {
    #[new]
    pub fn new(
        tau: u64,
        shares_num: u32,
        security_threshold: u32,
        validators: Vec<ExternalValidator>,
        me: ExternalValidator,
    ) -> Self {
        let validators = validators.into_iter().map(|v| v.0).collect();
        let me = me.0;
        Self(ferveo::api::PubliclyVerifiableDkg::new(
            tau,
            shares_num,
            security_threshold,
            validators,
            me,
        ))
    }
}

/// A Python module implemented in Rust.
#[pymodule]
fn _ferveo(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PubliclyVerifiableDkg>()?;
    m.add_class::<ExternalValidator>()?;

    Ok(())
}
