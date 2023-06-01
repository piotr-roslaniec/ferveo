use ferveo::bindings_python::*;
use pyo3::prelude::*;

#[pymodule]
fn ferveo_py(py: Python, m: &PyModule) -> PyResult<()> {
    make_ferveo_py_module(py, m)
}
