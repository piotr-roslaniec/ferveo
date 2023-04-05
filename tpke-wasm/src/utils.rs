use core::fmt;

use ferveo_common::{FromBytes, ToBytes};
use js_sys::Error;

pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

pub fn map_js_err<T: fmt::Display>(err: T) -> Error {
    Error::new(&format!("{}", err))
}

pub fn to_js_bytes<T: ToBytes>(t: &T) -> Result<Vec<u8>, Error> {
    t.to_bytes().map_err(map_js_err)
}

pub fn from_js_bytes<T: FromBytes>(bytes: &[u8]) -> Result<T, Error> {
    T::from_bytes(bytes).map_err(map_js_err)
}
