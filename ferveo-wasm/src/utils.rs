use core::fmt;

use ferveo_common::{FromBytes, ToBytes};
use js_sys::Error;
use wasm_bindgen::prelude::*;

pub type JsResult<T> = Result<T, Error>;

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

/// Tries to convert a JS array from `JsValue` to a vector of Rust type elements.
// This is necessary since wasm-bindgen does not support having a parameter of `Vec<&T>`
// (see https://github.com/rustwasm/wasm-bindgen/issues/111).
pub fn try_from_js_array<T>(value: impl AsRef<JsValue>) -> JsResult<Vec<T>>
where
    for<'a> T: TryFrom<&'a JsValue>,
    for<'a> <T as TryFrom<&'a JsValue>>::Error: core::fmt::Display,
{
    let array: &js_sys::Array = value.as_ref().dyn_ref().ok_or_else(|| {
        Error::new("Got a non-array argument where an array was expected")
    })?;
    let length: usize = array.length().try_into().map_err(map_js_err)?;
    let mut result = Vec::<T>::with_capacity(length);
    for js in array.iter() {
        let typed_elem = T::try_from(&js).map_err(map_js_err)?;
        result.push(typed_elem);
    }
    Ok(result)
}

pub fn into_js_array<T, U>(value: impl IntoIterator<Item = U>) -> T
where
    JsValue: From<U>,
    T: JsCast,
{
    value
        .into_iter()
        .map(JsValue::from)
        .collect::<js_sys::Array>()
        .unchecked_into::<T>()
}
