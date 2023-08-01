pub mod keypair;
pub mod serialization;

use std::{fmt, fmt::Formatter};

pub use keypair::*;
pub use serialization::*;

#[derive(Debug)]
pub enum Error {
    InvalidByteLength(usize, usize),
    SerializationError(ark_serialize::SerializationError),
    InvalidSeedLength(usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidByteLength(expected, actual) => {
                write!(
                    f,
                    "Invalid byte length: expected {expected}, actual {actual}"
                )
            }
            Error::SerializationError(e) => {
                write!(f, "Serialization error: {e}")
            }
            Error::InvalidSeedLength(len) => {
                write!(f, "Invalid seed length: {len}")
            }
        }
    }
}

type Result<T> = std::result::Result<T, Error>;
