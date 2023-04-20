use std::cmp::Ordering;

use ark_ec::pairing::Pairing;

pub mod keypair;
pub mod serialization;
pub mod utils;

pub use keypair::*;
pub use serialization::*;
pub use utils::*;

#[derive(Clone, Debug, PartialEq, Eq)]
/// Represents an external validator
pub struct ExternalValidator<E: Pairing> {
    /// The established address of the validator
    pub address: String,
    /// The Public key
    pub public_key: PublicKey<E>,
}

impl<E: Pairing> PartialOrd for ExternalValidator<E> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.address.partial_cmp(&other.address)
    }
}

impl<E: Pairing> Ord for ExternalValidator<E> {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.address.cmp(&other.address)
    }
}

impl<E: Pairing> ExternalValidator<E> {
    pub fn new(address: String, public_key: PublicKey<E>) -> Self {
        Self {
            address,
            public_key,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Validator<E: Pairing> {
    pub validator: ExternalValidator<E>,
    pub share_index: usize,
}

impl<E: Pairing> PartialOrd for Validator<E> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.validator.partial_cmp(&other.validator)
    }
}

impl<E: Pairing> Ord for Validator<E> {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.validator.cmp(&other.validator)
    }
}
