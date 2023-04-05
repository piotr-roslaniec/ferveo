use ark_ec::pairing::Pairing;

pub mod keypair;
pub mod serialization;
pub mod utils;

pub use keypair::*;
pub use serialization::*;
pub use utils::*;

#[derive(Clone, Debug, PartialEq)]
/// Represents an external validator
pub struct ExternalValidator<E: Pairing> {
    /// The established address of the validator
    pub address: String,
    /// The Public key
    pub public_key: PublicKey<E>,
}

impl<E: Pairing> ExternalValidator<E> {
    pub fn new(address: String, public_key: PublicKey<E>) -> Self {
        Self {
            address,
            public_key,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Validator<E: Pairing> {
    pub validator: ExternalValidator<E>,
    pub share_index: usize,
}

// TODO: Do we want to use this trait? Why?
pub trait Rng: ark_std::rand::CryptoRng + ark_std::rand::RngCore {}
