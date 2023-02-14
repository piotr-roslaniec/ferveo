use ark_ec::pairing::Pairing;

pub mod keypair;
pub mod serialization;

pub use keypair::*;
pub use serialization::*;

#[derive(Clone, Debug, PartialEq)]
/// Represents an external validator
pub struct ExternalValidator<E: Pairing> {
    /// The established address of the validator
    pub address: String,
    /// The Public key
    pub public_key: PublicKey<E>,
}

#[derive(Clone, Debug)]
pub struct Validator<E: Pairing> {
    pub validator: ExternalValidator<E>,
    pub share_index: usize,
}

// TODO: Do we want to use this trait? Why?
pub trait Rng: ark_std::rand::CryptoRng + ark_std::rand::RngCore {}
