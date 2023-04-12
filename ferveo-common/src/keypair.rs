use std::ops::Mul;

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_std::rand::{prelude::StdRng, RngCore, SeedableRng};
use rand_core::Error;
use serde::*;
use serde_with::serde_as;

use crate::serialization;

#[derive(Copy, Clone, Debug)]
pub struct PreparedPublicKey<E: Pairing> {
    pub encryption_key: E::G2Prepared,
}

impl<E: Pairing> From<PublicKey<E>> for PreparedPublicKey<E> {
    fn from(value: PublicKey<E>) -> Self {
        PreparedPublicKey::<E> {
            encryption_key: E::G2Prepared::from(value.encryption_key),
        }
    }
}

#[serde_as]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicKey<E: Pairing> {
    #[serde_as(as = "serialization::SerdeAs")]
    pub encryption_key: E::G2Affine,
}

#[serde_as]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Keypair<E: Pairing> {
    #[serde_as(as = "serialization::SerdeAs")]
    pub decryption_key: E::ScalarField,
}

impl<E: Pairing> Keypair<E> {
    /// Returns the public session key for the publicly verifiable DKG participant
    pub fn public(&self) -> PublicKey<E> {
        PublicKey::<E> {
            encryption_key: E::G2Affine::generator()
                .mul(self.decryption_key)
                .into_affine(),
        }
    }

    /// Creates a new ephemeral session key for participating in the DKG
    pub fn new<R: RngCore>(rng: &mut R) -> Self {
        use ark_std::UniformRand;
        Self {
            decryption_key: E::ScalarField::rand(rng),
        }
    }

    pub fn secure_randomness_size() -> usize {
        32
    }

    pub fn from_secure_randomness(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != Self::secure_randomness_size() {
            return Err(Error::new("Invalid seed length"));
        }
        let mut seed = [0; 32];
        seed.copy_from_slice(bytes);
        let mut rng = StdRng::from_seed(seed);
        Ok(Self::new(&mut rng))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type E = ark_bls12_381::Bls12_381;

    #[test]
    fn test_secure_randomness_generation() {
        let bytes = [0u8; 32];
        let keypair = Keypair::<E>::from_secure_randomness(&bytes);
        assert!(keypair.is_ok());
    }

    #[test]
    fn test_secure_randomness_generation_with_invalid_length() {
        let bytes = [0u8; 31];
        let keypair = Keypair::<E>::from_secure_randomness(&bytes);
        assert!(keypair.is_err());
    }
}
