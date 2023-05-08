use std::{cmp::Ordering, fmt::Formatter, io, ops::Mul};

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    rand::{prelude::StdRng, RngCore, SeedableRng},
    UniformRand,
};
use rand_core::Error;
use serde::*;
use serde_with::serde_as;

use crate::serialization;

// Normally, we would use a custom trait for this, but we can't because
// the arkworks will not let us create a blanket implementation for G1Affine
// and Fr types. So instead, we're using this shared utility function:
pub fn to_bytes<T: CanonicalSerialize>(
    item: &T,
) -> Result<Vec<u8>, ark_serialize::SerializationError> {
    let mut writer = Vec::new();
    item.serialize_compressed(&mut writer)?;
    Ok(writer)
}

pub fn from_bytes<T: CanonicalDeserialize>(
    bytes: &[u8],
) -> Result<T, ark_serialize::SerializationError> {
    let mut reader = io::Cursor::new(bytes);
    let item = T::deserialize_compressed(&mut reader)?;
    Ok(item)
}

#[serde_as]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicKey<E: Pairing> {
    #[serde_as(as = "serialization::SerdeAs")]
    pub encryption_key: E::G2Affine,
}

impl<E: Pairing> PublicKey<E> {
    pub fn to_bytes(
        &self,
    ) -> Result<Vec<u8>, ark_serialize::SerializationError> {
        to_bytes(&self.encryption_key)
    }

    pub fn from_bytes(
        bytes: &[u8],
    ) -> Result<Self, ark_serialize::SerializationError> {
        let encryption_key = from_bytes(bytes)?;
        Ok(PublicKey::<E> { encryption_key })
    }
}

impl<E: Pairing> PartialOrd for PublicKey<E> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.encryption_key.x() == other.encryption_key.x() {
            return self
                .encryption_key
                .y()
                .partial_cmp(&other.encryption_key.y());
        }
        self.encryption_key
            .x()
            .partial_cmp(&other.encryption_key.x())
    }
}

impl<E: Pairing> Ord for PublicKey<E> {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        if self.encryption_key.x() == other.encryption_key.x() {
            return self.encryption_key.y().cmp(&other.encryption_key.y());
        }
        self.encryption_key.x().cmp(&other.encryption_key.x())
    }
}

impl<E: Pairing> std::fmt::Display for PublicKey<E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PublicKey({:?}, {:?})",
            self.encryption_key.x(),
            self.encryption_key.y()
        )
    }
}

#[serde_as]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Keypair<E: Pairing> {
    #[serde_as(as = "serialization::SerdeAs")]
    pub decryption_key: E::ScalarField,
}

impl<E: Pairing> PartialOrd for Keypair<E> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.decryption_key.partial_cmp(&other.decryption_key)
    }
}

impl<E: Pairing> Ord for Keypair<E> {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.decryption_key.cmp(&other.decryption_key)
    }
}

impl<E: Pairing> Keypair<E> {
    /// Returns the public session key for the publicly verifiable DKG participant
    #[inline]
    pub fn public(&self) -> PublicKey<E> {
        PublicKey::<E> {
            encryption_key: E::G2Affine::generator()
                .mul(self.decryption_key)
                .into_affine(),
        }
    }

    /// Creates a new ephemeral session key for participating in the DKG
    #[inline]
    pub fn new<R: RngCore>(rng: &mut R) -> Self {
        Self {
            decryption_key: E::ScalarField::rand(rng),
        }
    }

    #[inline]
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

    #[test]
    fn test_keypair_sorting() {
        let mut keypairs = vec![];
        for _ in 0..100 {
            keypairs.push(Keypair::<E>::new(&mut rand::thread_rng()));
        }
        keypairs.sort();
        for i in 0..keypairs.len() - 1 {
            assert!(keypairs[i] < keypairs[i + 1]);
        }
    }

    #[test]
    fn test_public_key_sorting() {
        let mut public_keys = vec![];
        for _ in 0..100 {
            public_keys
                .push(Keypair::<E>::new(&mut rand::thread_rng()).public());
        }
        public_keys.sort();
        for i in 0..public_keys.len() - 1 {
            assert!(public_keys[i] < public_keys[i + 1]);
        }
    }

    #[test]
    fn test_equal_public_keys() {
        let public_key1 = Keypair::<E>::new(&mut rand::thread_rng()).public();
        let public_key2 = public_key1;

        assert_eq!(public_key1, public_key2);
        assert_eq!(
            public_key1.partial_cmp(&public_key2),
            Some(Ordering::Equal)
        );
        assert_eq!(public_key1.cmp(&public_key2), Ordering::Equal);
    }

    #[test]
    fn test_diff_x_public_keys() {
        let keypair1 = Keypair::<E>::new(&mut rand::thread_rng());

        // Modify keypair2's x-coordinate to make it different from keypair1's
        let mut keypair2;
        loop {
            keypair2 = Keypair::<E>::new(&mut rand::thread_rng());
            if keypair1.public().encryption_key.x()
                != keypair2.public().encryption_key.x()
            {
                break;
            }
        }

        let result = keypair1.public().cmp(&keypair2.public());
        assert_eq!(
            result,
            keypair1
                .public()
                .encryption_key
                .x()
                .cmp(&keypair2.public().encryption_key.x())
        );
    }
}
