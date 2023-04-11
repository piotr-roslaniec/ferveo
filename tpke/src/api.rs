//! Contains the public API of the library.

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ferveo_common::serialization;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

pub type E = ark_bls12_381::Bls12_381;
pub type G1Prepared = <E as ark_ec::pairing::Pairing>::G1Prepared;
pub type PrivateKey = ark_bls12_381::G2Affine;
pub type UnblindingKey = ark_bls12_381::Fr;
pub type SharedSecret = <E as ark_ec::pairing::Pairing>::TargetField;
pub type Result<T> = crate::Result<T>;
pub type PrivateDecryptionContextSimple =
    crate::PrivateDecryptionContextSimple<E>;
pub type DecryptionShareSimplePrecomputed =
    crate::DecryptionShareSimplePrecomputed<E>;
pub type DecryptionShareSimple = crate::DecryptionShareSimple<E>;
pub type Ciphertext = crate::Ciphertext<E>;

pub use crate::{
    decrypt_symmetric, decrypt_with_shared_secret, encrypt,
    share_combine_simple_precomputed,
};

#[serde_as]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DomainPoint(
    #[serde_as(as = "serialization::SerdeAs")] pub ark_bls12_381::Fr,
);

#[serde_as]
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DkgPublicKey(
    #[serde_as(as = "serialization::SerdeAs")] pub ark_bls12_381::G1Affine,
);

impl DkgPublicKey {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut writer = Vec::new();
        self.0.serialize_uncompressed(&mut writer)?;
        Ok(writer)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<DkgPublicKey> {
        let mut reader = bytes;
        let pk =
            ark_bls12_381::G1Affine::deserialize_uncompressed(&mut reader)?;
        Ok(Self(pk))
    }
}
