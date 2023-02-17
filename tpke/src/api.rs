//! Contains the public API of the library.

use ferveo_common::serialization;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

pub type E = ark_bls12_381::Bls12_381;
pub type DkgPublicKey = ark_bls12_381::G1Affine;
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
