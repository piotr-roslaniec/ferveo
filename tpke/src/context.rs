use crate::*;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicDecryptionContext<E: PairingEngine> {
    pub domain: Vec<E::Fr>,
    pub public_key_shares: PublicKeyShares<E>,
    pub blinded_key_shares: BlindedKeyShares<E>,
    // This decrypter's contribution to N(0), namely (-1)^|domain| * \prod_i omega_i
    pub lagrange_n_0: E::Fr,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PrivateDecryptionContext<E: PairingEngine> {
    pub index: usize,
    pub b: E::Fr,
    pub b_inv: E::Fr,
    pub private_key_share: PrivateKeyShare<E>,
    pub public_decryption_contexts: Vec<PublicDecryptionContext<E>>,
    pub g: E::G1Affine,
    pub g_inv: E::G1Prepared,
    pub h_inv: E::G2Prepared,
    pub scalar_bits: usize,
    pub window_size: usize,
}
