use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::One;
use ark_std::UniformRand;
use rand_core::RngCore;

#[derive(Debug, Clone)]
pub struct PublicKeyShare<E: PairingEngine> {
    pub public_key_share: E::G1Affine, // A_{i, \omega_i}
}

#[derive(Debug, Clone)]
pub struct BlindedKeyShare<E: PairingEngine> {
    pub blinding_key: E::G2Affine,      // [b] H
    pub blinded_key_share: E::G2Affine, // [b] Z_{i, \omega_i}
    // TODO: Should we use this kind of optizmization here or anywhere else?
    pub blinding_key_prepared: E::G2Prepared,
}

pub fn generate_random<R: RngCore, E: PairingEngine>(
    n: usize,
    rng: &mut R,
) -> Vec<E::Fr> {
    (0..n).map(|_| E::Fr::rand(rng)).collect::<Vec<_>>()
}

impl<E: PairingEngine> BlindedKeyShare<E> {
    pub fn verify_blinding<R: RngCore>(
        &self,
        public_key_share: &PublicKeyShare<E>,
        rng: &mut R,
    ) -> bool {
        let g = E::G1Affine::prime_subgroup_generator();
        let alpha = E::Fr::rand(rng);

        let alpha_a = E::G1Prepared::from(
            g + public_key_share.public_key_share.mul(alpha).into_affine(),
        );

        // \sum_i(Y_i)
        let alpha_z = E::G2Prepared::from(
            self.blinding_key + self.blinded_key_share.mul(alpha).into_affine(),
        );

        // e(g, Yi) == e(Ai, [b] H)
        E::product_of_pairings(&[
            (E::G1Prepared::from(-g), alpha_z),
            (alpha_a, E::G2Prepared::from(self.blinding_key)),
        ]) == E::Fqk::one()
    }

    pub fn multiply_by_omega_inv(&mut self, omega_inv: &E::Fr) {
        self.blinded_key_share =
            self.blinded_key_share.mul(-*omega_inv).into_affine();
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PrivateKeyShare<E: PairingEngine> {
    pub private_key_share: E::G2Affine,
}

impl<E: PairingEngine> PrivateKeyShare<E> {
    pub fn blind(&self, b: E::Fr) -> BlindedKeyShare<E> {
        let blinding_key =
            E::G2Affine::prime_subgroup_generator().mul(b).into_affine();
        BlindedKeyShare::<E> {
            blinding_key,
            blinding_key_prepared: E::G2Prepared::from(blinding_key),
            blinded_key_share: self.private_key_share.mul(b).into_affine(),
        }
    }
}
