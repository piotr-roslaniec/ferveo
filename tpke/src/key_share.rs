use std::ops::Mul;

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::One;
use ark_std::UniformRand;
use rand_core::RngCore;

#[derive(Debug, Clone)]
pub struct PublicKeyShare<E: Pairing> {
    pub public_key_share: E::G1Affine, // A_{i, \omega_i}
}

#[derive(Debug, Clone)]
pub struct BlindedKeyShare<E: Pairing> {
    pub blinding_key: E::G2Affine,      // [b] H
    pub blinded_key_share: E::G2Affine, // [b] Z_{i, \omega_i}
    pub blinding_key_prepared: E::G2Prepared,
}

pub fn generate_random<R: RngCore, E: Pairing>(
    n: usize,
    rng: &mut R,
) -> Vec<E::ScalarField> {
    (0..n)
        .map(|_| E::ScalarField::rand(rng))
        .collect::<Vec<_>>()
}

impl<E: Pairing> BlindedKeyShare<E> {
    pub fn verify_blinding<R: RngCore>(
        &self,
        public_key_share: &PublicKeyShare<E>,
        rng: &mut R,
    ) -> bool {
        let g = E::G1Affine::generator();
        let alpha = E::ScalarField::rand(rng);

        let alpha_a = E::G1Prepared::from(
            g + public_key_share.public_key_share.mul(alpha).into_affine(),
        );

        // \sum_i(Y_i)
        let alpha_z = E::G2Prepared::from(
            self.blinding_key + self.blinded_key_share.mul(alpha).into_affine(),
        );

        // e(g, Yi) == e(Ai, [b] H)
        let g_inv = E::G1Prepared::from(-g.into_group());
        E::multi_pairing([g_inv, alpha_a], [alpha_z, self.blinding_key.into()])
            .0
            == E::TargetField::one()
    }

    pub fn multiply_by_omega_inv(&mut self, omega_inv: &E::ScalarField) {
        self.blinded_key_share =
            self.blinded_key_share.mul(-*omega_inv).into_affine();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateKeyShare<E: Pairing> {
    pub private_key_share: E::G2Affine,
}

impl<E: Pairing> PrivateKeyShare<E> {
    pub fn blind(&self, b: E::ScalarField) -> BlindedKeyShare<E> {
        let blinding_key = E::G2Affine::generator().mul(b).into_affine();
        BlindedKeyShare::<E> {
            blinding_key,
            blinding_key_prepared: E::G2Prepared::from(blinding_key),
            blinded_key_share: self.private_key_share.mul(b).into_affine(),
        }
    }
}
