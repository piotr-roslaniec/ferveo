use std::usize;

use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{PrimeField, Zero};
use ark_poly::{univariate::DensePolynomial, Polynomial, UVPolynomial};
use itertools::zip_eq;
use rand_core::RngCore;

use crate::{lagrange_basis_at, PrivateKeyShare};

/// From PSS paper, section 4.2.1, (https://link.springer.com/content/pdf/10.1007/3-540-44750-4_27.pdf)
pub fn prepare_share_updates_for_recovery<E: PairingEngine>(
    domain_points: &[E::Fr],
    h: &E::G2Affine,
    x_r: &E::Fr,
    threshold: usize,
    rng: &mut impl RngCore,
) -> Vec<E::G2Projective> {
    // Generate a new random polynomial with constant term x_r
    let d_i = make_random_polynomial_at::<E>(threshold, x_r, rng);

    // Now, we need to evaluate the polynomial at each of participants' indices
    domain_points
        .iter()
        .map(|x_i| {
            let eval = d_i.evaluate(x_i);
            h.mul(eval.into_repr())
        })
        .collect()
}

/// From PSS paper, section 4.2.3, (https://link.springer.com/content/pdf/10.1007/3-540-44750-4_27.pdf)
pub fn update_share_for_recovery<E: PairingEngine>(
    private_key_share: &PrivateKeyShare<E>,
    share_updates: &[E::G2Projective],
) -> PrivateKeyShare<E> {
    let private_key_share = share_updates
        .iter()
        .fold(
            private_key_share.private_key_share.into_projective(),
            |acc, delta| acc + delta,
        )
        .into_affine();
    PrivateKeyShare { private_key_share }
}

/// From the PSS paper, section 4.2.4, (https://link.springer.com/content/pdf/10.1007/3-540-44750-4_27.pdf)
pub fn recover_share_from_updated_private_shares<E: PairingEngine>(
    x_r: &E::Fr,
    domain_points: &[E::Fr],
    updated_private_shares: &[PrivateKeyShare<E>],
) -> PrivateKeyShare<E> {
    // Interpolate new shares to recover y_r
    let lagrange = lagrange_basis_at::<E>(domain_points, x_r);
    let prods = zip_eq(updated_private_shares, lagrange)
        .map(|(y_j, l)| y_j.private_key_share.mul(l.into_repr()));
    let y_r = prods.fold(E::G2Projective::zero(), |acc, y_j| acc + y_j);

    PrivateKeyShare {
        private_key_share: y_r.into_affine(),
    }
}

pub fn make_random_polynomial_at<E: PairingEngine>(
    threshold: usize,
    root: &E::Fr,
    rng: &mut impl RngCore,
) -> DensePolynomial<E::Fr> {
    // [][threshold-1]
    let mut threshold_poly = DensePolynomial::<E::Fr>::rand(threshold - 1, rng);

    // [0..][threshold]
    threshold_poly[0] = E::Fr::zero();

    // Now, we calculate d_i_0
    // This is the term that will "zero out" the polynomial at x_r, d_i(x_r) = 0
    let d_i_0 = E::Fr::zero() - threshold_poly.evaluate(root);
    threshold_poly[0] = d_i_0;

    debug_assert!(threshold_poly.evaluate(root) == E::Fr::zero());
    debug_assert!(threshold_poly.coeffs.len() == threshold);

    threshold_poly
}

// TODO: Expose a method to create a proper decryption share after refreshing
pub fn refresh_private_key_share<E: PairingEngine>(
    h: &E::G2Projective,
    domain_point: &E::Fr,
    polynomial: &DensePolynomial<E::Fr>,
    validator_private_key_share: &PrivateKeyShare<E>,
) -> PrivateKeyShare<E> {
    let evaluated_polynomial = polynomial.evaluate(domain_point);
    let share_update = h.mul(evaluated_polynomial.into_repr());
    let updated_share = validator_private_key_share
        .private_key_share
        .into_projective()
        + share_update;
    PrivateKeyShare {
        private_key_share: updated_share.into_affine(),
    }
}
