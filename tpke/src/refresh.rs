use std::{ops::Mul, usize};

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::Zero;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use itertools::zip_eq;
use rand_core::RngCore;

use crate::{lagrange_basis_at, PrivateKeyShare};

/// From PSS paper, section 4.2.1, (https://link.springer.com/content/pdf/10.1007/3-540-44750-4_27.pdf)
pub fn prepare_share_updates_for_recovery<E: Pairing>(
    domain_points: &[E::ScalarField],
    h: &E::G2Affine,
    x_r: &E::ScalarField,
    threshold: usize,
    rng: &mut impl RngCore,
) -> Vec<E::G2> {
    // Generate a new random polynomial with constant term x_r
    let d_i = make_random_polynomial_at::<E>(threshold, x_r, rng);

    // Now, we need to evaluate the polynomial at each of participants' indices
    domain_points
        .iter()
        .map(|x_i| {
            let eval = d_i.evaluate(x_i);
            h.mul(eval)
        })
        .collect()
}

/// From PSS paper, section 4.2.3, (https://link.springer.com/content/pdf/10.1007/3-540-44750-4_27.pdf)
pub fn update_share_for_recovery<E: Pairing>(
    private_key_share: &PrivateKeyShare<E>,
    share_updates: &[E::G2],
) -> PrivateKeyShare<E> {
    let private_key_share = share_updates
        .iter()
        .fold(
            private_key_share.private_key_share.into_group(),
            |acc, delta| acc + delta,
        )
        .into_affine();
    PrivateKeyShare { private_key_share }
}

/// From the PSS paper, section 4.2.4, (https://link.springer.com/content/pdf/10.1007/3-540-44750-4_27.pdf)
pub fn recover_share_from_updated_private_shares<E: Pairing>(
    x_r: &E::ScalarField,
    domain_points: &[E::ScalarField],
    updated_private_shares: &[PrivateKeyShare<E>],
) -> PrivateKeyShare<E> {
    // Interpolate new shares to recover y_r
    let lagrange = lagrange_basis_at::<E>(domain_points, x_r);
    let prods = zip_eq(updated_private_shares, lagrange)
        .map(|(y_j, l)| y_j.private_key_share.mul(l));
    let y_r = prods.fold(E::G2::zero(), |acc, y_j| acc + y_j);

    PrivateKeyShare {
        private_key_share: y_r.into_affine(),
    }
}

pub fn make_random_polynomial_at<E: Pairing>(
    threshold: usize,
    root: &E::ScalarField,
    rng: &mut impl RngCore,
) -> DensePolynomial<E::ScalarField> {
    // [][threshold-1]
    let mut threshold_poly =
        DensePolynomial::<E::ScalarField>::rand(threshold - 1, rng);

    // [0..][threshold]
    threshold_poly[0] = E::ScalarField::zero();

    // Now, we calculate d_i_0
    // This is the term that will "zero out" the polynomial at x_r, d_i(x_r) = 0
    let d_i_0 = E::ScalarField::zero() - threshold_poly.evaluate(root);
    threshold_poly[0] = d_i_0;

    debug_assert!(threshold_poly.evaluate(root) == E::ScalarField::zero());
    debug_assert!(threshold_poly.coeffs.len() == threshold);

    threshold_poly
}

// TODO: Expose a method to create a proper decryption share after refreshing
pub fn refresh_private_key_share<E: Pairing>(
    h: &E::G2,
    domain_point: &E::ScalarField,
    polynomial: &DensePolynomial<E::ScalarField>,
    validator_private_key_share: &PrivateKeyShare<E>,
) -> PrivateKeyShare<E> {
    let evaluated_polynomial = polynomial.evaluate(domain_point);
    let share_update = h.mul(evaluated_polynomial);
    let updated_share =
        validator_private_key_share.private_key_share.into_group()
            + share_update;
    PrivateKeyShare {
        private_key_share: updated_share.into_affine(),
    }
}
