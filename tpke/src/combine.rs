#![allow(non_snake_case)]

use crate::*;
use ark_ec::ProjectiveCurve;

pub fn prepare_combine_fast<E: PairingEngine>(
    public_decryption_contexts: &[PublicDecryptionContextFast<E>],
    shares: &[DecryptionShareFast<E>],
) -> Vec<E::G2Prepared> {
    let mut domain = vec![]; // omega_i, vector of domain points
    let mut n_0 = E::Fr::one();
    for d_i in shares.iter() {
        domain.push(public_decryption_contexts[d_i.decrypter_index].domain);
        // n_0_i = 1 * t^1 * t^2 ...
        n_0 *= public_decryption_contexts[d_i.decrypter_index].lagrange_n_0;
    }
    let s = SubproductDomain::<E::Fr>::new(domain);
    let mut lagrange = s.inverse_lagrange_coefficients(); // 1/L_i

    // Given a vector of field elements {v_i}, compute the vector {coeff * v_i^(-1)}
    ark_ff::batch_inversion_and_mul(&mut lagrange, &n_0); // n_0 * L_i

    // L_i * [b]Z_i
    izip!(shares.iter(), lagrange.iter())
        .map(|(d_i, lambda)| {
            let decrypter = &public_decryption_contexts[d_i.decrypter_index];
            let blinded_key_share =
                decrypter.blinded_key_share.blinded_key_share;
            E::G2Prepared::from(
                // [b]Z_i * L_i
                blinded_key_share.mul(*lambda).into_affine(),
            )
        })
        .collect::<Vec<_>>()
}

pub fn prepare_combine_simple<E: PairingEngine>(
    domain: &[E::Fr],
) -> Vec<E::Fr> {
    // In this formula x_i = 0, hence numerator is x_m
    // See https://en.wikipedia.org/wiki/Lagrange_polynomial#Optimal_algorithm
    lagrange_basis_at::<E>(domain, &E::Fr::zero())
}

/// Calculate lagrange coefficients using optimized formula
pub fn lagrange_basis_at<E: PairingEngine>(
    shares_x: &[E::Fr],
    x_i: &E::Fr,
) -> Vec<<E>::Fr> {
    let mut lagrange_coeffs = vec![];
    for x_j in shares_x {
        let mut prod = E::Fr::one();
        for x_m in shares_x {
            if x_j != x_m {
                prod *= (*x_m - x_i) / (*x_m - *x_j);
            }
        }
        lagrange_coeffs.push(prod);
    }
    lagrange_coeffs
}

// TODO: Hide this from external users. Currently blocked by usage in benchmarks.
pub fn share_combine_fast_unchecked<E: PairingEngine>(
    shares: &[DecryptionShareFast<E>],
    prepared_key_shares: &[E::G2Prepared],
) -> E::Fqk {
    let mut pairing_product: Vec<(E::G1Prepared, E::G2Prepared)> = vec![];

    for (d_i, prepared_key_share) in izip!(shares, prepared_key_shares.iter()) {
        // e(D_i, [b*omega_i^-1] Z_{i,omega_i})
        pairing_product.push((
            // D_i
            E::G1Prepared::from(d_i.decryption_share),
            // Z_{i,omega_i}) = [dk_{i}^{-1}]*\hat{Y}_{i_omega_j}]
            // Reference: https://nikkolasg.github.io/ferveo/pvss.html#validator-decryption-of-private-key-shares
            // Prepared key share is a sum of L_i * [b]Z_i
            prepared_key_share.clone(),
        ));
    }
    E::product_of_pairings(&pairing_product)
}

pub fn share_combine_fast<E: PairingEngine>(
    pub_contexts: &[PublicDecryptionContextFast<E>],
    ciphertext: &Ciphertext<E>,
    decryption_shares: &[DecryptionShareFast<E>],
    prepared_key_shares: &[E::G2Prepared],
) -> Result<E::Fqk> {
    let is_valid_shares = verify_decryption_shares_fast(
        pub_contexts,
        ciphertext,
        decryption_shares,
    );
    if !is_valid_shares {
        return Err(
            ThresholdEncryptionError::DecryptionShareVerificationFailed.into(),
        );
    }
    Ok(share_combine_fast_unchecked(
        decryption_shares,
        prepared_key_shares,
    ))
}

pub fn share_combine_simple<E: PairingEngine>(
    decryption_shares: &[DecryptionShareSimple<E>],
    lagrange_coeffs: &[E::Fr],
) -> E::Fqk {
    // Sum of C_i^{L_i}z
    izip!(decryption_shares, lagrange_coeffs).fold(
        E::Fqk::one(),
        |acc, (c_i, alpha_i)| {
            acc * c_i.decryption_share.pow(alpha_i.into_repr())
        },
    )
}

pub fn share_combine_simple_precomputed<E: PairingEngine>(
    shares: &[DecryptionShareSimplePrecomputed<E>],
) -> E::Fqk {
    // s = ∏ C_{λ_i}, where λ_i is the Lagrange coefficient for i
    shares
        .iter()
        .fold(E::Fqk::one(), |acc, c_i| acc * c_i.decryption_share)
}

#[cfg(test)]
mod tests {
    type Fr = <ark_bls12_381::Bls12_381 as ark_ec::PairingEngine>::Fr;

    #[test]
    fn test_lagrange() {
        use ark_poly::EvaluationDomain;
        use ark_std::One;
        let fft_domain =
            ark_poly::Radix2EvaluationDomain::<Fr>::new(500).unwrap();

        let mut domain = Vec::with_capacity(500);
        let mut point = Fr::one();
        for _ in 0..500 {
            domain.push(point);
            point *= fft_domain.group_gen;
        }

        let mut lagrange_n_0 = domain.iter().product::<Fr>();
        if domain.len() % 2 == 1 {
            lagrange_n_0 = -lagrange_n_0;
        }
        let s = subproductdomain::SubproductDomain::<Fr>::new(domain);
        let mut lagrange = s.inverse_lagrange_coefficients();
        ark_ff::batch_inversion_and_mul(&mut lagrange, &lagrange_n_0);
    }
}
