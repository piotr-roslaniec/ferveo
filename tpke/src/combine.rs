#![allow(non_snake_case)]
#![allow(dead_code)]
use crate::*;
use ark_ec::ProjectiveCurve;

pub fn prepare_combine<E: PairingEngine>(
    public_decryption_contexts: &[PublicDecryptionContext<E>],
    shares: &[DecryptionShare<E>],
) -> Vec<E::G2Prepared> {
    let mut domain = vec![];
    let mut n_0 = E::Fr::one();
    for d_i in shares.iter() {
        domain.extend(
            public_decryption_contexts[d_i.decrypter_index]
                .domain
                .iter(),
        );
        n_0 *= public_decryption_contexts[d_i.decrypter_index].lagrange_n_0;
    }
    let s = SubproductDomain::<E::Fr>::new(domain);
    let mut lagrange = s.inverse_lagrange_coefficients();
    ark_ff::batch_inversion_and_mul(&mut lagrange, &n_0);
    let mut start = 0usize;
    shares
        .iter()
        .map(|d_i| {
            let decrypter = &public_decryption_contexts[d_i.decrypter_index];
            let end = start + decrypter.domain.len();
            let lagrange_slice = &lagrange[start..end];
            start = end;
            E::G2Prepared::from(
                izip!(
                    lagrange_slice.iter(),
                    decrypter.blinded_key_shares.blinded_key_shares.iter() //decrypter.blinded_key_shares.window_tables.iter()
                )
                .map(|(lambda, blinded_key_share)| {
                    blinded_key_share.mul(*lambda)
                })
                /*.map(|(lambda, base_table)| {
                    FixedBaseMSM::multi_scalar_mul::<E::G2Projective>(
                        scalar_bits,
                        window_size,
                        &base_table.window_table,
                        &[*lambda],
                    )[0]
                })*/
                .sum::<E::G2Projective>()
                .into_affine(),
            )
        })
        .collect::<Vec<_>>()
}

pub fn share_combine<E: PairingEngine>(
    shares: &[DecryptionShare<E>],
    prepared_key_shares: &[E::G2Prepared],
) -> E::Fqk {
    let mut pairing_product: Vec<(E::G1Prepared, E::G2Prepared)> = vec![];

    for (d_i, blinded_key_share) in izip!(shares, prepared_key_shares.iter()) {
        // e(D_i, [b*omega_i^-1] Z_{i,omega_i})
        pairing_product.push((
            E::G1Prepared::from(d_i.decryption_share),
            blinded_key_share.clone(),
        ));
    }
    E::product_of_pairings(&pairing_product)
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
