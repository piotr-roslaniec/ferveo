#![allow(unused_imports)]

pub mod dkg;
pub mod msg;
pub mod vss;

pub mod primitives;

use itertools::{izip, zip_eq};
pub use primitives::*;

use ferveo_common::Rng;

use crate::dkg::*;
use crate::msg::*;

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, One, Zero};
use ark_poly::{
    polynomial::univariate::DensePolynomial, polynomial::UVPolynomial,
    EvaluationDomain,
};
use ark_std::{end_timer, start_timer};
use serde::*;

use anyhow::{anyhow, Result};
pub use dkg::*;
pub use msg::*;
pub use vss::*;

use ark_ec::msm::FixedBaseMSM;
use ark_ec::PairingEngine;
use ark_ff::PrimeField;

use measure_time::print_time;

pub fn prepare_combine_simple<E: PairingEngine>(
    shares_x: &[E::Fr],
) -> Vec<E::Fr> {
    // Calculate lagrange coefficients using optimized formula, see https://en.wikipedia.org/wiki/Lagrange_polynomial#Optimal_algorithm
    let mut lagrange_coeffs = vec![];
    for x_j in shares_x {
        let mut prod = E::Fr::one();
        for x_m in shares_x {
            if x_j != x_m {
                // In this formula x_i = 0, hence numerator is x_m
                prod *= (*x_m) / (*x_m - *x_j);
            }
        }
        lagrange_coeffs.push(prod);
    }
    lagrange_coeffs
}

pub fn share_combine_simple<E: PairingEngine>(
    shares: &Vec<E::Fqk>,
    lagrange_coeffs: &Vec<E::Fr>,
) -> E::Fqk {
    let mut product_of_shares = E::Fqk::one();

    // Sum of C_i^{L_i}z
    for (c_i, alpha_i) in zip_eq(shares.iter(), lagrange_coeffs.iter()) {
        // Exponentiation by alpha_i
        let ss = c_i.pow(alpha_i.into_repr());
        product_of_shares *= ss;
    }

    product_of_shares
}

#[cfg(test)]
mod test_dkg_full {
    use super::*;

    use crate::dkg::pv::test_common::*;
    use ark_bls12_381::Bls12_381 as EllipticCurve;
    use ark_ff::UniformRand;
    use ferveo_common::{TendermintValidator, ValidatorSet};
    use group_threshold_cryptography as tpke;
    use itertools::{zip_eq, Itertools};

    type E = ark_bls12_381::Bls12_381;

    /// Test happy flow for a full DKG with simple threshold decryption variant
    #[test]
    fn test_dkg_simple_decryption_variant() {
        //
        // The following is copied from other tests
        //

        let rng = &mut ark_std::test_rng();
        let dkg = setup_dealt_dkg();
        let aggregate = aggregate(&dkg);
        // check that a polynomial of the correct degree was created
        assert_eq!(aggregate.coeffs.len(), 5);
        // check that the correct number of shares were created
        assert_eq!(aggregate.shares.len(), 4);
        // check that the optimistic verify returns true
        assert!(aggregate.verify_optimistic());
        // check that the full verify returns true
        assert!(aggregate.verify_full(&dkg));
        // check that the verification of aggregation passes
        assert_eq!(aggregate.verify_aggregation(&dkg).expect("Test failed"), 4);

        //
        // Now, we start the actual test
        //

        // At this point, we have a DKG that has been dealt and aggregated
        // We now want to test the decryption of a message

        // First, we encrypt a message using a DKG public key

        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();
        let public_key = dkg.final_key();
        let ciphertext = tpke::encrypt::<_, E>(msg, aad, &public_key, rng);

        // TODO: Update test utils so that we can easily get a validator keypair for each validator
        let validator_keypairs = gen_keypairs();

        // TODO: Check ciphertext validity, https://nikkolasg.github.io/ferveo/tpke.html#to-validate-ciphertext-for-ind-cca2-security

        // Each validator attempts to aggregate and decrypt the secret shares
        let decryption_shares = validator_keypairs
            .iter()
            .enumerate()
            // Assuming that the ordering of the validator keypairs is the same as the ordering of the validators in the validator set
            // TODO: Check this assumption
            .map(|(validator_i, keypair)| {
                let decrypted_shares: Vec<ark_bls12_381::G2Projective> =
                    // shares_for_validator(validator_i, &dkg)
                dkg.vss[&(validator_i as u32)].shares
                        .iter()
                        // Each "share" the validator has is actually a vector of shares
                        // This because of domain partitioning - the amount of shares is the same as the validator's "power"
                        .map(|share|
                            // Decrypt the share by decrypting each of the G2 elements within ShareEncryptions<E>
                            share.mul(keypair.decryption_key))
                        .collect();

                let z_i = decrypted_shares
                    .iter()
                    .fold(ark_bls12_381::G2Projective::zero(), |acc, share| {
                        acc + *share
                    });

                // Validator decryption of private key shares, https://nikkolasg.github.io/ferveo/pvss.html#validator-decryption-of-private-key-shares
                let u = ciphertext.commitment;
                let c_i = E::pairing(u, z_i);

                c_i
            })
            .collect::<Vec<_>>();

        // TODO: Am I taking a correct amount of x cooridnates herer? The domain contains 2^n=8 elements total, but I'm taking 4
        let shares_x = &dkg.domain.elements().take(decryption_shares.len()).collect::<Vec<_>>();
        let lagrange_coeffs = prepare_combine_simple::<E>(&shares_x);

        let s = share_combine_simple::<E>(&decryption_shares, &lagrange_coeffs);

        let plaintext =
            tpke::checked_decrypt_with_shared_secret(&ciphertext, aad, &s);
        assert_eq!(plaintext, msg);

        // TODO: Perform decryption here!

        // For every validator, we're collecting all the decryption shares from all of the PVSS transcripts
        // .flatten()
        // .collect();

        // let shares_x  = &dkg.domain.elements().collect::<Vec<_>>();
        // let lagrange_coeffs = prepare_combine_simple::<E>(&shares_x);
        //
        // let s =
        //     share_combine_simple::<E>(&decryption_shares, &lagrange_coeffs);
        //
        // let plaintext =
        //     tpke::checked_decrypt_with_shared_secret(&ciphertext, aad, &s);
        // assert_eq!(plaintext, msg);

        /*
        TODO: This variant seems to be outdated/unused in simple threshold decryption variant

        // Following section 4.4.8 of the paper, we need to compute the following:
        let decryption_shares = validator_keypairs.iter().map(|validator| {
            // TODO: Check the validity of (U, W)

            // Compute the decryption share D_{i,j} = [dk_j^{-1}]*U_i
            // We only have one U in this case
            let u = ciphertext.commitment;
            let dk_j = validator.decryption_key;
            let dk_j_inv = dk_j.inverse().unwrap();
            let d_ij = u.mul(dk_j_inv);
            d_ij
        });
        */
    }
}
